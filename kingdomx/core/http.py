"""SSRF-guarded HTTP client.

Every outbound request in KINGDOM X goes through :class:`SafeHttpClient`, which:

* refuses private, loopback and link-local targets unless explicitly allowed,
* re-checks the resolved address **on every redirect** (the classic SSRF trick is
  a public host that 302s to ``127.0.0.1``),
* caps response size so a hostile endpoint cannot exhaust memory,
* redacts credentials from anything it returns for logging.

When an operator truly wants to hit a lab box at 10.0.0.5, they pass it in
``allow_hosts`` explicitly — there is no automatic private-network mode.
"""

from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from kingdomx.core.errors import NetworkError, UnsafeTargetError, ValidationError
from kingdomx.core.logging_setup import get_logger
from kingdomx.core.redaction import redact
from kingdomx.core.validation import check_target_safe, normalise_url

log = get_logger("core.http")

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_REDIRECTS = 5


@dataclass
class HttpResponse:
    """A bounded, already-read HTTP response."""

    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    redirect_chain: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def text(self) -> str:
        charset = "utf-8"
        for key, value in self.headers.items():
            if key.lower() == "content-type" and "charset=" in value.lower():
                charset = value.lower().split("charset=")[-1].split(";")[0].strip() or "utf-8"
                break
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except json.JSONDecodeError as exc:
            raise NetworkError(
                f"response from {self.url} is not JSON", detail=str(exc)
            ) from exc

    def header(self, name: str, default: str = "") -> str:
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return default

    def summary(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "bytes": len(self.body),
            "truncated": self.truncated,
            "redirects": list(self.redirect_chain),
        }


def resolve_host(host: str, *, timeout: float = 5.0) -> list[str]:
    """Resolve every A/AAAA answer for ``host`` using the system resolver."""
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise NetworkError(f"cannot resolve {host}", detail=str(exc)) from exc
    finally:
        socket.setdefaulttimeout(previous)
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


def is_literal_ip(host: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            continue
    return False


def _with_params(url: str, params: Mapping[str, Any]) -> str:
    parts = urlsplit(url)
    extra = urlencode({k: v for k, v in params.items() if v is not None})
    query = f"{parts.query}&{extra}" if parts.query else extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


class SafeHttpClient:
    """Bounded HTTP client with per-hop SSRF validation."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        user_agent: str = "KingdomX/1.0",
        allow_private: bool = False,
        allow_hosts: Iterable[str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.allow_private = allow_private
        self.allow_hosts = list(allow_hosts or [])
        self.base_headers = dict(headers or {})

    def _guard(self, url: str) -> str:
        normalised = normalise_url(url)
        host = urlsplit(normalised).hostname or ""
        check_target_safe(host, allow_private=self.allow_private, allow=self.allow_hosts)
        # Resolve and re-check every answer: a public name can point at 10.0.0.1.
        if not self.allow_private and not is_literal_ip(host):
            for addr in resolve_host(host, timeout=min(self.timeout, 5.0)):
                check_target_safe(addr, allow_private=self.allow_private, allow=self.allow_hosts)
        return normalised

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        data: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
        follow_redirects: bool = True,
    ) -> HttpResponse:
        try:
            import httpx
        except ModuleNotFoundError as exc:  # pragma: no cover - dependency missing
            raise NetworkError("httpx is required; install it with pip") from exc

        target = self._guard(url)
        if params:
            target = _with_params(target, params)

        request_headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        request_headers.update(self.base_headers)
        request_headers.update(dict(headers or {}))

        budget = max_bytes if max_bytes is not None else self.max_bytes
        chain: list[str] = []
        started = time.perf_counter()

        for hop in range(self.max_redirects + 1):
            try:
                with httpx.Client(
                    timeout=timeout if timeout is not None else self.timeout,
                    follow_redirects=False,
                ) as client:
                    with client.stream(
                        method, target, headers=request_headers, json=json_body, content=data
                    ) as response:
                        status = response.status_code
                        resp_headers = {k: v for k, v in response.headers.items()}
                        collected = bytearray()
                        truncated = False
                        for chunk in response.iter_bytes():
                            collected.extend(chunk)
                            if len(collected) >= budget:
                                truncated = True
                                break
            except httpx.TimeoutException as exc:
                raise NetworkError(f"timeout contacting {target}", detail=str(exc)) from exc
            except httpx.HTTPError as exc:
                raise NetworkError(
                    f"request to {target} failed", detail=type(exc).__name__
                ) from exc

            location = resp_headers.get("location") or resp_headers.get("Location")
            if (
                follow_redirects
                and status in {301, 302, 303, 307, 308}
                and location
                and hop < self.max_redirects
            ):
                chain.append(target)
                target = self._guard(urljoin(target, location))
                if status == 303:
                    method, json_body, data = "GET", None, None
                continue

            elapsed = (time.perf_counter() - started) * 1000
            return HttpResponse(
                url=target,
                status=status,
                headers=resp_headers,
                body=bytes(collected[:budget]),
                elapsed_ms=elapsed,
                redirect_chain=chain,
                truncated=truncated,
            )

        raise NetworkError(
            f"too many redirects contacting {url}",
            detail=f"limit is {self.max_redirects}",
        )

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("HEAD", url, **kwargs)

    def post_json(self, url: str, payload: Any, **kwargs: Any) -> HttpResponse:
        return self.request("POST", url, json_body=payload, **kwargs)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.get(url, **kwargs).json()

    def probe(self, url: str, *, timeout: float = 4.0) -> dict[str, Any]:
        """Reachability check that reports *why* it failed instead of raising."""
        started = time.perf_counter()
        try:
            response = self.get(url, timeout=timeout, max_bytes=64 * 1024)
            return {
                "reachable": True,
                "status": response.status,
                "elapsed_ms": round(response.elapsed_ms, 1),
                "error": None,
            }
        except (NetworkError, UnsafeTargetError, ValidationError) as exc:
            return {
                "reachable": False,
                "status": None,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                "error": redact(exc.message),
                "code": getattr(exc, "code", "kingdomx.error"),
            }
        except Exception as exc:  # noqa: BLE001 - a probe must never raise
            return {
                "reachable": False,
                "status": None,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                "error": redact(type(exc).__name__),
                "code": "kingdomx.unexpected",
            }


def default_client(
    *, timeout: float = DEFAULT_TIMEOUT, user_agent: str = "KingdomX/1.0"
) -> SafeHttpClient:
    """A client for public-internet lookups: private targets stay blocked."""
    return SafeHttpClient(timeout=timeout, user_agent=user_agent)
