"""Real availability checks.

The rule this module enforces: **a model is only marked available when a real
call succeeded.** There are three verification levels:

``unverified``
    No call attempted (missing key, offline, provider unreachable).
``listed``
    The provider's model-list endpoint returned this model id.
``chat_ok``
    A minimal chat completion actually produced text.

A model that is merely in :mod:`kingdomx.ai.catalog` stays ``unverified`` forever.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

from kingdomx.ai.catalog import ProviderSpec, get_spec
from kingdomx.ai.client import ChatRequest, build_request, parse_model_list, parse_response
from kingdomx.core.errors import NetworkError, ProviderError, UnsafeTargetError
from kingdomx.core.http import SafeHttpClient
from kingdomx.core.logging_setup import get_logger

log = get_logger("ai.health")

VERIFY_UNVERIFIED = "unverified"
VERIFY_LISTED = "listed"
VERIFY_CHAT_OK = "chat_ok"


@dataclass
class HealthResult:
    """The outcome of contacting one provider."""

    provider: str
    reachable: bool
    key_present: bool
    models: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    error_code: str | None = None
    latency_ms: float = 0.0
    checked_at: float = field(default_factory=time.time)
    verification: str = VERIFY_UNVERIFIED
    http_status: int | None = None

    @property
    def ok(self) -> bool:
        return self.reachable and not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "reachable": self.reachable,
            "key_present": self.key_present,
            "model_count": len(self.models),
            "models": list(self.models),
            "error": self.error,
            "error_code": self.error_code,
            "latency_ms": round(self.latency_ms, 1),
            "checked_at": self.checked_at,
            "verification": self.verification,
            "http_status": self.http_status,
        }


def _client_for(spec: ProviderSpec, timeout: float) -> SafeHttpClient:
    """A client appropriate to the provider's locality.

    A local runtime (Ollama) legitimately lives on 127.0.0.1, which the SSRF guard
    blocks by default — so we allow private targets *only* for providers flagged
    ``local``.
    """
    return SafeHttpClient(
        timeout=timeout,
        allow_private=spec.local,
        user_agent="KingdomX/1.0 ai-health",
    )


def resolve_key(spec: ProviderSpec, api_key: str | None = None) -> str | None:
    if api_key:
        return api_key
    if spec.name == "ollama":
        # OLLAMA_HOST is a *host*, not a credential; there is no key.
        return None
    return os.environ.get(spec.env_var, "").strip() or None


def check_provider(
    provider: str,
    *,
    api_key: str | None = None,
    timeout: float = 10.0,
    deep: bool = False,
    model: str | None = None,
    base_url: str | None = None,
) -> HealthResult:
    """Contact ``provider`` for real and report what actually happened.

    ``deep=True`` additionally sends a one-word chat request to prove the model
    answers, which is the only way to distinguish ``listed`` from ``chat_ok``.
    """
    spec = get_spec(provider)
    if spec is None:
        return HealthResult(
            provider=provider,
            reachable=False,
            key_present=False,
            error=f"unknown provider: {provider}",
            error_code="kingdomx.provider.unknown",
        )

    if base_url:
        spec = ProviderSpec(
            name=spec.name,
            label=spec.label,
            base_url=base_url.rstrip("/"),
            kind=spec.kind,
            env_var=spec.env_var,
            docs_url=spec.docs_url,
            key_required=spec.key_required,
            local=spec.local,
            models_path=spec.models_path,
            chat_path=spec.chat_path,
            auth_style=spec.auth_style,
            default_model=spec.default_model,
            notes=spec.notes,
            known_models=spec.known_models,
        )

    key = resolve_key(spec, api_key)
    if spec.key_required and not key:
        return HealthResult(
            provider=spec.name,
            reachable=False,
            key_present=False,
            error=f"{spec.env_var} is not set",
            error_code="kingdomx.provider.no_key",
            verification=VERIFY_UNVERIFIED,
        )

    client = _client_for(spec, timeout)
    started = time.perf_counter()

    try:
        from kingdomx.ai.client import build_headers

        headers = build_headers(spec, key)
        response = client.get(spec.models_url, headers=headers, timeout=timeout)
    except (NetworkError, UnsafeTargetError, ProviderError) as exc:
        return HealthResult(
            provider=spec.name,
            reachable=False,
            key_present=bool(key),
            error=exc.message,
            error_code=getattr(exc, "code", "kingdomx.network"),
            latency_ms=(time.perf_counter() - started) * 1000,
        )

    latency = (time.perf_counter() - started) * 1000
    if response.status >= 400:
        return HealthResult(
            provider=spec.name,
            reachable=True,
            key_present=bool(key),
            error=f"HTTP {response.status} from {spec.models_url}",
            error_code="kingdomx.provider.http_error",
            latency_ms=latency,
            http_status=response.status,
        )

    try:
        payload = response.json()
    except NetworkError as exc:
        return HealthResult(
            provider=spec.name,
            reachable=True,
            key_present=bool(key),
            error=exc.message,
            error_code=exc.code,
            latency_ms=latency,
            http_status=response.status,
        )

    models = parse_model_list(spec, payload)
    result = HealthResult(
        provider=spec.name,
        reachable=True,
        key_present=bool(key),
        models=models,
        latency_ms=latency,
        http_status=response.status,
        verification=VERIFY_LISTED if models else VERIFY_UNVERIFIED,
    )

    if deep:
        target_model = model or _pick_model(spec, models)
        if not target_model:
            result.error = "no model available to test"
            result.error_code = "kingdomx.provider.no_model"
            return result
        check = _chat_probe(spec, target_model, key, timeout)
        if check["ok"]:
            result.verification = VERIFY_CHAT_OK
            result.error = None
        else:
            result.error = check["error"]
            result.error_code = check["code"]
            result.verification = VERIFY_LISTED

    return result


def _pick_model(spec: ProviderSpec, models: list[dict[str, Any]]) -> str | None:
    """Prefer a small/cheap model for the probe."""
    if spec.default_model and any(m["name"] == spec.default_model for m in models):
        return spec.default_model
    preferences = ("mini", "flash", "small", "turbo", "instant", "haiku", "8b")
    names = [m["name"] for m in models]
    for marker in preferences:
        for name in names:
            if marker in name.lower():
                return name
    return names[0] if names else (spec.default_model or None)


def _chat_probe(spec: ProviderSpec, model: str, key: str | None, timeout: float) -> dict[str, Any]:
    """Send the smallest possible chat request to prove the model replies."""
    request = ChatRequest.from_prompt(
        "Reply with the single word: OK",
        model=model,
        temperature=0.0,
        max_tokens=8,
    )
    try:
        built = build_request(spec, request, api_key=key)
        client = _client_for(spec, timeout)
        response = client.request(
            built["method"],
            built["url"],
            json_body=built["payload"],
            headers=built["headers"],
            timeout=timeout,
            max_bytes=256 * 1024,
        )
        parsed = parse_response(spec, response.status, response.body)
        if parsed.blocked:
            return {"ok": False, "error": f"blocked: {parsed.block_reason}", "code": "kingdomx.provider.blocked"}
        if not parsed.text.strip():
            return {
                "ok": False,
                "error": "model returned an empty completion",
                "code": "kingdomx.provider.empty",
            }
        return {"ok": True, "error": None, "code": None}
    except (NetworkError, ProviderError, UnsafeTargetError) as exc:
        return {
            "ok": False,
            "error": exc.message,
            "code": getattr(exc, "code", "kingdomx.provider"),
        }
    except Exception as exc:  # noqa: BLE001 - a probe must never crash the UI
        return {"ok": False, "error": type(exc).__name__, "code": "kingdomx.unexpected"}


def check_all(
    *,
    providers: list[str] | None = None,
    timeout: float = 8.0,
    api_keys: dict[str, str] | None = None,
) -> dict[str, HealthResult]:
    """Check each provider, returning results keyed by provider name."""
    from kingdomx.ai.catalog import provider_names

    keys = dict(api_keys or {})
    out: dict[str, HealthResult] = {}
    for name in providers or provider_names():
        out[name] = check_provider(name, api_key=keys.get(name), timeout=timeout)
    return out


def ollama_status(host: str | None = None, *, timeout: float = 3.0) -> dict[str, Any]:
    """Report whether a local Ollama daemon is running and what it has pulled."""
    base = (host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")
    if not base.startswith("http"):
        base = "http://" + base
    client = SafeHttpClient(timeout=timeout, allow_private=True, user_agent="KingdomX/1.0")
    try:
        response = client.get(f"{base}/api/tags", timeout=timeout)
    except (NetworkError, UnsafeTargetError) as exc:
        return {
            "running": False,
            "host": base,
            "models": [],
            "error": exc.message,
        }
    if response.status >= 400:
        return {
            "running": False,
            "host": base,
            "models": [],
            "error": f"HTTP {response.status}",
        }
    try:
        payload = response.json()
    except NetworkError as exc:
        return {"running": False, "host": base, "models": [], "error": exc.message}

    models = [
        {
            "name": item.get("name") or item.get("model") or "",
            "size": item.get("size"),
            "modified_at": item.get("modified_at"),
        }
        for item in (payload.get("models") or [])
        if isinstance(item, dict)
    ]
    return {"running": True, "host": base, "models": models, "error": None}
