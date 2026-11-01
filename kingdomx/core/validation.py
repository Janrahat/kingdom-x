"""Input validation and safety checks.

Two categories live here:

* **Format validators** — is this a domain, IP, CIDR, email, port, MAC, hash?
* **Safety validators** — is this target something we must refuse to touch?

Safety checks are deliberately separate from format checks: a value can be a
perfectly valid IP address and still be a private address we refuse to reach.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

from kingdomx.core.errors import UnsafeTargetError, ValidationError

# --------------------------------------------------------------------------- regexes
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\u0080-\uffff-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9\u0080-\uffff-]{1,63}(?<!-))*$"
)
LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
SHA_RE = {
    "md5": re.compile(r"^[0-9a-fA-F]{32}$"),
    "sha1": re.compile(r"^[0-9a-fA-F]{40}$"),
    "sha256": re.compile(r"^[0-9a-fA-F]{64}$"),
    "sha512": re.compile(r"^[0-9a-fA-F]{128}$"),
}

#: Hosts that must never be the target of an active scan unless explicitly allowed.
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
        "metadata",
        "instance-data",
    }
)

#: TLDs reserved for documentation and local use — not scannable targets.
RESERVED_TLDS = frozenset({"test", "invalid", "example", "localhost", "local"})


# --------------------------------------------------------------------------- results
@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    value: str
    reason: str | None = None
    normalised: str | None = None

    def raise_if_invalid(self, field: str = "value") -> str:
        if not self.ok:
            raise ValidationError(f"invalid {field}: {self.value}", detail=self.reason)
        return self.normalised or self.value


# --------------------------------------------------------------------------- formats
def validate_domain(value: str) -> ValidationResult:
    text = (value or "").strip().lower().rstrip(".")
    if not text:
        return ValidationResult(False, value, "empty")
    if len(text) > 253:
        return ValidationResult(False, value, "longer than 253 characters")
    if text.startswith("*."):
        text = text[2:]
    if text.startswith(".") or text.endswith("."):
        return ValidationResult(False, value, "leading or trailing dot")
    if ".." in text:
        return ValidationResult(False, value, "empty label")
    if not DOMAIN_RE.match(text):
        return ValidationResult(False, value, "not a valid DNS name")
    labels = text.split(".")
    for label in labels:
        if not LABEL_RE.match(label):
            return ValidationResult(False, value, f"invalid label: {label}")
    if labels[-1].isdigit():
        return ValidationResult(False, value, "TLD cannot be numeric")
    return ValidationResult(True, value, normalised=text)


def is_valid_domain(value: str) -> bool:
    return validate_domain(value).ok


def validate_ip(value: str) -> ValidationResult:
    text = (value or "").strip().strip("[]")
    if not text:
        return ValidationResult(False, value, "empty")
    try:
        addr = ipaddress.ip_address(text)
    except ValueError as exc:
        return ValidationResult(False, value, str(exc))
    return ValidationResult(True, value, normalised=str(addr))


def is_ip(value: str) -> bool:
    return validate_ip(value).ok


def validate_cidr(value: str) -> ValidationResult:
    text = (value or "").strip()
    if "/" not in text:
        return ValidationResult(False, value, "missing prefix length")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        return ValidationResult(False, value, str(exc))
    return ValidationResult(True, value, normalised=str(net))


def validate_port(value: int | str) -> ValidationResult:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return ValidationResult(False, str(value), "not an integer")
    if not 1 <= port <= 65535:
        return ValidationResult(False, str(value), "outside 1-65535")
    return ValidationResult(True, str(value), normalised=str(port))


def validate_port_spec(value: str) -> ValidationResult:
    """Accept ``80``, ``80,443`` or ``1-1024`` (nmap-style)."""
    text = (value or "").strip().replace(" ", "")
    if not text:
        return ValidationResult(False, value, "empty")
    for chunk in text.split(","):
        if not chunk:
            return ValidationResult(False, value, "empty item")
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            if not (validate_port(lo).ok and validate_port(hi).ok):
                return ValidationResult(False, value, f"bad range: {chunk}")
            if int(lo) > int(hi):
                return ValidationResult(False, value, f"reversed range: {chunk}")
        elif not validate_port(chunk).ok:
            return ValidationResult(False, value, f"bad port: {chunk}")
    return ValidationResult(True, value, normalised=text)


def validate_email(value: str) -> ValidationResult:
    text = (value or "").strip()
    if len(text) > 254:
        return ValidationResult(False, value, "longer than 254 characters")
    if not EMAIL_RE.match(text):
        return ValidationResult(False, value, "not a valid address")
    return ValidationResult(True, value, normalised=text.lower())


def validate_mac(value: str) -> ValidationResult:
    text = (value or "").strip()
    if not MAC_RE.match(text):
        return ValidationResult(False, value, "not a MAC address")
    return ValidationResult(True, value, normalised=text.lower().replace("-", ":"))


def validate_hash(value: str, algorithm: str | None = None) -> ValidationResult:
    text = (value or "").strip()
    if algorithm:
        pattern = SHA_RE.get(algorithm.lower())
        if pattern is None:
            return ValidationResult(False, value, f"unknown algorithm: {algorithm}")
        if not pattern.match(text):
            return ValidationResult(False, value, f"not a {algorithm} digest")
        return ValidationResult(True, value, normalised=text.lower(), reason=algorithm.lower())
    for name, pattern in SHA_RE.items():
        if pattern.match(text):
            return ValidationResult(True, value, normalised=text.lower(), reason=name)
    return ValidationResult(False, value, "not a recognised hex digest")


def detect_hash_algorithm(value: str) -> str | None:
    result = validate_hash(value)
    return result.reason if result.ok else None


def validate_host(value: str, *, allow_cidr: bool = False) -> ValidationResult:
    """A host may be a domain, an IPv4/IPv6 address, or (optionally) a CIDR."""
    text = (value or "").strip()
    if not text:
        return ValidationResult(False, value, "empty")
    if is_ip(text):
        return validate_ip(text)
    if "/" in text:
        if not allow_cidr:
            return ValidationResult(False, value, "CIDR not permitted here")
        return validate_cidr(text)
    if text.count(":") == 1 and not text.startswith("["):
        host, _, port = text.partition(":")
        if validate_port(port).ok and validate_domain(host).ok:
            return ValidationResult(True, value, normalised=f"{host.lower()}:{port}")
    return validate_domain(text)


# --------------------------------------------------------------------------- safety
def is_private_address(addr) -> bool:
    """True for anything that is not a globally routable unicast address."""
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in ipaddress.ip_network("100.64.0.0/10"):  # CGNAT
            return True
        if addr in ipaddress.ip_network("192.0.0.0/24"):  # IETF protocol
            return True
        if addr in ipaddress.ip_network("198.18.0.0/15"):  # benchmarking
            return True
    else:
        if addr in ipaddress.ip_network("fc00::/7"):  # unique local
            return True
        if getattr(addr, "ipv4_mapped", None) is not None:
            return is_private_address(addr.ipv4_mapped)
    return not addr.is_global


def check_target_safe(
    host: str,
    *,
    allow_private: bool = False,
    allow: Iterable[str] | None = None,
) -> str:
    """Refuse SSRF-prone targets unless the operator explicitly allowed them.

    ``allow`` is an operator-supplied allowlist of exact hosts or CIDRs for a lab
    environment. It is never populated automatically.
    """
    text = (host or "").strip().strip("[]").lower().rstrip(".")
    if not text:
        raise UnsafeTargetError("empty target")

    allow_list = [str(item).strip().lower() for item in (allow or []) if str(item).strip()]
    if text in allow_list:
        return text

    if text in BLOCKED_HOSTNAMES:
        raise UnsafeTargetError(
            f"refusing to contact {text}",
            detail="loopback/local names are blocked as SSRF targets",
        )

    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        addr = None

    if addr is not None:
        for entry in allow_list:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return text
            except ValueError:
                continue
        if not allow_private and is_private_address(addr):
            raise UnsafeTargetError(
                f"refusing to contact {text}",
                detail="private/loopback/link-local addresses require allow_private_targets",
            )
        return text

    tld = text.rsplit(".", 1)[-1] if "." in text else ""
    if tld in RESERVED_TLDS and not allow_private:
        raise UnsafeTargetError(
            f"refusing to contact {text}",
            detail=f".{tld} is a reserved documentation TLD",
        )
    return text


def normalise_url(url: str, *, allow_schemes: Iterable[str] = ("http", "https")) -> str:
    """Validate and normalise an absolute URL."""
    text = (url or "").strip()
    if not text:
        raise ValidationError("empty URL")
    if len(text) > 8192:
        raise ValidationError("URL longer than 8192 characters")
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://", text):
        text = "https://" + text
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    allowed = {s.lower() for s in allow_schemes}
    if scheme not in allowed:
        raise ValidationError(
            f"scheme {scheme!r} not allowed",
            detail="allowed schemes: " + ", ".join(sorted(allowed)),
        )
    if not parts.hostname:
        raise ValidationError("URL has no host")
    host_check = validate_host(parts.hostname)
    if not host_check.ok:
        raise ValidationError(f"invalid URL host: {parts.hostname}", detail=host_check.reason)
    if parts.port is not None and not validate_port(parts.port).ok:
        raise ValidationError(f"invalid URL port: {parts.port}")
    netloc = parts.netloc
    # Strip credentials embedded in the URL — a phishing / redirect vector.
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def safe_url_for_display(url: str, *, max_len: int = 120) -> str:
    """Render a URL for a table cell without credentials or query secrets."""
    try:
        parts = urlsplit(url if "://" in url else "https://" + url)
    except ValueError:
        return url[:max_len]
    netloc = parts.netloc.rsplit("@", 1)[-1]
    path = parts.path or "/"
    rendered = f"{parts.scheme or 'https'}://{netloc}{path}"
    if len(rendered) > max_len:
        rendered = rendered[: max_len - 1] + "…"
    return rendered


def validate_phone_number(value: str) -> ValidationResult:
    """E.164-shaped structural check only. Never resolves a subscriber."""
    text = (value or "").strip()
    cleaned = re.sub(r"[\s\-().]", "", text)
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned
    if not re.match(r"^\+[1-9]\d{6,14}$", cleaned):
        return ValidationResult(False, value, "not a plausible E.164 number")
    return ValidationResult(True, value, normalised=cleaned)


def clamp_text(value: str, *, limit: int = 4096) -> str:
    """Bound a user string and strip control characters."""
    text = (value or "")[:limit]
    return "".join(ch for ch in text if ch in "\n\t" or ord(ch) >= 32)


def check_no_shell_metachars(value: str, field: str = "value") -> str:
    """Reject strings that would be dangerous if ever passed to a shell.

    KINGDOM X never builds a shell command string, but rejecting these at the
    input boundary means a future refactor cannot introduce an injection.
    """
    forbidden = set(";|&$`><\n\r\0\\")
    found = sorted(forbidden.intersection(value or ""))
    if found:
        raise ValidationError(
            f"{field} contains shell metacharacters",
            detail="rejected: " + " ".join(repr(ch) for ch in found),
        )
    return value
