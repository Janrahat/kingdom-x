"""Secret redaction.

Anything that reaches a log line, a report, an API response or the terminal must
first pass through :func:`redact`. The rule is fail-closed: if a value *looks*
like a credential it is masked, even when we are not certain it is one.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

MASK = "***REDACTED***"

#: Names whose *value* must never be printed.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "api-key",
        "api_secret",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "passphrase",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "bearer",
        "authorization",
        "auth",
        "session",
        "session_id",
        "session_token",
        "cookie",
        "set-cookie",
        "private_key",
        "secret_key",
        "signing_key",
        "credentials",
        "x-api-key",
        "anthropic_api_key",
        "openai_api_key",
        "gemini_api_key",
    }
)

#: Keys that merely *mention* a secret concept and are safe to print.
SAFE_KEYS: frozenset[str] = frozenset(
    {
        "key_present",
        "has_key",
        "api_key_configured",
        "api_key_source",
        "token_count",
        "tokens",
        "key_name",
        "key_prefix",
        "token_budget",
        "secret_backend",
    }
)

# Well-known credential shapes. Order matters: most specific first.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b")),
    ("google", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    ("github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b")),
    ("aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}")),
    ("conn_string", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|redis|mongodb)://[^\s:@/]+:[^\s@/]+@")),
)


def _is_sensitive_key(key: str) -> bool:
    normalised = key.strip().lower().replace(" ", "_").replace("-", "_")
    if normalised in SAFE_KEYS:
        return False
    if normalised in SENSITIVE_KEYS:
        return True
    compact = normalised.replace("_", "")
    for candidate in SENSITIVE_KEYS:
        if compact == candidate.replace("_", "").replace("-", ""):
            return True
    return any(
        marker in compact
        for marker in ("apikey", "secret", "password", "passwd", "accesstoken", "refreshtoken")
    )


def redact_text(text: str) -> str:
    """Mask every credential-shaped substring in ``text``."""
    if not text:
        return text
    result = text
    for _name, pattern in _PATTERNS:
        result = pattern.sub(MASK, result)
    return result


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact ``value``.

    Dict keys are preserved (they are useful for diagnosis); only values are
    masked. Depth is bounded so a cyclic structure can never hang the caller.
    """
    if _depth > 12:
        return "<max-depth>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _is_sensitive_key(key):
                out[key] = MASK if item else ""
            else:
                out[key] = redact(item, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        seq: Iterable[Any] = value
        return [redact(item, _depth=_depth + 1) for item in seq]
    return redact_text(str(value))


def contains_secret(text: str) -> bool:
    """True when ``text`` holds something that looks like a credential."""
    if not text:
        return False
    return any(pattern.search(text) for _name, pattern in _PATTERNS)


def mask_secret(secret: str, *, visible: int = 4) -> str:
    """Render a credential safely for confirmation messages (``sk-…a1b2``)."""
    if not secret:
        return ""
    if len(secret) <= visible * 2:
        return MASK
    return f"{secret[:visible]}{'…'}{secret[-visible:]}"


def describe_presence(secret: str | None) -> dict:
    """Non-revealing metadata about a configured credential."""
    if not secret:
        return {"present": False, "length": 0, "prefix": ""}
    return {
        "present": True,
        "length": len(secret),
        "prefix": secret[:3] if len(secret) > 8 else MASK,
    }
