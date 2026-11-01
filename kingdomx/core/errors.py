"""Exception hierarchy.

Every error carries a machine-readable ``code`` so the terminal UI and the API can
render a consistent status without string matching.
"""

from __future__ import annotations


class KingdomXError(Exception):
    """Base class for every expected KINGDOM X failure."""

    code = "kingdomx.error"
    http_status = 500

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict:
        payload = {"code": self.code, "message": self.message}
        if self.detail:
            payload["detail"] = self.detail
        return payload

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.detail:
            return f"{self.message} ({self.detail})"
        return self.message


class ConfigError(KingdomXError):
    code = "kingdomx.config"
    http_status = 500


class ValidationError(KingdomXError):
    code = "kingdomx.validation"
    http_status = 400


class NetworkError(KingdomXError):
    code = "kingdomx.network"
    http_status = 502


class UnsafeTargetError(KingdomXError):
    """The operator asked us to touch something we must refuse to touch."""

    code = "kingdomx.unsafe_target"
    http_status = 403


class ProviderError(KingdomXError):
    code = "kingdomx.provider"
    http_status = 502


class StorageError(KingdomXError):
    code = "kingdomx.storage"
    http_status = 500


class PluginError(KingdomXError):
    code = "kingdomx.plugin"
    http_status = 400


class AuthorizationError(KingdomXError):
    """An active operation was requested without recorded authorisation."""

    code = "kingdomx.authorization"
    http_status = 403
