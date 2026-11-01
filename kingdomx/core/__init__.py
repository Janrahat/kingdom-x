"""Core primitives shared by every KINGDOM X module."""

from kingdomx.core.errors import (
    AuthorizationError,
    ConfigError,
    KingdomXError,
    NetworkError,
    PluginError,
    ProviderError,
    StorageError,
    UnsafeTargetError,
    ValidationError,
)

__all__ = [
    "KingdomXError",
    "ConfigError",
    "ValidationError",
    "NetworkError",
    "UnsafeTargetError",
    "ProviderError",
    "StorageError",
    "PluginError",
    "AuthorizationError",
]
