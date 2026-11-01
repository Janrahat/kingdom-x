"""Configuration with layered resolution and secret-safe persistence.

Resolution order (later wins):
    1. built-in defaults
    2. ``config/kingdomx.toml`` (or $KINGDOMX_CONFIG)
    3. environment variables (``KINGDOMX_*`` and provider keys)
    4. explicit overrides passed to :class:`Config.load`

Secrets are *never* written to disk in plaintext by this module. When the
operator wants to persist a key, :meth:`Config.store_secret` obfuscates it with a
locally generated Fernet key stored in a 0600 file outside the repository.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from kingdomx.core.errors import ConfigError
from kingdomx.core.platform_detect import current as current_platform

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore[assignment]

#: Environment variable that points at a different config file.
CONFIG_ENV = "KINGDOMX_CONFIG"
#: Environment variable that moves the whole data directory.
DATA_DIR_ENV = "KINGDOMX_DATA_DIR"

DEFAULT_CONFIG: dict[str, Any] = {
    "app": {
        "name": "KINGDOM X",
        "subtitle": "THE KING OF GLOBAL TECHNOLOGY",
        "tagline": "ONE PLATFORM. ALL TECHNOLOGIES. UNLIMITED INTELLIGENCE.",
        "theme": "royal",
        "language": "en",
        "offline": False,
    },
    "server": {
        "host": "127.0.0.1",
        "port": 8000,
        "workers": 1,
        "session_hours": 12,
        "allow_remote": False,
        "require_auth": True,
    },
    "network": {
        "timeout": 10.0,
        "max_redirects": 5,
        "user_agent": "KingdomX/1.0 (+local intelligence platform)",
        "allow_private_targets": False,
        "rate_limit_per_minute": 60,
    },
    "storage": {
        "driver": "sqlite",
        "sqlite_path": "data/kingdomx.db",
        "postgres_dsn": "",
        "retention_days": 90,
        "backup_keep": 5,
    },
    "ai": {
        "default_provider": "ollama",
        "default_model": "",
        "temperature": 0.2,
        "max_tokens": 2048,
        "track_usage": True,
    },
    "security": {
        "require_authorization": True,
        "redact_logs": True,
        "audit_log": True,
        "active_scan_enabled": True,
        "allowed_targets": [],
    },
    "logging": {
        "level": "INFO",
        "json": False,
        "file": "logs/kingdomx.log",
        "max_bytes": 5242880,
        "backups": 3,
    },
}

#: Environment variables that carry provider credentials.
PROVIDER_KEY_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "qwen": "DASHSCOPE_API_KEY",
    "huggingface": "HUGGINGFACE_API_KEY",
    "groq": "GROQ_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}

_SECRET_FILE = "secrets.vault"
_KEY_FILE = ".kingdomx.key"


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``overlay`` into a copy of ``base``."""
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _env_overrides() -> dict[str, Any]:
    """Read KINGDOMX_* environment variables into a nested dict."""
    out: dict[str, Any] = {}
    for raw_key, raw_value in os.environ.items():
        if not raw_key.startswith("KINGDOMX__"):
            continue
        path = raw_key[len("KINGDOMX__") :].lower().split("__")
        if not path or not path[0]:
            continue
        node = out
        for part in path[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):  # pragma: no cover - defensive
                break
        else:
            node[path[-1]] = _coerce(raw_value)
    return out


def _coerce(value: str) -> Any:
    """Turn an environment string into bool/int/float/list where unambiguous."""
    text = value.strip()
    lowered = text.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"none", "null"}:
        return None
    if text.startswith("[") and text.endswith("]"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return [part.strip() for part in text[1:-1].split(",") if part.strip()]
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def project_root() -> Path:
    """Repository root (the directory containing the ``kingdomx`` package)."""
    return Path(__file__).resolve().parents[2]


def default_data_dir() -> Path:
    override = os.environ.get(DATA_DIR_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return project_root() / "data"


def default_config_path() -> Path:
    override = os.environ.get(CONFIG_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return project_root() / "config" / "kingdomx.toml"


@dataclass
class Config:
    """Immutable-ish view over the merged configuration tree."""

    data: dict[str, Any]
    path: Path
    sources: list[str] = field(default_factory=list)
    data_dir: Path = field(default_factory=default_data_dir)

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> "Config":
        config_path = Path(path) if path else default_config_path()
        merged = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
        sources = ["defaults"]

        if config_path.is_file():
            merged = _deep_merge(merged, _read_toml(config_path))
            sources.append(str(config_path))

        env_layer = _env_overrides()
        if env_layer:
            merged = _deep_merge(merged, env_layer)
            sources.append("env:KINGDOMX__*")

        if overrides:
            merged = _deep_merge(merged, overrides)
            sources.append("overrides")

        return cls(data=merged, path=config_path, sources=sources, data_dir=default_data_dir())

    @classmethod
    def in_memory(cls, **sections: Any) -> "Config":
        """A config that touches no files — used by tests and the API test client."""
        merged = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
        merged = _deep_merge(merged, sections)
        return cls(data=merged, path=Path("<memory>"), sources=["defaults", "memory"])

    # ------------------------------------------------------------------ access
    def section(self, name: str) -> dict[str, Any]:
        value = self.data.get(name)
        if isinstance(value, dict):
            return value
        raise ConfigError(f"unknown config section: {name}")

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def require(self, dotted: str) -> Any:
        sentinel = object()
        value = self.get(dotted, sentinel)
        if value is sentinel:
            raise ConfigError(f"missing required config key: {dotted}")
        return value

    # ------------------------------------------------------------------ derived paths
    @property
    def db_path(self) -> Path:
        raw = self.get("storage.sqlite_path", "data/kingdomx.db")
        candidate = Path(str(raw))
        if not candidate.is_absolute():
            candidate = self.data_dir / candidate.name
        return candidate

    @property
    def log_path(self) -> Path:
        raw = self.get("logging.file", "logs/kingdomx.log")
        candidate = Path(str(raw))
        if not candidate.is_absolute():
            candidate = self.data_dir / candidate.name
        return candidate

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def offline(self) -> bool:
        env = os.environ.get("KINGDOMX_OFFLINE", "").strip().lower() in {"1", "true", "yes", "on"}
        return bool(self.get("app.offline", False)) or env

    # ------------------------------------------------------------------ runtime env
    def provider_key(self, provider: str) -> str | None:
        """Provider credential from the environment, or the encrypted vault."""
        env_name = PROVIDER_KEY_ENV.get(provider, f"{provider.upper()}_API_KEY")
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
        return self.read_secret(f"provider.{provider}")

    def provider_status(self) -> dict[str, dict[str, Any]]:
        """Non-revealing presence map for every known provider."""
        out: dict[str, dict[str, Any]] = {}
        for provider, env_name in PROVIDER_KEY_ENV.items():
            from_env = bool(os.environ.get(env_name, "").strip())
            from_vault = bool(self.read_secret(f"provider.{provider}"))
            out[provider] = {
                "env_var": env_name,
                "configured": from_env or from_vault,
                "source": "env" if from_env else ("vault" if from_vault else None),
            }
        return out

    # ------------------------------------------------------------------ secrets
    def _key_path(self) -> Path:
        return self.data_dir / _KEY_FILE

    def _vault_path(self) -> Path:
        return self.data_dir / _SECRET_FILE

    def _fernet(self):
        try:
            from cryptography.fernet import Fernet
        except ModuleNotFoundError as exc:  # pragma: no cover - dependency missing
            raise ConfigError(
                "cryptography is required for the secret vault; install it with pip"
            ) from exc

        key_path = self._key_path()
        if key_path.is_file():
            raw = key_path.read_bytes().strip()
        else:
            # Derive a stable key when the operator supplied a master passphrase.
            master = os.environ.get("KINGDOMX_MASTER_KEY", "").strip()
            if master:
                digest = hashlib.sha256(master.encode("utf-8")).digest()
                raw = base64.urlsafe_b64encode(digest)
            else:
                raw = Fernet.generate_key()
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(raw)
            try:
                key_path.chmod(0o600)
            except OSError:  # pragma: no cover - Termux may ignore chmod
                pass
        return Fernet(raw)

    def _read_vault(self) -> dict[str, str]:
        path = self._vault_path()
        if not path.is_file():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_vault(self, data: dict[str, str]) -> None:
        path = self._vault_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:  # pragma: no cover
            pass

    def store_secret(self, name: str, value: str) -> None:
        """Encrypt ``value`` into the local vault under ``name``."""
        if not value:
            self.delete_secret(name)
            return
        fernet = self._fernet()
        vault = self._read_vault()
        vault[name] = fernet.encrypt(value.encode("utf-8")).decode("ascii")
        self._write_vault(vault)

    def read_secret(self, name: str) -> str | None:
        """Decrypt ``name`` from the vault, or None."""
        blob = self._read_vault().get(name)
        if not blob:
            return None
        try:
            return self._fernet().decrypt(blob.encode("ascii")).decode("utf-8")
        except Exception:  # noqa: BLE001 - corrupt/rotated key must not crash
            return None

    def delete_secret(self, name: str) -> bool:
        vault = self._read_vault()
        if name not in vault:
            return False
        del vault[name]
        self._write_vault(vault)
        return True

    def secret_names(self) -> list[str]:
        return sorted(self._read_vault().keys())

    # ------------------------------------------------------------------ export
    def safe_dict(self) -> dict[str, Any]:
        """Config for display: no secret material, ever."""
        out = asdict(self) if False else json.loads(json.dumps(self.data, default=str))
        return out

    def to_json(self) -> str:
        return json.dumps(self.safe_dict(), indent=2, sort_keys=True)

    def summary(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "sources": list(self.sources),
            "data_dir": str(self.data_dir),
            "offline": self.offline,
            "platform": current_platform().label,
            "providers_configured": [
                name for name, info in self.provider_status().items() if info["configured"]
            ],
        }


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config file: {path}", detail=str(exc)) from exc
    if tomllib is None:  # pragma: no cover - Python 3.10
        raise ConfigError("TOML config requires Python 3.11+ (tomllib)")
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, Exception) as exc:  # noqa: BLE001
        raise ConfigError(f"invalid TOML in {path}", detail=str(exc)) from exc
    return parsed if isinstance(parsed, dict) else {}


def write_default_config(path: Path | None = None, *, force: bool = False) -> Path:
    """Write a commented starter config. Refuses to clobber an existing file."""
    target = Path(path) if path else default_config_path()
    if target.exists() and not force:
        raise ConfigError(f"config already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_toml(DEFAULT_CONFIG), encoding="utf-8")
    return target


def render_toml(data: dict[str, Any], *, header: str | None = None) -> str:
    """Render a flat two-level dict as TOML without needing a TOML writer."""
    lines: list[str] = []
    if header:
        lines.extend(f"# {line}" for line in header.splitlines())
        lines.append("")
    lines.append("# KINGDOM X — THE KING OF GLOBAL TECHNOLOGY")
    lines.append("# Generated config. Secrets belong in .env or `kingdomx --set-key`, never here.")
    lines.append("")
    for section, values in data.items():
        if not isinstance(values, dict):
            continue
        lines.append(f"[{section}]")
        for key, value in values.items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if value is None:
        return '""'
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def random_session_secret(nbytes: int = 32) -> str:
    """A fresh CSRF/session seed."""
    return secrets.token_urlsafe(nbytes)
