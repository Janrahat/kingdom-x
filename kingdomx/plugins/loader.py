"""Plugin manifests, installation and sandboxed execution."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kingdomx.core.logging_setup import get_logger

log = get_logger("plugins.loader")

MANIFEST_NAME = "plugin.json"
ENTRY_NAME = "plugin.py"
RUN_TIMEOUT = 60.0
MAX_MANIFEST_BYTES = 64 * 1024

#: Capabilities a plugin may request. Anything not in this set is a hard error.
PERMISSIONS: dict[str, str] = {
    "network": "May make outbound network requests.",
    "filesystem.read": "May read files the operator's user can read.",
    "filesystem.write": "May write files.",
    "subprocess": "May execute external programs.",
    "ai": "May call a configured AI provider (uses the operator's keys).",
    "database": "May read and write the KINGDOM X SQLite database.",
}

#: Permissions that are refused outright — they cannot be granted to a plugin.
FORBIDDEN_PERMISSIONS: dict[str, str] = {
    "root": "Plugins never run as root. Run the specific command yourself if needed.",
    "kernel": "Kernel-level access is out of scope for a plugin.",
    "credentials.read": "Plugins may not read stored API keys or vault entries.",
    "raw_socket": "Raw packet access is not available to plugins.",
}


class PluginError(Exception):
    """Raised for any plugin problem, with a stable code."""

    def __init__(self, message: str, *, code: str = "kingdomx.plugin") -> None:
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


@dataclass
class PluginManifest:
    """A validated plugin manifest."""

    name: str
    version: str
    description: str
    author: str = ""
    entry: str = ENTRY_NAME
    permissions: list[str] = field(default_factory=list)
    kingdomx_min_version: str = "1.0.0"
    homepage: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "entry": self.entry,
            "permissions": list(self.permissions),
            "kingdomx_min_version": self.kingdomx_min_version,
            "homepage": self.homepage,
        }


@dataclass
class PluginRecord:
    """An installed plugin on disk."""

    manifest: PluginManifest
    path: Path
    installed_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.manifest.to_dict(),
            "path": str(self.path),
            "installed_at": self.installed_at,
            "entry_exists": (self.path / self.manifest.entry).is_file(),
        }


def _allowed_name(name: str) -> bool:
    if not name or len(name) > 48:
        return False
    return all(char.isalnum() or char in "-_." for char in name) and not name.startswith(".")


def validate_manifest(data: dict[str, Any]) -> PluginManifest:
    """Validate a manifest dict, raising :class:`PluginError` with the reason."""
    if not isinstance(data, dict):
        raise PluginError("manifest must be a JSON object", code="kingdomx.plugin.manifest")

    name = str(data.get("name") or "").strip()
    if not _allowed_name(name):
        raise PluginError(
            "manifest 'name' must be 1-48 characters of letters, digits, - _ or .",
            code="kingdomx.plugin.manifest",
        )

    version = str(data.get("version") or "").strip()
    if not version or not version[0].isdigit():
        raise PluginError(
            "manifest 'version' must start with a digit (e.g. 1.0.0)",
            code="kingdomx.plugin.manifest",
        )

    description = str(data.get("description") or "").strip()
    if len(description) < 8:
        raise PluginError(
            "manifest 'description' must be at least 8 characters",
            code="kingdomx.plugin.manifest",
        )

    entry = str(data.get("entry") or ENTRY_NAME).strip()
    if "/" in entry or "\\" in entry or entry.startswith("."):
        raise PluginError(
            "manifest 'entry' must be a plain filename inside the plugin directory",
            code="kingdomx.plugin.manifest",
        )
    if not entry.endswith(".py"):
        raise PluginError("manifest 'entry' must be a .py file", code="kingdomx.plugin.manifest")

    raw_permissions = data.get("permissions") or []
    if not isinstance(raw_permissions, list):
        raise PluginError(
            "manifest 'permissions' must be a list",
            code="kingdomx.plugin.manifest",
        )
    permissions: list[str] = []
    for permission in raw_permissions:
        text = str(permission).strip()
        if text in FORBIDDEN_PERMISSIONS:
            raise PluginError(
                f"permission '{text}' cannot be granted: {FORBIDDEN_PERMISSIONS[text]}",
                code="kingdomx.plugin.permission",
            )
        if text not in PERMISSIONS:
            raise PluginError(
                f"unknown permission '{text}'. Allowed: {', '.join(sorted(PERMISSIONS))}",
                code="kingdomx.plugin.permission",
            )
        if text not in permissions:
            permissions.append(text)

    return PluginManifest(
        name=name,
        version=version,
        description=description,
        author=str(data.get("author") or "")[:120],
        entry=entry,
        permissions=permissions,
        kingdomx_min_version=str(data.get("kingdomx_min_version") or "1.0.0"),
        homepage=str(data.get("homepage") or "")[:200],
    )


def read_manifest(directory: Path) -> PluginManifest:
    manifest_path = directory / MANIFEST_NAME
    if not manifest_path.is_file():
        raise PluginError(f"{MANIFEST_NAME} not found in {directory}", code="kingdomx.plugin.manifest")
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise PluginError("manifest is too large", code="kingdomx.plugin.manifest")
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PluginError(f"manifest is not valid JSON: {exc}", code="kingdomx.plugin.manifest") from exc
    return validate_manifest(data)


def plugin_root() -> Path:
    """Where installed plugins live."""
    base = Path(os.environ.get("KINGDOMX_HOME", Path.home() / ".kingdomx"))
    return base / "plugins"


def list_installed() -> list[PluginRecord]:
    root = plugin_root()
    if not root.is_dir():
        return []
    records: list[PluginRecord] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        try:
            manifest = read_manifest(entry)
        except PluginError:
            continue
        records.append(
            PluginRecord(
                manifest=manifest,
                path=entry,
                installed_at=entry.stat().st_mtime,
            )
        )
    return records


def install_plugin(source: str | Path) -> PluginRecord:
    """Copy a plugin directory into the plugin root after validation."""
    src = Path(source).expanduser().resolve()
    if not src.is_dir():
        raise PluginError(f"not a directory: {src}", code="kingdomx.plugin.install")

    manifest = read_manifest(src)
    if not (src / manifest.entry).is_file():
        raise PluginError(
            f"declared entry '{manifest.entry}' does not exist",
            code="kingdomx.plugin.install",
        )

    root = plugin_root()
    root.mkdir(parents=True, exist_ok=True)
    destination = root / manifest.name
    if destination.exists():
        raise PluginError(
            f"plugin '{manifest.name}' is already installed; remove it first",
            code="kingdomx.plugin.install",
        )

    shutil.copytree(src, destination)
    log.info("installed plugin %s v%s", manifest.name, manifest.version)
    return PluginRecord(manifest=manifest, path=destination, installed_at=time.time())


def remove_plugin(name: str) -> bool:
    root = plugin_root()
    target = root / name
    if not target.is_dir():
        return False
    # Refuse to escape the plugin root.
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise PluginError("refusing to remove a path outside the plugin root", code="kingdomx.plugin.remove") from exc
    shutil.rmtree(target)
    log.info("removed plugin %s", name)
    return True


def run_plugin(
    name: str,
    *,
    context: dict[str, Any] | None = None,
    timeout: float = RUN_TIMEOUT,
) -> dict[str, Any]:
    """Execute a plugin's ``run(context)`` in a subprocess with a timeout."""
    records = {record.manifest.name: record for record in list_installed()}
    record = records.get(name)
    if record is None:
        raise PluginError(f"plugin '{name}' is not installed", code="kingdomx.plugin.missing")

    entry = record.path / record.manifest.entry
    if not entry.is_file():
        raise PluginError(f"entry file missing for '{name}'", code="kingdomx.plugin.missing")

    payload = json.dumps(context or {})
    runner = f"""
import json, sys
sys.path.insert(0, {str(record.path)!r})
import importlib.util
spec = importlib.util.spec_from_file_location("kx_plugin", {str(entry)!r})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if not hasattr(module, "run"):
    print(json.dumps({{"ok": False, "error": "plugin has no run(context) function"}}))
    raise SystemExit(0)
result = module.run(json.loads(sys.argv[1]))
print(json.dumps({{"ok": True, "result": result}}, default=str))
"""

    started = time.perf_counter()
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell
            [sys.executable, "-c", runner, payload],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            cwd=str(record.path),
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "LANG": "C",
                "KINGDOMX_PLUGIN": record.manifest.name,
                "KINGDOMX_PERMISSIONS": ",".join(record.manifest.permissions),
            },
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "plugin": name,
            "error": f"plugin exceeded the {timeout:.0f}s timeout and was terminated",
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except OSError as exc:
        return {"ok": False, "plugin": name, "error": str(exc)}

    elapsed = round((time.perf_counter() - started) * 1000, 1)
    stdout = (completed.stdout or "").strip()
    last_line = stdout.splitlines()[-1] if stdout else ""

    if completed.returncode != 0:
        return {
            "ok": False,
            "plugin": name,
            "error": f"plugin exited with {completed.returncode}",
            "stderr": (completed.stderr or "")[:800],
            "elapsed_ms": elapsed,
        }

    try:
        parsed = json.loads(last_line)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "plugin": name,
            "error": "plugin produced no parsable JSON result",
            "stdout": stdout[:800],
            "elapsed_ms": elapsed,
        }

    return {"plugin": name, "elapsed_ms": elapsed, **parsed}


def plugin_permissions() -> dict[str, str]:
    return dict(PERMISSIONS)


def reference_plugin() -> dict[str, Any]:
    """A minimal, valid plugin — used by the docs and the tests."""
    return {
        "manifest": {
            "name": "example-hello",
            "version": "1.0.0",
            "description": "Minimal reference plugin that echoes its context.",
            "author": "KINGDOM X",
            "entry": "plugin.py",
            "permissions": [],
        },
        "source": (
            '"""Reference KINGDOM X plugin."""\n\n'
            "def run(context):\n"
            '    return {"message": "hello from the reference plugin", "received_keys": sorted(context)}\n'
        ),
    }
