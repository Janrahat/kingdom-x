"""Platform detection for Kali Linux, Termux, generic Linux, macOS and Windows.

Nothing here is guessed from a marketing name: each classification is based on a
real filesystem or environment signal, and every result records which signals
produced it so an operator can audit the conclusion.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

TERMUX_PREFIX = "/data/data/com.termux/files/usr"


@dataclass(frozen=True)
class PlatformInfo:
    """A detected runtime environment."""

    system: str
    """``linux``, ``darwin`` or ``windows``."""

    family: str
    """``kali``, ``termux``, ``parrot``, ``debian``, ``ubuntu``, ``linux``,
    ``macos`` or ``windows``."""

    distro_id: str
    distro_name: str
    version: str
    kernel: str
    arch: str
    is_termux: bool
    is_root: bool
    is_wsl: bool
    python: str
    signals: tuple[str, ...] = field(default_factory=tuple)
    has_systemd: bool = False
    has_sudo: bool = False

    @property
    def is_android(self) -> bool:
        return self.is_termux

    @property
    def is_linux(self) -> bool:
        return self.system == "linux"

    @property
    def is_kali(self) -> bool:
        return self.family == "kali"

    @property
    def label(self) -> str:
        names = {
            "kali": "Kali Linux",
            "termux": "Termux (Android)",
            "parrot": "Parrot OS",
            "debian": "Debian",
            "ubuntu": "Ubuntu",
            "linux": "Linux",
            "macos": "macOS",
            "windows": "Windows",
        }
        return names.get(self.family, self.family.title())

    @property
    def root_note(self) -> str:
        if self.is_termux:
            return "Root is unavailable in Termux; every core feature runs unprivileged."
        if self.is_root:
            return "Running as root — prefer sudo only for operations that need it."
        return "Running unprivileged — normal features work; some scans need sudo."

    def to_dict(self) -> dict:
        return {
            "system": self.system,
            "family": self.family,
            "label": self.label,
            "distro_id": self.distro_id,
            "distro_name": self.distro_name,
            "version": self.version,
            "kernel": self.kernel,
            "arch": self.arch,
            "is_termux": self.is_termux,
            "is_kali": self.is_kali,
            "is_root": self.is_root,
            "is_wsl": self.is_wsl,
            "python": self.python,
            "has_systemd": self.has_systemd,
            "has_sudo": self.has_sudo,
            "signals": list(self.signals),
            "root_note": self.root_note,
        }


def _read_os_release() -> dict[str, str]:
    """Parse /etc/os-release without invoking a shell."""
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        path = Path(candidate)
        try:
            if not path.is_file():
                continue
            data: dict[str, str] = {}
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                data[key.strip()] = value.strip().strip("\"'")
            if data:
                return data
        except OSError:
            continue
    return {}


def _is_wsl() -> bool:
    try:
        text = Path("/proc/version").read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False
    return "microsoft" in text or "wsl" in text


def detect_termux() -> tuple[bool, tuple[str, ...]]:
    """Termux detection from four independent signals."""
    signals: list[str] = []
    if os.environ.get("PREFIX", "").startswith(TERMUX_PREFIX):
        signals.append("env:PREFIX=/data/data/com.termux")
    if os.environ.get("TERMUX_VERSION"):
        signals.append("env:TERMUX_VERSION")
    if Path(TERMUX_PREFIX, "bin").is_dir():
        signals.append("path:/data/data/com.termux/files/usr/bin")
    if Path("/system/build.prop").is_file():
        signals.append("path:/system/build.prop")
    return (len(signals) >= 1, tuple(signals))


def detect_platform() -> PlatformInfo:
    """Classify the current environment from real signals."""
    system = platform.system().lower()
    if system.startswith(("cygwin", "msys")):
        system = "windows"
    kernel = platform.release()
    arch = platform.machine() or "unknown"

    signals: list[str] = []
    on_termux, termux_signals = detect_termux()
    signals.extend(termux_signals)

    osr = _read_os_release() if system == "linux" else {}
    distro_id = (osr.get("ID") or "").lower()
    distro_name = osr.get("PRETTY_NAME") or osr.get("NAME") or platform.platform()
    version = osr.get("VERSION_ID") or osr.get("VERSION") or ""

    if on_termux:
        family = "termux"
        distro_id = distro_id or "termux"
        distro_name = "Termux " + os.environ.get("TERMUX_VERSION", "")
        distro_name = distro_name.strip()
        version = os.environ.get("TERMUX_VERSION", "") or version
        signals.append("classifier:termux")
    elif system == "linux":
        if distro_id == "kali":
            family = "kali"
            signals.append("os-release:ID=kali")
        elif distro_id == "parrot":
            family = "parrot"
            signals.append("os-release:ID=parrot")
        elif distro_id == "debian":
            family = "debian"
            signals.append("os-release:ID=debian")
        elif distro_id in {"ubuntu", "linuxmint", "pop"}:
            family = "ubuntu"
            signals.append(f"os-release:ID={distro_id}")
        else:
            family = "linux"
            signals.append(f"os-release:ID={distro_id or 'unknown'}")
        if _is_wsl():
            signals.append("proc:/proc/version contains microsoft")
    elif system == "darwin":
        family = "macos"
        signals.append("platform.system()=Darwin")
    elif system == "windows":
        family = "windows"
        signals.append("platform.system()=Windows")
    else:
        family = "linux"
        signals.append(f"platform.system()={platform.system()}")

    is_root = bool(hasattr(os, "geteuid") and os.geteuid() == 0)
    if is_root:
        signals.append("os.geteuid()==0")

    return PlatformInfo(
        system=system,
        family=family,
        distro_id=distro_id or system,
        distro_name=distro_name,
        version=str(version),
        kernel=kernel,
        arch=arch,
        is_termux=on_termux,
        is_root=is_root,
        is_wsl=_is_wsl() if system == "linux" else False,
        python=platform.python_version(),
        signals=tuple(signals),
        has_systemd=Path("/run/systemd/system").is_dir(),
        has_sudo=shutil.which("sudo") is not None and not on_termux,
    )


@lru_cache(maxsize=1)
def current() -> PlatformInfo:
    """Cached detection for the running process."""
    return detect_platform()


def refresh() -> PlatformInfo:
    """Re-detect, bypassing the cache (used by diagnostics and tests)."""
    current.cache_clear()
    return current()


def python_ok(minimum: tuple[int, int] = (3, 10)) -> bool:
    return sys.version_info[:2] >= minimum


def which_any(*names: str) -> str | None:
    """First executable found on PATH, or None."""
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def is_offline_env() -> bool:
    """True when the operator explicitly set KINGDOMX_OFFLINE."""
    return os.environ.get("KINGDOMX_OFFLINE", "").strip().lower() in {"1", "true", "yes", "on"}
