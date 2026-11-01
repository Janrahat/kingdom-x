"""Local system diagnostics.

psutil gives portable numbers when installed; the ``/proc`` readers are the
fallback and are also what Android/Termux exposes. Every field records whether it
came from psutil, /proc, or a platform call, because on Termux some of them are
genuinely unavailable.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kingdomx.core.logging_setup import get_logger
from kingdomx.core.platform_detect import current as current_platform

log = get_logger("computers.system")

COMMAND_TIMEOUT = 5.0


# --------------------------------------------------------------------------- /proc
def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _meminfo() -> dict[str, int]:
    text = _read("/proc/meminfo")
    if not text:
        return {}
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.strip().split()
        if len(parts) >= 2 and parts[1].lower().startswith("kb"):
            try:
                values[key.strip()] = int(parts[0]) * 1024
            except ValueError:
                continue
        elif parts:
            try:
                values[key.strip()] = int(parts[0])
            except ValueError:
                continue
    return values


def _cpuinfo() -> dict[str, Any]:
    text = _read("/proc/cpuinfo")
    if not text:
        return {}
    model = ""
    count = 0
    mhz: float | None = None
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in {"model name", "hardware", "processor", "cpu model"}:
            if value and not model:
                model = value
            if key == "processor":
                count += 1
        elif key in {"cpu mhz", "bogomips"} and mhz is None:
            try:
                mhz = float(value)
            except ValueError:
                pass
    cores = os.cpu_count() or count or None
    return {"model": model or platform.processor() or "unknown", "cores": cores, "mhz": mhz}


def _uptime() -> float | None:
    text = _read("/proc/uptime")
    if not text:
        return None
    try:
        return float(text.split()[0])
    except (ValueError, IndexError):
        return None


def _loadavg() -> tuple[float, float, float] | None:
    try:
        return os.getloadavg()
    except (OSError, AttributeError):
        return None


# --------------------------------------------------------------------------- public
@dataclass
class SystemSnapshot:
    """A point-in-time description of this machine."""

    hostname: str
    platform_label: str
    platform_family: str
    os_name: str
    os_release: str
    os_version: str
    architecture: str
    kernel: str
    is_termux: bool
    is_root: bool
    python_version: str
    cpu_model: str = ""
    cpu_cores: int | None = None
    cpu_mhz: float | None = None
    memory_total: int = 0
    memory_available: int = 0
    swap_total: int = 0
    uptime_seconds: float | None = None
    loadavg: tuple[float, float, float] | None = None
    primary_ip: str | None = None
    sources: dict[str, str] = field(default_factory=dict)

    @property
    def memory_used(self) -> int:
        return max(0, self.memory_total - self.memory_available)

    @property
    def memory_percent(self) -> float:
        if not self.memory_total:
            return 0.0
        return round(self.memory_used / self.memory_total * 100, 1)

    @property
    def uptime_human(self) -> str:
        if self.uptime_seconds is None:
            return "unknown"
        total = int(self.uptime_seconds)
        days, remainder = divmod(total, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes = remainder // 60
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        parts.append(f"{minutes}m")
        return " ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "platform": {
                "label": self.platform_label,
                "family": self.platform_family,
                "is_termux": self.is_termux,
                "is_root": self.is_root,
            },
            "os": {
                "name": self.os_name,
                "release": self.os_release,
                "version": self.os_version,
                "architecture": self.architecture,
                "kernel": self.kernel,
            },
            "python": self.python_version,
            "cpu": {
                "model": self.cpu_model,
                "cores": self.cpu_cores,
                "mhz": self.cpu_mhz,
            },
            "memory": {
                "total": self.memory_total,
                "available": self.memory_available,
                "used": self.memory_used,
                "percent": self.memory_percent,
                "swap_total": self.swap_total,
            },
            "uptime_seconds": self.uptime_seconds,
            "uptime_human": self.uptime_human,
            "loadavg": list(self.loadavg) if self.loadavg else None,
            "primary_ip": self.primary_ip,
            "sources": dict(self.sources),
        }


def kernel_info() -> dict[str, str]:
    """``uname``-style values plus the distro pretty-name when available."""
    data = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "python": platform.python_version(),
        "distro": "",
    }
    try:
        import distro  # type: ignore[import-not-found]

        data["distro"] = distro.name(pretty=True)
    except ModuleNotFoundError:
        release = _read("/etc/os-release") or ""
        for line in release.splitlines():
            if line.startswith("PRETTY_NAME="):
                data["distro"] = line.split("=", 1)[1].strip().strip('"')
                break
    return data


def collect() -> SystemSnapshot:
    """Read this machine's current state."""
    plat = current_platform()
    uname = kernel_info()
    cpu = _cpuinfo()
    mem = _meminfo()
    load = _loadavg()

    snapshot = SystemSnapshot(
        hostname=socket.gethostname() or "unknown",
        platform_label=plat.label,
        platform_family=plat.family,
        os_name=uname.get("distro") or uname.get("system", "unknown"),
        os_release=uname.get("release", ""),
        os_version=uname.get("version", ""),
        architecture=uname.get("machine", ""),
        kernel=uname.get("release", ""),
        is_termux=plat.is_termux,
        is_root=plat.is_root,
        python_version=platform.python_version(),
        cpu_model=cpu.get("model", ""),
        cpu_cores=cpu.get("cores"),
        cpu_mhz=cpu.get("mhz"),
        memory_total=mem.get("MemTotal", 0),
        memory_available=mem.get("MemAvailable", mem.get("MemFree", 0)),
        swap_total=mem.get("SwapTotal", 0),
        uptime_seconds=_uptime(),
        loadavg=load,
        primary_ip=_primary_ip(),
    )
    snapshot.sources = {
        "cpu": "/proc/cpuinfo" if _read("/proc/cpuinfo") else "platform",
        "memory": "/proc/meminfo" if mem else "unavailable",
        "uptime": "/proc/uptime" if snapshot.uptime_seconds is not None else "unavailable",
        "loadavg": "os.getloadavg" if load else "unavailable",
    }
    return snapshot


def _primary_ip() -> str | None:
    """The address used for outbound traffic — no packet is actually sent."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.connect(("1.1.1.1", 53))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        if sock is not None:
            sock.close()


def disk_usage(paths: list[str] | None = None) -> list[dict[str, Any]]:
    """Filesystem usage for the interesting mount points."""
    candidates = paths or ["/", "/home", "/var", "/tmp", str(Path.home())]
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for candidate in candidates:
        target = Path(candidate)
        try:
            resolved = str(target.resolve())
        except OSError:
            continue
        if resolved in seen or not target.exists():
            continue
        seen.add(resolved)
        try:
            usage = shutil.disk_usage(resolved)
        except OSError:
            continue
        out.append(
            {
                "mount": resolved,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": round(usage.used / usage.total * 100, 1) if usage.total else 0.0,
                "warning": usage.used / usage.total >= 0.9 if usage.total else False,
            }
        )
    return out


def processes(*, limit: int = 25, sort_by: str = "memory") -> list[dict[str, Any]]:
    """Top processes by memory or CPU."""
    try:
        import psutil
    except ModuleNotFoundError:
        return _processes_proc(limit=limit)

    rows: list[dict[str, Any]] = []
    for proc in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_percent", "status", "create_time"]
    ):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        rows.append(
            {
                "pid": info.get("pid"),
                "name": info.get("name"),
                "user": info.get("username"),
                "cpu_percent": round(float(info.get("cpu_percent") or 0.0), 1),
                "memory_percent": round(float(info.get("memory_percent") or 0.0), 1),
                "status": info.get("status"),
            }
        )
    key = "memory_percent" if sort_by == "memory" else "cpu_percent"
    return sorted(rows, key=lambda row: -(row.get(key) or 0.0))[:limit]


def _processes_proc(*, limit: int) -> list[dict[str, Any]]:
    """Fallback: read /proc/*/stat for RSS."""
    page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
    rows: list[dict[str, Any]] = []
    for entry in Path("/proc").iterdir() if Path("/proc").is_dir() else []:
        if not entry.name.isdigit():
            continue
        stat = _read(str(entry / "stat"))
        comm = _read(str(entry / "comm"))
        if not stat:
            continue
        fields = stat.rsplit(")", 1)
        if len(fields) != 2:
            continue
        values = fields[1].split()
        try:
            rss = int(values[21]) * page_size
        except (IndexError, ValueError):
            continue
        rows.append(
            {
                "pid": int(entry.name),
                "name": (comm or "?").strip(),
                "user": None,
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "rss_bytes": rss,
                "status": values[0] if values else None,
            }
        )
    return sorted(rows, key=lambda row: -row.get("rss_bytes", 0))[:limit]


def services(*, limit: int = 40) -> list[dict[str, Any]]:
    """systemd units, if this system uses systemd."""
    code = subprocess.run(  # noqa: S603 - fixed argv
        ["systemctl", "list-units", "--type=service", "--no-pager", "--no-legend", "--all"],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=COMMAND_TIMEOUT,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
    )
    if code.returncode != 0:
        plat = current_platform()
        reason = (
            "Termux has no systemd; use `termux-services` or `ps` instead."
            if plat.is_termux
            else "systemd is not available on this system."
        )
        return [{"note": reason, "available": False}]

    rows: list[dict[str, Any]] = []
    for line in code.stdout.splitlines()[:limit]:
        parts = line.split()
        if len(parts) < 4:
            continue
        rows.append(
            {
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "state": parts[3],
                "description": " ".join(parts[4:])[:120],
                "available": True,
            }
        )
    return rows


def installed_packages(*, limit: int = 5000) -> dict[str, Any]:
    """Installed package inventory, from whichever manager exists."""
    plat = current_platform()
    if plat.is_termux and shutil.which("pkg"):
        code = subprocess.run(  # noqa: S603 - fixed argv
            ["pkg", "list-installed"],
            capture_output=True, text=True, errors="replace",
            timeout=20, check=False,
            env={"PATH": "/data/data/com.termux/files/usr/bin:/usr/bin:/bin", "LANG": "C"},
        )
        if code.returncode == 0:
            names = [
                line.split("/")[0].strip()
                for line in code.stdout.splitlines()
                if "/" in line
            ]
            return {"manager": "pkg (Termux)", "count": len(names), "packages": names[:limit]}

    if shutil.which("dpkg-query"):
        code = subprocess.run(  # noqa: S603 - fixed argv
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            capture_output=True, text=True, errors="replace",
            timeout=25, check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        if code.returncode == 0:
            packages = []
            for line in code.stdout.splitlines():
                if "\t" in line:
                    name, _, version = line.partition("\t")
                    packages.append({"name": name, "version": version})
            return {
                "manager": "dpkg",
                "count": len(packages),
                "packages": packages[:limit],
            }

    if shutil.which("rpm"):
        code = subprocess.run(  # noqa: S603 - fixed argv
            ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"],
            capture_output=True, text=True, errors="replace",
            timeout=25, check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        if code.returncode == 0:
            packages = [
                {"name": line.split("\t")[0], "version": line.split("\t")[1]}
                for line in code.stdout.splitlines()
                if "\t" in line
            ]
            return {"manager": "rpm", "count": len(packages), "packages": packages[:limit]}

    return {
        "manager": None,
        "count": 0,
        "packages": [],
        "note": "No supported package manager found (pkg, dpkg, rpm).",
    }


def health_report() -> dict[str, Any]:
    """A compact health summary with real thresholds."""
    snapshot = collect()
    disks = disk_usage()
    issues: list[dict[str, Any]] = []

    if snapshot.memory_percent >= 90:
        issues.append(
            {
                "level": "high",
                "area": "memory",
                "detail": f"{snapshot.memory_percent}% of RAM in use",
                "advice": "Find the top consumer; the OOM killer will start terminating processes.",
            }
        )
    elif snapshot.memory_percent >= 75:
        issues.append(
            {
                "level": "medium",
                "area": "memory",
                "detail": f"{snapshot.memory_percent}% of RAM in use",
                "advice": "Watch the trend; add swap or reduce concurrent work.",
            }
        )

    for disk in disks:
        if disk["percent"] >= 90:
            issues.append(
                {
                    "level": "critical",
                    "area": "storage",
                    "detail": f"{disk['mount']} is {disk['percent']}% full",
                    "advice": "Free space now; writes are close to failing.",
                }
            )
        elif disk["percent"] >= 80:
            issues.append(
                {
                    "level": "medium",
                    "area": "storage",
                    "detail": f"{disk['mount']} is {disk['percent']}% full",
                    "advice": "Rotate logs and clear caches.",
                }
            )

    if snapshot.loadavg and snapshot.cpu_cores:
        one_minute = snapshot.loadavg[0]
        if one_minute > snapshot.cpu_cores * 1.5:
            issues.append(
                {
                    "level": "high",
                    "area": "cpu",
                    "detail": f"load average {one_minute:.2f} on {snapshot.cpu_cores} core(s)",
                    "advice": "The machine is oversubscribed; find the runaway process.",
                }
            )

    return {
        "snapshot": snapshot.to_dict(),
        "disks": disks,
        "issues": issues,
        "verdict": (
            "CRITICAL"
            if any(issue["level"] == "critical" for issue in issues)
            else "DEGRADED"
            if any(issue["level"] == "high" for issue in issues)
            else "ATTENTION"
            if issues
            else "HEALTHY"
        ),
        "note": "Thresholds are fixed local heuristics, not a monitoring service.",
    }
