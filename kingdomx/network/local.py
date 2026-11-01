"""Local network state: sockets, routes, interfaces, ARP.

All read-only. ``psutil`` is used when present; ``ss``/``ip`` and ``/proc`` are the
fallbacks, and every result records which one answered.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kingdomx.core.logging_setup import get_logger
from kingdomx.core.platform_detect import current as current_platform
from kingdomx.cybersecurity.ports import KNOWN_PORTS, risk_for, service_for

log = get_logger("network.local")

COMMAND_TIMEOUT = 5.0
SAFE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}


def _run(argv: list[str], *, timeout: float = COMMAND_TIMEOUT) -> tuple[int, str]:
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env=SAFE_ENV,
        )
    except (subprocess.TimeoutExpired, OSError):
        return 127, ""
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


def psutil_available() -> bool:
    try:
        import psutil  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


def listening_ports() -> dict[str, Any]:
    """Which ports this machine is listening on."""
    if psutil_available():
        import psutil

        rows: list[dict[str, Any]] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            connections = []
            note = "psutil could not read the socket table without root; falling back."
        else:
            note = None

        for conn in connections:
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue
            port = conn.laddr.port
            process_name = ""
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = ""
            rows.append(
                {
                    "protocol": "tcp" if conn.type == 1 else "udp",
                    "address": conn.laddr.ip,
                    "port": port,
                    "service": service_for(port),
                    "risk": risk_for(port),
                    "process": process_name,
                    "pid": conn.pid,
                    "exposed": conn.laddr.ip in {"0.0.0.0", "::"},
                }
            )
        if rows or note is None:
            return {
                "backend": "psutil",
                "listeners": sorted(rows, key=lambda row: (row["port"], row["address"])),
                "count": len(rows),
                "note": note,
            }

    code, output = _run(["ss", "-lntu"])
    backend = "ss"
    if code != 0:
        code, output = _run(["netstat", "-lntu"])
        backend = "netstat"
    if code != 0:
        return {
            "backend": None,
            "listeners": [],
            "count": 0,
            "note": "No socket table readable: psutil unavailable, ss and netstat both failed.",
        }

    rows = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].lower() in {"netid", "active"}:
            continue
        protocol = parts[0].lower()
        if protocol not in {"tcp", "udp", "tcp6", "udp6"}:
            continue
        local = parts[4] if protocol.startswith("tcp") else parts[3]
        address, _, port_text = local.rpartition(":")
        port_text = port_text.strip()
        if not port_text.isdigit():
            continue
        port = int(port_text)
        rows.append(
            {
                "protocol": "tcp" if protocol.startswith("tcp") else "udp",
                "address": address.strip("[]") or "*",
                "port": port,
                "service": service_for(port),
                "risk": risk_for(port),
                "process": "",
                "pid": None,
                "exposed": address.strip("[]") in {"0.0.0.0", "*", "::"},
            }
        )
    return {
        "backend": backend,
        "listeners": sorted(rows, key=lambda row: (row["port"], row["address"])),
        "count": len(rows),
        "note": "Process names require root; only addresses and ports are shown.",
    }


def connections(*, limit: int = 100, established_only: bool = False) -> dict[str, Any]:
    """Current socket table (inbound and outbound)."""
    if not psutil_available():
        return {
            "backend": None,
            "connections": [],
            "note": "psutil is required for a connection table with process attribution.",
        }
    import psutil

    rows: list[dict[str, Any]] = []
    try:
        table = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return {
            "backend": "psutil",
            "connections": [],
            "note": "access denied — run with sudo for the full table",
        }

    for conn in table:
        status = conn.status
        if established_only and status != psutil.CONN_ESTABLISHED:
            continue
        rows.append(
            {
                "protocol": "tcp" if conn.type == 1 else "udp",
                "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                "status": status,
                "pid": conn.pid,
            }
        )
        if len(rows) >= limit:
            break
    return {"backend": "psutil", "connections": rows, "count": len(rows)}


def routes() -> dict[str, Any]:
    """The routing table."""
    code, output = _run(["ip", "route", "show"])
    if code == 0 and output.strip():
        rows = []
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            entry: dict[str, Any] = {"raw": line.strip()}
            if parts[0] == "default":
                entry["destination"] = "default"
                if "via" in parts:
                    entry["gateway"] = parts[parts.index("via") + 1]
                if "dev" in parts:
                    entry["interface"] = parts[parts.index("dev") + 1]
            else:
                entry["destination"] = parts[0]
                if "via" in parts:
                    entry["gateway"] = parts[parts.index("via") + 1]
                if "dev" in parts:
                    entry["interface"] = parts[parts.index("dev") + 1]
            rows.append(entry)
        return {"backend": "ip route", "routes": rows, "count": len(rows)}

    proc = Path("/proc/net/route")
    if proc.is_file():
        rows = []
        for line in proc.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 8:
                continue
            def dotted(hex_value: str) -> str:
                raw = int(hex_value, 16).to_bytes(4, "little")
                return ".".join(str(byte) for byte in raw)

            rows.append(
                {
                    "interface": parts[0],
                    "destination": dotted(parts[1]),
                    "gateway": dotted(parts[2]),
                    "flags": parts[3],
                }
            )
        return {"backend": "/proc/net/route", "routes": rows, "count": len(rows)}

    return {"backend": None, "routes": [], "note": "no routing information source available"}


def interface_table() -> dict[str, Any]:
    """Interface addresses with up/down state."""
    if psutil_available():
        import psutil

        stats = psutil.net_if_stats()
        rows = []
        for name, entries in psutil.net_if_addrs().items():
            stat = stats.get(name)
            for entry in entries:
                if entry.family not in {2, 10}:  # AF_INET, AF_INET6
                    continue
                rows.append(
                    {
                        "interface": name,
                        "family": "IPv4" if entry.family == 2 else "IPv6",
                        "address": entry.address.split("%")[0],
                        "netmask": entry.netmask,
                        "up": bool(stat.isup) if stat else None,
                        "speed_mbps": stat.speed if stat else None,
                    }
                )
        return {"backend": "psutil", "interfaces": rows, "count": len(rows)}

    code, output = _run(["ip", "-o", "addr", "show"])
    if code != 0:
        return {"backend": None, "interfaces": [], "note": "no interface information source"}
    rows = []
    for line in output.splitlines():
        match = re.match(r"\d+:\s+(\S+)\s+inet6?\s+(\S+)", line)
        if match:
            rows.append(
                {
                    "interface": match.group(1),
                    "family": "IPv6" if "inet6" in line.split()[2] else "IPv4",
                    "address": match.group(2).split("/")[0],
                    "netmask": match.group(2).split("/")[1] if "/" in match.group(2) else None,
                    "up": "UP" in line,
                    "speed_mbps": None,
                }
            )
    return {"backend": "ip addr", "interfaces": rows, "count": len(rows)}


def arp_table() -> dict[str, Any]:
    """Neighbours this host has spoken to recently (the ARP/NDP cache)."""
    code, output = _run(["ip", "neigh", "show"])
    if code == 0 and output.strip():
        rows = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            entry = {"ip": parts[0], "interface": parts[2] if len(parts) > 2 else ""}
            if "lladdr" in parts:
                index = parts.index("lladdr")
                if index + 1 < len(parts):
                    entry["mac"] = parts[index + 1]
            entry["state"] = parts[-1]
            rows.append(entry)
        return {
            "backend": "ip neigh",
            "entries": rows,
            "count": len(rows),
            "note": "This is the local cache only — not a scan of the network.",
        }

    proc = Path("/proc/net/arp")
    if proc.is_file():
        rows = []
        for line in proc.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                rows.append(
                    {
                        "ip": parts[0],
                        "mac": parts[3],
                        "interface": parts[5] if len(parts) > 5 else "",
                        "state": "reachable" if parts[2] != "0x0" else "incomplete",
                    }
                )
        return {"backend": "/proc/net/arp", "entries": rows, "count": len(rows)}

    return {"backend": None, "entries": [], "note": "no ARP cache readable"}


@dataclass
class BandwidthSample:
    bytes_sent: int
    bytes_recv: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "timestamp": self.timestamp,
        }


def bandwidth(*, interval: float = 1.0) -> dict[str, Any]:
    """Measure throughput over ``interval`` seconds."""
    if not psutil_available():
        return {
            "ok": False,
            "error": "psutil is required for bandwidth sampling",
            "note": "Install it with `pip install psutil`.",
        }
    import psutil

    first = psutil.net_io_counters()
    time.sleep(max(0.2, interval))
    second = psutil.net_io_counters()

    sent = second.bytes_sent - first.bytes_sent
    recv = second.bytes_recv - first.bytes_recv
    return {
        "ok": True,
        "interval_seconds": interval,
        "sent_bytes": sent,
        "recv_bytes": recv,
        "sent_per_second": round(sent / interval, 1),
        "recv_per_second": round(recv / interval, 1),
        "sent_human": human_bytes(sent / interval) + "/s",
        "recv_human": human_bytes(recv / interval) + "/s",
        "totals": {
            "sent": second.bytes_sent,
            "recv": second.bytes_recv,
            "packets_sent": second.packets_sent,
            "packets_recv": second.packets_recv,
        },
    }


def human_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def network_summary() -> dict[str, Any]:
    """Everything the network menu shows at a glance."""
    plat = current_platform()
    return {
        "platform": plat.label,
        "psutil": psutil_available(),
        "has_ss": shutil.which("ss") is not None,
        "has_ip": shutil.which("ip") is not None,
        "listening": listening_ports()["count"],
        "interfaces": interface_table()["count"],
        "arp_entries": arp_table()["count"],
        "dangerous_listeners": [
            listener
            for listener in listening_ports()["listeners"]
            if listener["risk"] in {"critical", "high"}
        ],
    }


def explain_listener(port: int) -> str:
    """Explain why a listening port matters."""
    info = KNOWN_PORTS.get(int(port))
    if not info:
        return f"Port {port}: not in the knowledge base; check IANA for the assignment."
    lines = [
        f"{port}/{info.transport} {info.service}",
        info.description,
        f"Risk if exposed: {info.risk.upper()}",
    ]
    if info.risk in {"critical", "high"}:
        lines.append("Bind it to 127.0.0.1 or firewall it.")
    return "\n".join(lines)
