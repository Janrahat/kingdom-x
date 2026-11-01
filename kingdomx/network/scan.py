"""Authorized active scanning.

This is the only place in KINGDOM X that touches a remote host actively. Three
gates must all pass before a single packet is sent:

1. :func:`kingdomx.core.authorization.require_authorization` — the operator must
   have recorded a written authorization for the exact target.
2. The target must be a private/loopback address *unless* the authorization
   explicitly recorded a public target.
3. The scan must be an allow-listed preset — never an arbitrary command line.

Reading nmap's XML output is separated from running nmap so it can be tested
without touching the network.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree

from kingdomx.core.authorization import require_authorization
from kingdomx.core.errors import AuthorizationError, UnsafeTargetError, ValidationError
from kingdomx.core.logging_setup import get_logger
from kingdomx.core.validation import validate_host
from kingdomx.cybersecurity.ports import COMMON_PORTS, risk_for, service_for

log = get_logger("network.scan")

SCAN_TIMEOUT = 600.0

#: Allow-listed scan profiles. No profile accepts free-form extra arguments.
PROFILES: dict[str, dict[str, Any]] = {
    "top-ports": {
        "args": ["-sT", "-Pn", "--top-ports", "100", "-T4"],
        "description": "TCP connect scan of the 100 most common ports. No root needed.",
    },
    "service": {
        "args": ["-sT", "-Pn", "-sV", "--version-light", "-T4", "--top-ports", "100"],
        "description": "TCP connect plus light service/version detection.",
    },
    "quick-common": {
        "args": ["-sT", "-Pn", "-T4", "-p", ",".join(str(p) for p in COMMON_PORTS)],
        "description": "TCP connect against the curated common-port list.",
    },
}


@dataclass
class DiscoveredPort:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    risk: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "risk": self.risk,
        }


@dataclass
class ScanResult:
    target: str
    profile: str
    ok: bool
    ports: list[DiscoveredPort] = field(default_factory=list)
    host_up: bool | None = None
    hostname: str = ""
    elapsed_seconds: float | None = None
    command: str = ""
    error: str | None = None
    backend: str = "nmap"
    raw_xml_bytes: int = 0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "profile": self.profile,
            "ok": self.ok,
            "host_up": self.host_up,
            "hostname": self.hostname,
            "open_ports": [p.to_dict() for p in self.ports],
            "open_count": len(self.ports),
            "elapsed_seconds": self.elapsed_seconds,
            "command": self.command,
            "error": self.error,
            "backend": self.backend,
            "note": self.note,
        }

    @property
    def dangerous(self) -> list[DiscoveredPort]:
        return [p for p in self.ports if p.risk in {"critical", "high"}]


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def parse_nmap_output(xml_text: str) -> ScanResult:
    """Parse ``nmap -oX`` output. Separated from execution so it is testable."""
    result = ScanResult(target="", profile="", ok=False, raw_xml_bytes=len(xml_text))
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        result.error = f"could not parse nmap XML: {exc}"
        return result

    runstats = root.find("runstats/finished")
    if runstats is not None:
        try:
            result.elapsed_seconds = float(runstats.get("elapsed", "0"))
        except ValueError:
            result.elapsed_seconds = None

    host = root.find("host")
    if host is None:
        result.ok = True
        result.note = "No host element in the output — the target did not respond."
        return result

    status = host.find("status")
    if status is not None:
        result.host_up = status.get("state") == "up"

    hostname = host.find("hostnames/hostname")
    if hostname is not None:
        result.hostname = hostname.get("name", "")

    address = host.find("address")
    if address is not None:
        result.target = address.get("addr", "")

    for port_element in host.findall("ports/port"):
        port_id = port_element.get("portid")
        protocol = port_element.get("protocol", "tcp")
        state_element = port_element.find("state")
        state = state_element.get("state", "unknown") if state_element is not None else "unknown"
        service_element = port_element.find("service")
        service = service_element.get("name", "") if service_element is not None else ""
        product = service_element.get("product", "") if service_element is not None else ""
        version = service_element.get("version", "") if service_element is not None else ""
        if not service and port_id and port_id.isdigit():
            service = service_for(int(port_id))
        result.ports.append(
            DiscoveredPort(
                port=int(port_id) if port_id and port_id.isdigit() else 0,
                protocol=protocol,
                state=state,
                service=service,
                product=product,
                version=version,
                risk=risk_for(int(port_id)) if port_id and port_id.isdigit() else "low",
            )
        )

    result.ports = [p for p in result.ports if p.state == "open"]
    result.ports.sort(key=lambda p: p.port)
    result.ok = True
    return result


def authorize_and_scan(
    target: str,
    *,
    profile: str = "top-ports",
    operator: str = "operator",
) -> ScanResult:
    """Run one allow-listed nmap profile against an authorized target."""
    check = validate_host(target)
    if not check.ok:
        raise ValidationError(f"invalid target: {check.reason}")
    clean = (check.normalised or target).split(":")[0]

    if profile not in PROFILES:
        raise ValidationError(
            f"unknown profile '{profile}'",
            detail="available: " + ", ".join(sorted(PROFILES)),
        )

    # Gate 1 + 2: written authorization for this exact target.
    require_authorization(clean, action="port-scan", operator=operator)

    if not nmap_available():
        return ScanResult(
            target=clean,
            profile=profile,
            ok=False,
            error="nmap is not installed",
            backend="unavailable",
            note=_install_hint(),
        )

    argv = ["nmap", *PROFILES[profile]["args"], "-oX", "-", clean]
    command = " ".join(argv)
    log.info("authorized scan profile=%s target=%s", profile, clean)

    try:
        completed = subprocess.run(  # noqa: S603 - argv list from an allow-list, no shell
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=SCAN_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ScanResult(
            target=clean,
            profile=profile,
            ok=False,
            error=f"scan timed out after {SCAN_TIMEOUT:.0f}s",
            command=command,
            note="Narrow the port range or increase SCAN_TIMEOUT.",
        )
    except OSError as exc:
        return ScanResult(
            target=clean, profile=profile, ok=False, error=str(exc), command=command
        )

    if completed.returncode not in {0, 1}:
        return ScanResult(
            target=clean,
            profile=profile,
            ok=False,
            error=f"nmap exited with {completed.returncode}",
            command=command,
            note=(completed.stderr or "")[:300],
        )

    parsed = parse_nmap_output(completed.stdout or "")
    parsed.target = parsed.target or clean
    parsed.profile = profile
    parsed.command = command
    if not parsed.ok:
        parsed.error = parsed.error or "nmap produced no parsable output"
    return parsed


def _install_hint() -> str:
    from kingdomx.core.platform_detect import current as current_platform

    plat = current_platform()
    if plat.is_termux:
        return "Install with: pkg install nmap"
    if plat.family in {"kali", "parrot", "debian", "ubuntu"}:
        return "Install with: sudo apt install -y nmap"
    return "Install nmap from https://nmap.org/download"


def safe_lab_targets() -> list[dict[str, str]]:
    """Destinations that are always legitimate to scan."""
    return [
        {
            "target": "127.0.0.1",
            "why": "Loopback — your own machine. Scanning it never touches a network.",
        },
        {
            "target": "::1",
            "why": "IPv6 loopback — also your own machine.",
        },
        {
            "target": "localhost",
            "why": "Resolves to loopback.",
        },
        {
            "target": "scanme.nmap.org",
            "why": "Nmap's own host, explicitly published for testing. Rate-limited; keep it light.",
        },
        {
            "target": "192.168.0.0/16",
            "why": "Private range — only with the network owner's permission (that is usually you).",
        },
    ]


def profile_list() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "args": " ".join(spec["args"]),
            "description": spec["description"],
            "needs_root": "-sS" in spec["args"] or "-O" in spec["args"],
        }
        for name, spec in PROFILES.items()
    ]


def nmap_version() -> str | None:
    """Installed nmap version, or None."""
    if not nmap_available():
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=8,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    for line in completed.stdout.splitlines():
        if line.lower().startswith("nmap version"):
            return line.strip()
    return None or (completed.stdout.splitlines()[0] if completed.stdout else None)
