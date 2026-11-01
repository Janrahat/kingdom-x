"""Linux host configuration audit — read only.

Every check reads a file or invokes a read-only command. Nothing is modified, so
this is safe to run on a production host without a change window.

Where a check cannot run on the current platform (Termux has no ``/etc/ssh``), the
finding says so explicitly instead of reporting a false pass.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kingdomx.core.logging_setup import get_logger
from kingdomx.core.platform_detect import current as current_platform
from kingdomx.cybersecurity.severity import Finding, Report, Severity

log = get_logger("cyber.audit")

COMMAND_TIMEOUT = 5.0

#: Accounts that must never have a password hash.
SYSTEM_ACCOUNTS = frozenset(
    {
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
        "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
        "nobody", "_apt", "systemd-network", "systemd-timesync", "messagebus",
        "sshd", "colord", "geoclue", "pulse", "rtkit", "saned", "whoopsie",
    }
)


@dataclass
class Check:
    """One auditable property of the host."""

    key: str
    title: str
    category: str
    severity: Severity
    run: Callable[[], tuple[bool | None, str, str]]
    """Returns ``(ok, evidence, remediation)``. ``ok=None`` means not applicable."""


def _run(argv: list[str], *, timeout: float = COMMAND_TIMEOUT) -> tuple[int, str]:
    """Run a read-only command from an argv list (never a shell string)."""
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return 127, ""
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


def _read(path: str, limit: int = 200_000) -> str | None:
    try:
        target = Path(path)
        if not target.is_file():
            return None
        return target.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return None


# --------------------------------------------------------------------------- checks
def check_ssh_root_login() -> tuple[bool | None, str, str]:
    config = _read("/etc/ssh/sshd_config")
    if config is None:
        return None, "/etc/ssh/sshd_config not present (sshd not installed, or not Linux)", ""
    match = re.search(r"^\s*PermitRootLogin\s+(\S+)", config, re.MULTILINE)
    value = match.group(1).lower() if match else "prohibit-password (default)"
    ok = bool(match) and value in {"no", "prohibit-password", "forced-commands-only"}
    return ok, f"PermitRootLogin {value}", "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd."


def check_ssh_password_auth() -> tuple[bool | None, str, str]:
    config = _read("/etc/ssh/sshd_config")
    if config is None:
        return None, "/etc/ssh/sshd_config not present", ""
    match = re.search(r"^\s*PasswordAuthentication\s+(\S+)", config, re.MULTILINE)
    value = match.group(1).lower() if match else "yes (default)"
    ok = bool(match) and value == "no"
    return ok, f"PasswordAuthentication {value}", "Set 'PasswordAuthentication no' and distribute SSH keys."


def check_ssh_empty_passwords() -> tuple[bool | None, str, str]:
    config = _read("/etc/ssh/sshd_config")
    if config is None:
        return None, "/etc/ssh/sshd_config not present", ""
    match = re.search(r"^\s*PermitEmptyPasswords\s+(\S+)", config, re.MULTILINE)
    value = match.group(1).lower() if match else "no (default)"
    return value == "no", f"PermitEmptyPasswords {value}", "Keep PermitEmptyPasswords at no."


def check_firewall() -> tuple[bool | None, str, str]:
    for tool, args in (("ufw", ["status"]), ("nft", ["list", "ruleset"]), ("iptables", ["-S"])):
        code, output = _run([tool, *args])
        if code == 127:
            continue
        if code != 0:
            continue
        lowered = output.lower()
        if tool == "ufw":
            if "status: active" in lowered:
                return True, "ufw is active", ""
            return False, "ufw is installed but inactive", "Enable it: sudo ufw enable (after allowing SSH)."
        if tool == "nft":
            rules = len([line for line in output.splitlines() if line.strip()])
            return rules > 0, f"nftables has {rules} rule line(s)", "Add a default-drop input policy."
        rules = len([line for line in output.splitlines() if line.startswith("-A")])
        return rules > 0, f"iptables has {rules} rule(s)", "Add a default-drop input policy."
    return None, "no firewall tool found (ufw, nft, iptables)", "Install and enable ufw."


def check_world_writable_etc() -> tuple[bool | None, str, str]:
    base = Path("/etc")
    if not base.is_dir():
        return None, "/etc not present", ""
    offenders: list[str] = []
    for candidate in base.rglob("*"):
        if len(offenders) >= 10:
            break
        try:
            mode = candidate.lstat().st_mode
        except OSError:
            continue
        if mode & stat.S_IWOTH:
            offenders.append(str(candidate))
    if offenders:
        return False, "world-writable: " + ", ".join(offenders[:5]), "chmod o-w on each path."
    return True, "/etc has no world-writable entries", ""


def check_passwd_permissions() -> tuple[bool | None, str, str]:
    problems: list[str] = []
    expected = {
        "/etc/passwd": 0o644,
        "/etc/shadow": 0o640,
        "/etc/group": 0o644,
        "/etc/gshadow": 0o640,
        "/etc/sudoers": 0o440,
    }
    checked = 0
    for path, maximum in expected.items():
        try:
            mode = Path(path).stat().st_mode & 0o777
        except OSError:
            continue
        checked += 1
        if mode & 0o007:
            problems.append(f"{path} is {oct(mode)} (world-accessible)")
        elif mode > maximum:
            problems.append(f"{path} is {oct(mode)}, expected {oct(maximum)}")
    if not checked:
        return None, "no standard account files found", ""
    if problems:
        return False, "; ".join(problems), "chmod 640 /etc/shadow; chmod 440 /etc/sudoers."
    return True, f"{checked} account file(s) have correct modes", ""


def check_empty_passwords() -> tuple[bool | None, str, str]:
    shadow = _read("/etc/shadow")
    if shadow is None:
        return None, "/etc/shadow not readable (needs root, or not Linux)", ""
    empty: list[str] = []
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "":
            empty.append(parts[0])
    if empty:
        return False, "accounts with no password: " + ", ".join(empty), "Lock them: passwd -l <user>."
    return True, "no account has an empty password hash", ""


def check_suid_binaries() -> tuple[bool | None, str, str]:
    code, output = _run(
        ["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-perm", "-4000", "-type", "f"],
        timeout=8.0,
    )
    if code == 127:
        return None, "find command unavailable", ""
    entries = [line for line in output.splitlines() if line.strip().startswith("/")]
    if len(entries) > 25:
        return False, f"{len(entries)} setuid binaries (unusually many)", "Review each; remove the setuid bit where unnecessary."
    return True, f"{len(entries)} setuid binaries under standard bin paths", ""


def check_core_dumps() -> tuple[bool | None, str, str]:
    limits = _read("/etc/security/limits.conf")
    sysctl = _read("/etc/sysctl.conf")
    if limits is None and sysctl is None:
        return None, "no limits.conf or sysctl.conf", ""
    text = (limits or "") + "\n" + (sysctl or "")
    disabled = bool(re.search(r"^\s*\*\s+(?:hard|soft)\s+core\s+0", text, re.MULTILINE)) or bool(
        re.search(r"fs\.suid_dumpable\s*=\s*0", text)
    )
    return disabled, "core dumps " + ("restricted" if disabled else "not explicitly restricted"), (
        "Add '* hard core 0' to /etc/security/limits.conf to stop cores leaking memory to disk."
    )


def check_aslr() -> tuple[bool | None, str, str]:
    value = _read("/proc/sys/kernel/randomize_va_space")
    if value is None:
        return None, "/proc/sys/kernel/randomize_va_space unreadable", ""
    level = value.strip()
    return level == "2", f"randomize_va_space={level}", "echo 2 > /proc/sys/kernel/randomize_va_space"


def check_ip_forwarding() -> tuple[bool | None, str, str]:
    value = _read("/proc/sys/net/ipv4/ip_forward")
    if value is None:
        return None, "ip_forward unreadable", ""
    enabled = value.strip() == "1"
    return (not enabled), f"ip_forward={value.strip()}", (
        "Disable unless this host is a router: sysctl -w net.ipv4.ip_forward=0"
    )


def check_unattended_upgrades() -> tuple[bool | None, str, str]:
    config = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if not config.parent.is_dir():
        return None, "apt not present", ""
    if not config.is_file():
        return False, "20auto-upgrades not configured", "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"
    text = config.read_text(encoding="utf-8", errors="replace")
    enabled = bool(re.search(r'Update-Package-Lists\s+"1"', text)) and bool(
        re.search(r'Unattended-Upgrade\s+"1"', text)
    )
    return enabled, "automatic upgrades " + ("enabled" if enabled else "disabled"), (
        "Enable unattended-upgrades so security patches apply without manual intervention."
    )


def check_selinux_apparmor() -> tuple[bool | None, str, str]:
    selinux = _read("/sys/fs/selinux/enforce")
    if selinux is not None:
        enforcing = selinux.strip() == "1"
        return enforcing, f"SELinux enforce={selinux.strip()}", "Set SELINUX=enforcing in /etc/selinux/config."
    apparmor = Path("/sys/module/apparmor")
    if apparmor.is_dir():
        profiles = _read("/sys/kernel/security/apparmor/profiles")
        count = len([line for line in (profiles or "").splitlines() if line.strip()])
        return count > 0, f"AppArmor loaded with {count} profile(s)", "Enable profiles for exposed services."
    status, output = _run(["aa-status"])
    if status == 0 and "apparmor module is loaded" in output.lower():
        return True, "AppArmor is loaded", ""
    return None, "neither SELinux nor AppArmor detected", ""


def check_time_sync() -> tuple[bool | None, str, str]:
    code, output = _run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    if code == 0 and output.strip():
        synced = output.strip().lower() == "yes"
        return synced, f"NTPSynchronized={output.strip()}", "Enable systemd-timesyncd or chrony."
    for service in ("systemd-timesyncd", "chronyd", "ntpd"):
        code2, out2 = _run(["systemctl", "is-active", service])
        if code2 == 0 and out2.strip() == "active":
            return True, f"{service} is active", ""
    return None, "could not determine time synchronisation", "Install and enable a time daemon."


def check_open_dangerous_ports() -> tuple[bool | None, str, str]:
    """Read the local listening sockets (not a scan)."""
    code, output = _run(["ss", "-lntup"])
    if code != 0:
        code, output = _run(["netstat", "-lntup"])
        if code != 0:
            return None, "neither ss nor netstat available", ""

    from kingdomx.cybersecurity.ports import KNOWN_PORTS

    dangerous: list[str] = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[4] if parts[0].startswith(("tcp", "udp")) else parts[3]
        address, _, port_text = local.rpartition(":")
        port_text = port_text.strip()
        if not port_text.isdigit():
            continue
        port = int(port_text)
        info = KNOWN_PORTS.get(port)
        if info and info.risk in {"critical", "high"}:
            exposed = address.strip() in {"0.0.0.0", "*", "::", "[::]"}
            dangerous.append(f"{port}/{info.service}{' (all interfaces)' if exposed else ''}")

    if dangerous:
        return False, "listening: " + ", ".join(sorted(set(dangerous))[:10]), (
            "Bind these services to 127.0.0.1 or restrict them with a firewall rule."
        )
    return True, "no high/critical-risk service listening locally", ""


CHECKS: tuple[Check, ...] = (
    Check("ssh_root", "SSH root login disabled", "ssh", Severity.HIGH, check_ssh_root_login),
    Check("ssh_password", "SSH password authentication disabled", "ssh", Severity.HIGH, check_ssh_password_auth),
    Check("ssh_empty", "SSH empty passwords disabled", "ssh", Severity.CRITICAL, check_ssh_empty_passwords),
    Check("firewall", "Host firewall active", "network", Severity.HIGH, check_firewall),
    Check("etc_perms", "/etc free of world-writable entries", "permissions", Severity.HIGH, check_world_writable_etc),
    Check("acct_perms", "Account file permissions correct", "permissions", Severity.HIGH, check_passwd_permissions),
    Check("empty_pw", "No account has an empty password", "accounts", Severity.CRITICAL, check_empty_passwords),
    Check("suid", "Setuid binary count reasonable", "permissions", Severity.MEDIUM, check_suid_binaries),
    Check("core", "Core dumps restricted", "hardening", Severity.LOW, check_core_dumps),
    Check("aslr", "ASLR fully enabled", "hardening", Severity.MEDIUM, check_aslr),
    Check("ipfwd", "IP forwarding disabled", "network", Severity.LOW, check_ip_forwarding),
    Check("upgrades", "Automatic security upgrades enabled", "patching", Severity.MEDIUM, check_unattended_upgrades),
    Check("mac", "Mandatory access control active", "hardening", Severity.MEDIUM, check_selinux_apparmor),
    Check("time", "Time synchronisation active", "hardening", Severity.LOW, check_time_sync),
    Check("ports", "No dangerous service listening on all interfaces", "network", Severity.HIGH, check_open_dangerous_ports),
)


def run_audit(*, keys: list[str] | None = None, categories: list[str] | None = None) -> Report:
    """Run the read-only host audit."""
    platform = current_platform()
    report = Report(module="host_audit", target=platform.label, started_at=time.time())
    wanted_keys = set(keys or [])
    wanted_categories = {c.lower() for c in (categories or [])}

    executed = 0
    for check in CHECKS:
        if wanted_keys and check.key not in wanted_keys:
            continue
        if wanted_categories and check.category.lower() not in wanted_categories:
            continue
        executed += 1
        try:
            ok, evidence, remediation = check.run()
        except Exception as exc:  # noqa: BLE001 - one bad check must not kill the audit
            report.errors.append(f"{check.key}: {type(exc).__name__}")
            continue

        if ok is None:
            report.add(
                Finding(
                    title=f"{check.title} — not applicable",
                    severity=Severity.INFO,
                    category=check.category,
                    detail=evidence or "check could not run on this platform",
                    passed=False,
                    extra={"check": check.key, "applicable": False},
                )
            )
        elif ok:
            report.passed(check.title, check.category, detail=evidence, extra={"check": check.key})
        else:
            report.issue(
                title=check.title,
                severity=check.severity,
                category=check.category,
                detail=evidence,
                remediation=remediation or None,
                extra={"check": check.key},
            )

    report.meta = {
        "platform": platform.label,
        "family": platform.family,
        "checks_run": executed,
        "is_root": platform.is_root,
        "read_only": True,
        "note": (
            "Termux has no /etc/ssh or systemd; Linux-specific checks report "
            "'not applicable' there rather than a false pass."
        ),
    }
    report.finished_at = time.time()
    return report


def list_checks() -> list[dict[str, Any]]:
    return [
        {
            "key": check.key,
            "title": check.title,
            "category": check.category,
            "severity": check.severity.label,
        }
        for check in CHECKS
    ]
