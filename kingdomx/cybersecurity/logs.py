"""Log analysis: parse common Linux/auth log formats and surface real signal.

Handles syslog-style lines (``auth.log``, ``syslog``, ``messages``), journald
short format, and generic application logs. Detects brute-force attempts, sudo
escalation, service crashes, OOM kills and repeated connection refusals.

Everything is local file reading. Nothing is uploaded.
"""

from __future__ import annotations

import gzip
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from kingdomx.cybersecurity.severity import Finding, Report, Severity

#: Syslog header: ``Oct 31 14:22:01 host process[pid]: message``
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

#: ISO-ish prefix used by journald and most app logs.
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<rest>.*)$"
)

#: Severity tokens in a log line.
LEVEL_RE = re.compile(
    r"\b(?P<level>EMERG|ALERT|CRIT|CRITICAL|ERROR|ERR|WARN|WARNING|NOTICE|INFO|DEBUG|TRACE)\b",
    re.IGNORECASE,
)

LEVEL_SEVERITY = {
    "emerg": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "err": Severity.HIGH,
    "warn": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "notice": Severity.LOW,
    "info": Severity.INFO,
    "debug": Severity.INFO,
    "trace": Severity.INFO,
}

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

#: Detection patterns. Each yields a finding when its threshold is met.
PATTERNS: dict[str, dict[str, Any]] = {
    "ssh_failed": {
        "regex": re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)", re.I),
        "title": "SSH authentication failures",
        "severity": Severity.HIGH,
        "threshold": 5,
        "detail": "Repeated SSH password failures indicate brute-forcing or a misconfigured service.",
        "remediation": "Disable password authentication, require keys, and rate-limit with fail2ban or sshd MaxStartups.",
    },
    "ssh_invalid_user": {
        "regex": re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)", re.I),
        "title": "SSH logins for non-existent users",
        "severity": Severity.MEDIUM,
        "threshold": 5,
        "detail": "Attempts against non-existent accounts are a strong brute-force signal.",
    },
    "ssh_breakin": {
        "regex": re.compile(r"(?:POSSIBLE BREAK-IN ATTEMPT|reverse mapping checking getaddrinfo.*failed)", re.I),
        "title": "SSH reverse-DNS mismatch",
        "severity": Severity.LOW,
        "threshold": 1,
        "detail": "Forward/reverse DNS disagree for the connecting host.",
    },
    "sudo_fail": {
        "regex": re.compile(r"sudo:.*incorrect password attempts?|authentication failure.*sudo", re.I),
        "title": "Failed sudo authentication",
        "severity": Severity.HIGH,
        "threshold": 3,
        "detail": "Someone is trying to escalate privileges and failing.",
    },
    "sudo_ok": {
        "regex": re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.*)", re.I),
        "title": "Successful sudo escalations",
        "severity": Severity.LOW,
        "threshold": 1,
        "detail": "Privilege escalation occurred. Verify each command was intended.",
    },
    "auth_failure": {
        "regex": re.compile(r"authentication failure|pam_unix.*authentication failure", re.I),
        "title": "PAM authentication failures",
        "severity": Severity.MEDIUM,
        "threshold": 5,
        "detail": "Repeated PAM failures across services.",
    },
    "oom_kill": {
        "regex": re.compile(r"Out of memory: Killed process|oom-kill:.*task=", re.I),
        "title": "OOM killer invoked",
        "severity": Severity.HIGH,
        "threshold": 1,
        "detail": "The kernel killed a process for lack of memory. Services will appear to crash randomly.",
        "remediation": "Find the memory consumer, add swap or a memory limit, and set a systemd MemoryMax.",
    },
    "segfault": {
        "regex": re.compile(r"segfault at|general protection fault", re.I),
        "title": "Segmentation faults",
        "severity": Severity.MEDIUM,
        "threshold": 1,
        "detail": "A process crashed at the memory level — likely a bug or a corrupted binary.",
    },
    "service_fail": {
        "regex": re.compile(r"(?:Failed to start|failed with result|Unit .* entered failed state)", re.I),
        "title": "Service start failures",
        "severity": Severity.HIGH,
        "threshold": 1,
        "detail": "systemd reported a unit failure.",
        "remediation": "Inspect with `systemctl status <unit>` and `journalctl -u <unit> -n 100`.",
    },
    "disk_full": {
        "regex": re.compile(r"No space left on device|disk quota exceeded", re.I),
        "title": "Disk space exhaustion",
        "severity": Severity.CRITICAL,
        "threshold": 1,
        "detail": "Writes are failing. This cascades into database and service corruption.",
        "remediation": "Free space now, then set up log rotation and a disk-usage alert.",
    },
    "conn_refused": {
        "regex": re.compile(r"Connection refused|connect to .* failed: Connection refused", re.I),
        "title": "Connection refusals",
        "severity": Severity.LOW,
        "threshold": 10,
        "detail": "A client is repeatedly reaching a port nothing listens on.",
    },
    "permission_denied": {
        "regex": re.compile(r"Permission denied|Access denied", re.I),
        "title": "Permission denials",
        "severity": Severity.LOW,
        "threshold": 10,
        "detail": "Repeated permission errors point at a wrong owner or mode.",
    },
    "tls_error": {
        "regex": re.compile(r"SSL_CTX_use_PrivateKey.*failed|certificate verify failed|SSL alert number", re.I),
        "title": "TLS/certificate errors",
        "severity": Severity.MEDIUM,
        "threshold": 1,
        "detail": "Certificate or key problems. Clients will refuse the connection.",
    },
}


@dataclass
class LogLine:
    raw: str
    line_no: int
    ts: datetime | None = None
    host: str = ""
    process: str = ""
    level: str = ""
    message: str = ""
    ips: tuple[str, ...] = ()


@dataclass
class LogAnalysis:
    path: str
    total_lines: int = 0
    parsed_lines: int = 0
    level_counts: dict[str, int] = field(default_factory=dict)
    process_counts: dict[str, int] = field(default_factory=dict)
    ip_counts: dict[str, int] = field(default_factory=dict)
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    detections: dict[str, list[LogLine]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "level_counts": dict(self.level_counts),
            "top_processes": dict(
                sorted(self.process_counts.items(), key=lambda kv: -kv[1])[:10]
            ),
            "top_source_ips": dict(sorted(self.ip_counts.items(), key=lambda kv: -kv[1])[:10]),
            "first_timestamp": self.first_ts.isoformat() if self.first_ts else None,
            "last_timestamp": self.last_ts.isoformat() if self.last_ts else None,
            "detections": {name: len(items) for name, items in self.detections.items()},
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }


def _open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _parse_timestamp(text: str) -> datetime | None:
    """Parse syslog month/day or ISO timestamps. Year is inferred as current."""
    raw = (text or "").strip()
    if not raw:
        return None
    iso = raw.replace("Z", "+00:00").replace(" ", "T", 1)
    try:
        parsed = datetime.fromisoformat(iso)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    try:
        parsed = datetime.strptime(raw, "%b %d %H:%M:%S")
        now = datetime.now(timezone.utc)
        candidate = parsed.replace(year=now.year, tzinfo=timezone.utc)
        # A December line read in January belongs to last year.
        if candidate > now.replace(day=now.day) and (candidate - now).days > 180:
            candidate = candidate.replace(year=now.year - 1)
        return candidate
    except ValueError:
        return None


def parse_line(raw: str, line_no: int) -> LogLine:
    """Parse one log line into structured fields."""
    line = LogLine(raw=raw.rstrip("\n"), line_no=line_no)
    text = line.raw

    syslog = SYSLOG_RE.match(text)
    if syslog:
        line.ts = _parse_timestamp(syslog.group("ts"))
        line.host = syslog.group("host")
        line.process = syslog.group("proc")
        line.message = syslog.group("msg")
    else:
        iso = ISO_RE.match(text)
        if iso:
            line.ts = _parse_timestamp(iso.group("ts"))
            line.message = iso.group("rest")
            head = line.message.split(" ", 1)[0]
            if head and ":" in head:
                line.process = head.rstrip(":")
        else:
            line.message = text

    level_match = LEVEL_RE.search(line.message) or LEVEL_RE.search(text)
    if level_match:
        line.level = level_match.group("level").upper()

    ips = [ip for ip in IPV4_RE.findall(line.message)]
    ips.extend(IPV6_RE.findall(line.message))
    line.ips = tuple(dict.fromkeys(ips))
    return line


def analyse_file(
    path: str | Path,
    *,
    max_lines: int = 200000,
    since: datetime | None = None,
) -> LogAnalysis:
    """Read and analyse one log file (optionally gzipped)."""
    file_path = Path(path)
    analysis = LogAnalysis(path=str(file_path))
    if not file_path.is_file():
        analysis.errors.append(f"file not found: {file_path}")
        return analysis

    level_counter: Counter[str] = Counter()
    process_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    detections: dict[str, list[LogLine]] = defaultdict(list)

    try:
        with _open_text(file_path) as handle:
            for index, raw in enumerate(handle.read().splitlines(), start=1):
                if index > max_lines:
                    break
                analysis.total_lines += 1
                if not raw.strip():
                    continue
                line = parse_line(raw, index)
                if not line.message:
                    continue
                analysis.parsed_lines += 1

                if since and line.ts and line.ts < since:
                    continue

                if line.level:
                    level_counter[line.level] += 1
                if line.process:
                    process_counter[line.process] += 1
                for ip in line.ips:
                    ip_counter[ip] += 1

                if line.ts:
                    if analysis.first_ts is None or line.ts < analysis.first_ts:
                        analysis.first_ts = line.ts
                    if analysis.last_ts is None or line.ts > analysis.last_ts:
                        analysis.last_ts = line.ts

                for name, spec in PATTERNS.items():
                    if spec["regex"].search(line.message):
                        detections[name].append(line)
    except OSError as exc:
        analysis.errors.append(f"cannot read {file_path}: {exc}")
        return analysis

    analysis.level_counts = dict(level_counter)
    analysis.process_counts = dict(process_counter)
    analysis.ip_counts = dict(ip_counter)
    analysis.detections = dict(detections)
    analysis.findings = _build_findings(analysis)
    return analysis


def _build_findings(analysis: LogAnalysis) -> list[Finding]:
    findings: list[Finding] = []

    for name, hits in analysis.detections.items():
        spec = PATTERNS[name]
        if len(hits) < spec["threshold"]:
            continue
        ips = Counter(ip for hit in hits for ip in hit.ips)
        top = ", ".join(f"{ip} ({count})" for ip, count in ips.most_common(5))
        findings.append(
            Finding(
                title=f"{spec['title']}: {len(hits)} occurrence(s)",
                severity=spec["severity"],
                category="logs",
                detail=spec["detail"] + (f"\nTop sources: {top}" if top else ""),
                evidence="\n".join(hit.raw[:200] for hit in hits[:3]),
                remediation=spec.get("remediation"),
                extra={"pattern": name, "count": len(hits)},
            )
        )

    if analysis.level_counts.get("CRITICAL") or analysis.level_counts.get("CRIT"):
        findings.append(
            Finding(
                title="Critical-level log entries present",
                severity=Severity.HIGH,
                category="logs",
                detail=f"{analysis.level_counts.get('CRITICAL', 0) + analysis.level_counts.get('CRIT', 0)} critical lines.",
            )
        )

    if not findings:
        findings.append(
            Finding(
                title=f"No problem patterns found in {analysis.parsed_lines} parsed line(s)",
                severity=Severity.INFO,
                category="logs",
                detail=(
                    "Absence of matches is not proof the host is healthy — it means these "
                    "specific patterns did not appear in the window read."
                ),
                passed=True,
            )
        )
    return sorted(findings, key=lambda f: (f.passed, -f.severity.weight))


def analyse_path(path: str | Path, **kwargs: Any) -> Report:
    """Analyse a file or every readable log under a directory."""
    report = Report(module="logs", target=str(path), started_at=time.time())
    base = Path(path).expanduser()

    if base.is_dir():
        candidates = [
            candidate
            for candidate in sorted(base.rglob("*"))
            if candidate.is_file()
            and (candidate.suffix in {"", ".log", ".gz"} or "log" in candidate.name.lower())
        ][:40]
    else:
        candidates = [base]

    analyses: list[LogAnalysis] = []
    for candidate in candidates:
        result = analyse_file(candidate, **kwargs)
        analyses.append(result)
        report.findings.extend(result.findings)
        report.errors.extend(result.errors)

    report.meta = {
        "files_analysed": len(analyses),
        "files": [
            {
                "path": item.path,
                "lines": item.total_lines,
                "parsed": item.parsed_lines,
                "detections": {k: len(v) for k, v in item.detections.items()},
            }
            for item in analyses
        ],
        "total_lines": sum(item.total_lines for item in analyses),
    }
    report.finished_at = time.time()
    return report


def top_offenders(analysis: LogAnalysis, *, limit: int = 10) -> list[dict[str, Any]]:
    """The noisiest source IPs in one analysis."""
    return [
        {"ip": ip, "occurrences": count}
        for ip, count in sorted(analysis.ip_counts.items(), key=lambda kv: -kv[1])[:limit]
    ]


def timeline(analysis: LogAnalysis, *, buckets: int = 24) -> list[dict[str, Any]]:
    """Bucket log activity into equal time slices between first and last event."""
    if not analysis.first_ts or not analysis.last_ts:
        return []
    span = (analysis.last_ts - analysis.first_ts).total_seconds()
    if span <= 0:
        return [{"start": analysis.first_ts.isoformat(), "count": analysis.total_lines}]

    width = span / buckets
    counts = [0] * buckets
    for hits in analysis.detections.values():
        for hit in hits:
            if not hit.ts:
                continue
            offset = (hit.ts - analysis.first_ts).total_seconds()
            index = min(buckets - 1, max(0, int(offset // width)))
            counts[index] += 1

    return [
        {
            "start": (
                analysis.first_ts.timestamp() + index * width
            ),
            "count": count,
        }
        for index, count in enumerate(counts)
    ]


def common_log_paths() -> list[Path]:
    """Standard locations worth checking on this platform."""
    candidates = [
        Path("/var/log/auth.log"),
        Path("/var/log/secure"),
        Path("/var/log/syslog"),
        Path("/var/log/messages"),
        Path("/var/log/kern.log"),
        Path("/var/log/dpkg.log"),
        Path("/var/log/nginx/error.log"),
        Path("/var/log/apache2/error.log"),
    ]
    from kingdomx.core.platform_detect import current as current_platform

    platform = current_platform()
    if platform.is_termux:
        prefix = Path("/data/data/com.termux/files/usr/var/log")
        candidates.extend([prefix / "termux.log", prefix / "pacman.log"])
    return [path for path in candidates if path.is_file()]
