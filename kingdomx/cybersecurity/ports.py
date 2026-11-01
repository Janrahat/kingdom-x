"""Port and service knowledge base.

Data only — no scanning. Used to explain a port number, to warn when an exposed
service is dangerous, and to give the report generator something factual to cite.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PortInfo:
    port: int
    service: str
    transport: str
    description: str
    risk: str
    """``none``, ``low``, ``medium``, ``high``, ``critical``."""

    encrypted: bool = False


#: Well-known ports worth explaining. Not exhaustive — a curated defensive list.
KNOWN_PORTS: dict[int, PortInfo] = {
    20: PortInfo(20, "ftp-data", "tcp", "FTP data channel (active mode).", "medium"),
    21: PortInfo(21, "ftp", "tcp", "FTP control channel; plaintext credentials.", "high"),
    22: PortInfo(22, "ssh", "tcp", "Secure Shell. Key-based auth only; disable password login.", "low", True),
    23: PortInfo(23, "telnet", "tcp", "Telnet: plaintext everything. Should not exist on a modern host.", "critical"),
    25: PortInfo(25, "smtp", "tcp", "SMTP. Relaying must be locked down.", "medium"),
    53: PortInfo(53, "domain", "udp", "DNS. Open recursion enables amplification attacks.", "medium"),
    67: PortInfo(67, "dhcp", "udp", "DHCP server.", "low"),
    69: PortInfo(69, "tftp", "udp", "TFTP: no authentication at all.", "high"),
    80: PortInfo(80, "http", "tcp", "Plain HTTP. Redirect to HTTPS.", "medium"),
    88: PortInfo(88, "kerberos", "tcp", "Kerberos authentication.", "low", True),
    110: PortInfo(110, "pop3", "tcp", "POP3 without TLS exposes mail credentials.", "high"),
    111: PortInfo(111, "rpcbind", "tcp", "RPC portmapper; frequently abused for amplification.", "high"),
    123: PortInfo(123, "ntp", "udp", "NTP. Misconfigured monlist enables DDoS amplification.", "low"),
    135: PortInfo(135, "msrpc", "tcp", "Windows RPC endpoint mapper. Never expose to the internet.", "critical"),
    137: PortInfo(137, "netbios-ns", "udp", "NetBIOS name service; leaks host and workgroup names.", "high"),
    139: PortInfo(139, "netbios-ssn", "tcp", "NetBIOS session service.", "high"),
    143: PortInfo(143, "imap", "tcp", "IMAP. Use 993 with TLS.", "high"),
    161: PortInfo(161, "snmp", "udp", "SNMP. v1/v2c community strings are plaintext.", "high"),
    389: PortInfo(389, "ldap", "tcp", "LDAP. Use 636 (LDAPS) or StartTLS.", "high"),
    443: PortInfo(443, "https", "tcp", "HTTPS.", "none", True),
    445: PortInfo(445, "microsoft-ds", "tcp", "SMB. EternalBlue-class targets; never internet-facing.", "critical"),
    465: PortInfo(465, "smtps", "tcp", "SMTP over implicit TLS.", "low", True),
    500: PortInfo(500, "isakmp", "udp", "IPsec IKE.", "low", True),
    514: PortInfo(514, "syslog", "udp", "Syslog over UDP: unauthenticated and spoofable.", "medium"),
    587: PortInfo(587, "submission", "tcp", "SMTP submission with STARTTLS.", "low", True),
    636: PortInfo(636, "ldaps", "tcp", "LDAP over TLS.", "low", True),
    873: PortInfo(873, "rsync", "tcp", "rsync daemon; often world-readable exports.", "high"),
    993: PortInfo(993, "imaps", "tcp", "IMAP over TLS.", "low", True),
    995: PortInfo(995, "pop3s", "tcp", "POP3 over TLS.", "low", True),
    1080: PortInfo(1080, "socks", "tcp", "SOCKS proxy; an open one is an abuse vector.", "high"),
    1433: PortInfo(1433, "ms-sql-s", "tcp", "Microsoft SQL Server. Never expose publicly.", "critical"),
    1521: PortInfo(1521, "oracle", "tcp", "Oracle TNS listener.", "critical"),
    2049: PortInfo(2049, "nfs", "tcp", "NFS; misconfigured exports leak whole filesystems.", "critical"),
    2375: PortInfo(2375, "docker", "tcp", "Docker daemon WITHOUT TLS — effectively root on the host.", "critical"),
    2376: PortInfo(2376, "docker-s", "tcp", "Docker daemon over TLS.", "medium", True),
    3000: PortInfo(3000, "dev-server", "tcp", "Typical Node/React dev server. Development only.", "medium"),
    3306: PortInfo(3306, "mysql", "tcp", "MySQL/MariaDB. Bind to localhost or a private network.", "critical"),
    3389: PortInfo(3389, "ms-wbt-server", "tcp", "RDP. Brute-forced constantly; VPN + MFA required.", "critical", True),
    5432: PortInfo(5432, "postgresql", "tcp", "PostgreSQL. Should never be internet-facing.", "critical"),
    5601: PortInfo(5601, "kibana", "tcp", "Kibana; unauthenticated instances leak all indexed logs.", "high"),
    5672: PortInfo(5672, "amqp", "tcp", "RabbitMQ AMQP.", "medium"),
    5900: PortInfo(5900, "vnc", "tcp", "VNC. Frequently password-less.", "critical"),
    6379: PortInfo(6379, "redis", "tcp", "Redis. Unauthenticated Redis is a well-known RCE path.", "critical"),
    6443: PortInfo(6443, "kubernetes-api", "tcp", "Kubernetes API server.", "high", True),
    8000: PortInfo(8000, "http-alt", "tcp", "Common application/dev HTTP port.", "low"),
    8080: PortInfo(8080, "http-proxy", "tcp", "Alternate HTTP / proxy port.", "medium"),
    8443: PortInfo(8443, "https-alt", "tcp", "Alternate HTTPS port.", "low", True),
    8888: PortInfo(8888, "sun-answerbook", "tcp", "Common Jupyter/proxy port; notebooks often unauthenticated.", "high"),
    9000: PortInfo(9000, "php-fpm", "tcp", "PHP-FPM or Portainer; both dangerous when exposed.", "high"),
    9090: PortInfo(9090, "prometheus", "tcp", "Prometheus UI; leaks infrastructure topology.", "medium"),
    9200: PortInfo(9200, "elasticsearch", "tcp", "Elasticsearch. Open instances have leaked terabytes.", "critical"),
    9300: PortInfo(9300, "elasticsearch-cluster", "tcp", "Elasticsearch transport port.", "critical"),
    11211: PortInfo(11211, "memcached", "udp", "Memcached; classic amplification and cache-poisoning target.", "critical"),
    27017: PortInfo(27017, "mongodb", "tcp", "MongoDB. Historically defaulted to no authentication.", "critical"),
    50000: PortInfo(50000, "sap", "tcp", "SAP application server.", "high"),
}

#: Services whose mere exposure on a public interface is a serious problem.
CRITICAL_EXPOSURE = frozenset(
    port for port, info in KNOWN_PORTS.items() if info.risk == "critical"
)


def describe_port(port: int) -> str:
    """Human-readable explanation of a port number."""
    info = KNOWN_PORTS.get(int(port))
    if info is None:
        if 0 < int(port) < 1024:
            return (
                f"Port {port}: unassigned system port in the privileged range "
                "(0-1023). Unknown service; identify it before exposing it."
            )
        if int(port) < 49152:
            return (
                f"Port {port}: registered range (1024-49151), no entry in the KINGDOM X "
                "knowledge base. Check IANA for the current assignment."
            )
        return (
            f"Port {port}: dynamic/ephemeral range (49152-65535). Normally used for "
            "outbound connections, so a listener here is unusual."
        )

    lines = [
        f"Port {info.port}/{info.transport}  {info.service}",
        "",
        info.description,
        f"Encrypted: {'yes' if info.encrypted else 'no'}",
        f"Exposure risk: {info.risk.upper()}",
    ]
    if info.risk in {"critical", "high"}:
        lines.append(
            "If this port is reachable from the internet, treat it as an incident until "
            "you have proven otherwise."
        )
    return "\n".join(lines)


def risk_for(port: int) -> str:
    info = KNOWN_PORTS.get(int(port))
    if info is None:
        return "medium" if int(port) < 1024 else "low"
    return info.risk


def service_for(port: int) -> str:
    info = KNOWN_PORTS.get(int(port))
    return info.service if info else "unknown"


def is_encrypted(port: int) -> bool:
    info = KNOWN_PORTS.get(int(port))
    return bool(info and info.encrypted)


def dangerous_open_ports(open_ports: list[int]) -> list[dict]:
    """Which of these open ports deserve escalation."""
    out = []
    for port in open_ports:
        info = KNOWN_PORTS.get(int(port))
        if info and info.risk in {"critical", "high"}:
            out.append(
                {
                    "port": info.port,
                    "service": info.service,
                    "risk": info.risk,
                    "why": info.description,
                }
            )
    return out


#: Ports used by the standard "top 100" style checks, ordered by usefulness.
COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 636, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900,
    6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017,
)


def parse_port_spec(spec: str) -> list[int]:
    """Expand ``"80,443,8000-8010"`` into a port list."""
    from kingdomx.core.validation import validate_port_spec

    validate_port_spec(spec).raise_if_invalid("port specification")
    ports: list[int] = []
    for chunk in spec.replace(" ", "").split(","):
        if "-" in chunk:
            low, _, high = chunk.partition("-")
            ports.extend(range(int(low), int(high) + 1))
        elif chunk:
            ports.append(int(chunk))
    # De-duplicate while keeping order.
    seen: set[int] = set()
    out: list[int] = []
    for port in ports:
        if port not in seen and 0 < port < 65536:
            seen.add(port)
            out.append(port)
    return out
