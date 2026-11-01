"""Detection of installed security tooling.

A tool is only reported ``present`` when an executable was actually found on
PATH. Versions come from running ``<tool> --version`` with a hard timeout and
capturing the first line — no shell, no interpolation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Sequence

from kingdomx.core.logging_setup import get_logger
from kingdomx.core.platform_detect import current as current_platform

log = get_logger("cyber.tools")

VERSION_TIMEOUT = 4.0


@dataclass(frozen=True)
class ToolSpec:
    """A legitimate, well-known security utility."""

    name: str
    binary: str
    category: str
    purpose: str
    homepage: str
    license: str
    version_args: tuple[str, ...] = ("--version",)
    platforms: tuple[str, ...] = ()
    """Empty = any Linux-like platform. Otherwise the families it works on."""
    kali_package: str = ""
    termux_package: str = ""
    requires_root: bool = False
    active: bool = False
    """True when running it touches a target (needs authorization)."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "version_args", tuple(self.version_args))
        object.__setattr__(self, "platforms", tuple(self.platforms))


#: Curated directory with real package names and real upstream URLs.
TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "nmap", "nmap", "Network",
        "Port and service discovery; the standard host enumeration tool.",
        "https://nmap.org", "GPL-2.0 (NPSL for the nmap.org build)",
        ("--version",), kali_package="nmap", termux_package="nmap", requires_root=True, active=True,
    ),
    ToolSpec(
        "tshark", "tshark", "Network",
        "Command-line packet analysis from the Wireshark project.",
        "https://www.wireshark.org", "GPL-2.0",
        ("--version",), kali_package="tshark", termux_package="tshark", requires_root=True,
    ),
    ToolSpec(
        "tcpdump", "tcpdump", "Network",
        "Classic packet capture utility.",
        "https://www.tcpdump.org", "BSD-3-Clause",
        ("--version",), kali_package="tcpdump", termux_package="tcpdump", requires_root=True,
    ),
    ToolSpec(
        "responder", "responder", "Network",
        "LLMNR/NBT-NS/mDNS poisoner used in authorized internal assessments.",
        "https://github.com/lgandx/Responder", "GPL-3.0",
        ("--version",), requires_root=True, active=True,
    ),
    ToolSpec(
        "nikto", "nikto", "Web",
        "Web server scanner for known dangerous files and misconfigurations.",
        "https://github.com/sullo/nikto", "GPL-2.0",
        ("-Version",), kali_package="nikto", active=True,
    ),
    ToolSpec(
        "whatweb", "whatweb", "Web",
        "Web technology fingerprinting.",
        "https://github.com/urbanadventurer/WhatWeb", "GPL-2.0",
        ("--version",), kali_package="whatweb", active=True,
    ),
    ToolSpec(
        "zap", "zaproxy", "Web",
        "OWASP Zed Attack Proxy, a full web application scanner.",
        "https://www.zaproxy.org", "Apache-2.0",
        ("-version",), kali_package="zaproxy", active=True,
    ),
    ToolSpec(
        "wpscan", "wpscan", "Web",
        "WordPress vulnerability scanner.",
        "https://github.com/wpscanteam/wpscan", "Non-free (WPScan license)",
        ("--version",), kali_package="wpscan", active=True,
    ),
    ToolSpec(
        "sqlmap", "sqlmap", "Web",
        "Automated SQL injection detection and exploitation.",
        "https://sqlmap.org", "GPL-2.0",
        ("--version",), kali_package="sqlmap", active=True,
    ),
    ToolSpec(
        "lynis", "lynis", "Audit",
        "Host hardening audit for Linux and Unix systems.",
        "https://cisofy.com/lynis/", "GPL-3.0",
        ("--version",), kali_package="lynis",
    ),
    ToolSpec(
        "trivy", "trivy", "Supply chain",
        "Vulnerability, misconfiguration and secret scanner for containers and filesystems.",
        "https://trivy.dev", "Apache-2.0",
        ("--version",), kali_package="trivy", termux_package="trivy",
    ),
    ToolSpec(
        "grype", "grype", "Supply chain",
        "Container and filesystem vulnerability scanner backed by Anchore data.",
        "https://github.com/anchore/grype", "Apache-2.0",
        ("version",),
    ),
    ToolSpec(
        "syft", "syft", "Supply chain",
        "SBOM generator for container images and filesystems.",
        "https://github.com/anchore/syft", "Apache-2.0",
        ("version",),
    ),
    ToolSpec(
        "yara", "yara", "Malware",
        "Pattern-matching engine for classifying malware samples.",
        "https://virustotal.github.io/yara/", "BSD-3-Clause",
        ("--version",), kali_package="yara",
    ),
    ToolSpec(
        "clamav", "clamscan", "Malware",
        "Open-source antivirus engine and signature scanner.",
        "https://www.clamav.net", "GPL-2.0",
        ("--version",), kali_package="clamav", termux_package="clamav",
    ),
    ToolSpec(
        "gitleaks", "gitleaks", "Secrets",
        "Detects hard-coded secrets in git history and working trees.",
        "https://github.com/gitleaks/gitleaks", "MIT",
        ("version",), kali_package="gitleaks",
    ),
    ToolSpec(
        "semgrep", "semgrep", "Code",
        "Static analysis for many languages using pattern-based rules.",
        "https://semgrep.dev", "LGPL-2.1",
        ("--version",), kali_package="semgrep", termux_package="semgrep",
    ),
    ToolSpec(
        "bandit", "bandit", "Code",
        "Python-specific security linter.",
        "https://github.com/PyCQA/bandit", "Apache-2.0",
        ("--version",),
    ),
    ToolSpec(
        "ruff", "ruff", "Code",
        "Fast Python linter and formatter.",
        "https://docs.astral.sh/ruff/", "MIT",
        ("--version",),
    ),
    ToolSpec(
        "shellcheck", "shellcheck", "Code",
        "Static analysis for shell scripts.",
        "https://www.shellcheck.net", "GPL-3.0",
        ("--version",), kali_package="shellcheck", termux_package="shellcheck",
    ),
    ToolSpec(
        "openssl", "openssl", "Crypto",
        "TLS/SSL toolkit used here for certificate inspection.",
        "https://www.openssl.org", "Apache-2.0",
        ("version",), kali_package="openssl", termux_package="openssl",
    ),
    ToolSpec(
        "ssh-audit", "ssh-audit", "Crypto",
        "SSH server and client configuration auditor.",
        "https://github.com/jtesta/ssh-audit", "MIT",
        ("--version",),
    ),
    ToolSpec(
        "hashcat", "hashcat", "Crypto",
        "GPU password recovery; used here only for authorized strength testing.",
        "https://hashcat.net/hashcat/", "MIT",
        ("--version",), kali_package="hashcat", requires_root=True,
    ),
    ToolSpec(
        "john", "john", "Crypto",
        "John the Ripper password cracker.",
        "https://www.openwall.com/john/", "GPL-2.0",
        ("--version",), kali_package="john",
    ),
    ToolSpec(
        "hydra", "hydra", "Auth",
        "Network login brute-forcer; authorized engagements only.",
        "https://github.com/vanhauser-thc/thc-hydra", "AGPL-3.0",
        ("-h",), kali_package="hydra", active=True,
    ),
    ToolSpec(
        "aircrack-ng", "aircrack-ng", "Wireless",
        "802.11 security auditing suite.",
        "https://www.aircrack-ng.org", "GPL-2.0",
        ("--version",), kali_package="aircrack-ng", requires_root=True, active=True,
    ),
    ToolSpec(
        "bettercap", "bettercap", "Wireless",
        "Swiss-army knife for network and Wi-Fi reconnaissance.",
        "https://www.bettercap.org", "MIT",
        ("-version",), kali_package="bettercap", requires_root=True, active=True,
    ),
    ToolSpec(
        "kismet", "kismet", "Wireless",
        "Passive wireless detector, sniffer and IDS.",
        "https://www.kismetwireless.net", "GPL-2.0",
        ("--version",), kali_package="kismet", requires_root=True,
    ),
    ToolSpec(
        "whois", "whois", "OSINT",
        "Registry WHOIS client.",
        "https://github.com/rfc1036/whois", "GPL-2.0",
        ("--version",), kali_package="whois", termux_package="whois",
    ),
    ToolSpec(
        "dig", "dig", "OSINT",
        "DNS query tool from BIND.",
        "https://www.isc.org/bind/", "MPL-2.0",
        ("-v",), kali_package="dnsutils", termux_package="dnsutils",
    ),
    ToolSpec(
        "nslookup", "nslookup", "OSINT",
        "Simple DNS lookup utility.",
        "https://www.isc.org/bind/", "MPL-2.0",
        ("-version",), kali_package="dnsutils", termux_package="dnsutils",
    ),
    ToolSpec(
        "theHarvester", "theHarvester", "OSINT",
        "Gathers public emails, hosts and names for a target domain.",
        "https://github.com/laramies/theHarvester", "GPL-2.0",
        ("--version",), kali_package="theharvester", active=True,
    ),
    ToolSpec(
        "amass", "amass", "OSINT",
        "Subdomain enumeration from public sources.",
        "https://github.com/owasp-amass/amass", "Apache-2.0",
        ("-version",), kali_package="amass", active=True,
    ),
    ToolSpec(
        "subfinder", "subfinder", "OSINT",
        "Passive subdomain discovery.",
        "https://github.com/projectdiscovery/subfinder", "MIT",
        ("-version",), active=True,
    ),
    ToolSpec(
        "httpx", "httpx", "OSINT",
        "ProjectDiscovery HTTP probing toolkit.",
        "https://github.com/projectdiscovery/httpx", "MIT",
        ("-version",), active=True,
    ),
    ToolSpec(
        "nuclei", "nuclei", "Vulnerability",
        "Template-driven vulnerability scanner.",
        "https://github.com/projectdiscovery/nuclei", "MIT",
        ("-version",), active=True,
    ),
    ToolSpec(
        "searchsploit", "searchsploit", "Vulnerability",
        "Offline Exploit-DB search.",
        "https://www.exploit-db.com/searchsploit", "GPL-2.0",
        ("--version",), kali_package="exploitdb",
    ),
    ToolSpec(
        "metasploit", "msfconsole", "Vulnerability",
        "Metasploit Framework console.",
        "https://www.metasploit.com", "BSD-3-Clause",
        ("--version",), kali_package="metasploit-framework", requires_root=True,
    ),
    ToolSpec(
        "netdiscover", "netdiscover", "Network",
        "ARP-level host discovery for local networks.",
        "https://github.com/netdiscover-scanner/netdiscover", "GPL-3.0",
        ("--version",), kali_package="netdiscover", requires_root=True, active=True,
    ),
    ToolSpec(
        "arp-scan", "arp-scan", "Network",
        "ARP scan of the local subnet.",
        "https://github.com/royhills/arp-scan", "GPL-2.0",
        ("--version",), kali_package="arp-scan", requires_root=True, active=True,
    ),
    ToolSpec(
        "hping3", "hping3", "Network",
        "Craft and send arbitrary TCP/IP packets.",
        "https://github.com/antirez/hping", "GPL-2.0",
        ("--version",), kali_package="hping3", requires_root=True, active=True,
    ),
    ToolSpec(
        "iperf3", "iperf3", "Network",
        "Bandwidth and latency measurement between two hosts.",
        "https://software.es.net/iperf/", "BSD-3-Clause",
        ("--version",), kali_package="iperf3", termux_package="iperf3",
    ),
    ToolSpec(
        "dnsrecon", "dnsrecon", "DNS",
        "DNS enumeration and zone-transfer testing.",
        "https://github.com/darkoperator/dnsrecon", "GPL-2.0",
        ("--version",), kali_package="dnsrecon", active=True,
    ),
    ToolSpec(
        "dnsutils", "nslookup", "DNS",
        "BIND query utilities.",
        "https://www.isc.org/bind/", "MPL-2.0",
        ("-version",), kali_package="dnsutils", termux_package="dnsutils",
    ),
    ToolSpec(
        "fierce", "fierce", "DNS",
        "DNS reconnaissance and non-contiguous IP space discovery.",
        "https://github.com/mschwager/fierce", "GPL-3.0",
        ("--version",), kali_package="fierce", active=True,
    ),
    ToolSpec(
        "masscan", "masscan", "Network",
        "Very fast port scanner.",
        "https://github.com/robertdavidgraham/masscan", "AGPL-3.0",
        ("--version",), kali_package="masscan", requires_root=True, active=True,
    ),
    ToolSpec(
        "rustscan", "rustscan", "Network",
        "Fast port discovery front-end for nmap.",
        "https://github.com/bee-san/RustScan", "GPL-3.0",
        ("--version",), active=True,
    ),
    ToolSpec(
        "nbtscan", "nbtscan", "Network",
        "NetBIOS name scanning.",
        "https://github.com/resurrecting-open-source-projects/nbtscan", "GPL-2.0",
        ("-h",), kali_package="nbtscan", active=True,
    ),
    ToolSpec(
        "enum4linux", "enum4linux", "Network",
        "SMB and NetBIOS enumeration for Windows/Samba hosts.",
        "https://github.com/CiscoCXSecurity/enum4linux", "GPL-2.0",
        ("-h",), kali_package="enum4linux", active=True,
    ),
    ToolSpec(
        "smbclient", "smbclient", "Network",
        "SMB/CIFS client used for share enumeration.",
        "https://www.samba.org", "GPL-3.0",
        ("--version",), kali_package="smbclient", termux_package="smbclient", active=True,
    ),
    ToolSpec(
        "johnny", "johnny", "Crypto",
        "Qt front-end for John the Ripper.",
        "https://github.com/openwall/johnny", "GPL-2.0",
        ("--version",), kali_package="johnny",
    ),
    ToolSpec(
        "binwalk", "binwalk", "Forensics",
        "Firmware image analysis and embedded file extraction.",
        "https://github.com/ReFirmLabs/binwalk", "MIT",
        ("--version",), kali_package="binwalk", termux_package="binwalk",
    ),
    ToolSpec(
        "foremost", "foremost", "Forensics",
        "File carving from disk images.",
        "https://github.com/korczis/foremost", "Public domain",
        ("-V",), kali_package="foremost",
    ),
    ToolSpec(
        "sleuthkit", "fls", "Forensics",
        "The Sleuth Kit filesystem forensic tools.",
        "https://www.sleuthkit.org", "IBM Public License / CPL",
        ("-V",), kali_package="sleuthkit",
    ),
    ToolSpec(
        "autopsy", "autopsy", "Forensics",
        "Graphical digital forensics platform built on The Sleuth Kit.",
        "https://www.autopsy.com", "Apache-2.0",
        ("--version",), kali_package="autopsy",
    ),
    ToolSpec(
        "exiftool", "exiftool", "Forensics",
        "Read and write metadata in media files.",
        "https://exiftool.org", "Perl Artistic License",
        ("-ver",), kali_package="libimage-exiftool-perl", termux_package="perl",
    ),
    ToolSpec(
        "volatility", "volatility3", "Forensics",
        "Memory forensics framework.",
        "https://github.com/volatilityfoundation/volatility3", "VSL",
        ("--version",), kali_package="volatility3",
    ),
    ToolSpec(
        "radare2", "r2", "Reverse engineering",
        "Reverse engineering framework and disassembler.",
        "https://rada.re", "LGPL-3.0",
        ("-v",), kali_package="radare2", termux_package="radare2",
    ),
    ToolSpec(
        "ghidra", "ghidra", "Reverse engineering",
        "NSA software reverse engineering suite.",
        "https://ghidra-sre.org", "Apache-2.0",
        ("-version",), kali_package="ghidra",
    ),
    ToolSpec(
        "gdb", "gdb", "Reverse engineering",
        "GNU debugger.",
        "https://www.sourceware.org/gdb/", "GPL-3.0",
        ("--version",), kali_package="gdb", termux_package="gdb",
    ),
    ToolSpec(
        "strace", "strace", "Debugging",
        "Trace system calls and signals.",
        "https://strace.io", "LGPL-2.1",
        ("-V",), kali_package="strace", termux_package="strace", requires_root=True,
    ),
    ToolSpec(
        "ltrace", "ltrace", "Debugging",
        "Trace library calls.",
        "https://www.ltrace.org", "GPL-2.0",
        ("-V",), kali_package="ltrace",
    ),
    ToolSpec(
        "lsof", "lsof", "Monitoring",
        "List open files and the processes holding them.",
        "https://github.com/lsof-org/lsof", "lsof license",
        ("-v",), kali_package="lsof", termux_package="lsof",
    ),
    ToolSpec(
        "ss", "ss", "Monitoring",
        "Socket statistics; the modern replacement for netstat.",
        "https://github.com/iproute2/iproute2", "GPL-2.0",
        ("-V",), kali_package="iproute2", termux_package="iproute2",
    ),
    ToolSpec(
        "netstat", "netstat", "Monitoring",
        "Legacy socket and route listing.",
        "https://github.com/iproute2/iproute2", "GPL-2.0",
        ("--version",), kali_package="net-tools", termux_package="net-tools",
    ),
    ToolSpec(
        "htop", "htop", "Monitoring",
        "Interactive process viewer.",
        "https://htop.dev", "GPL-2.0",
        ("--version",), kali_package="htop", termux_package="htop",
    ),
    ToolSpec(
        "glances", "glances", "Monitoring",
        "Cross-platform system monitoring tool.",
        "https://nicolargo.github.io/glances/", "LGPL-3.0",
        ("--version",), kali_package="glances",
    ),
    ToolSpec(
        "file", "file", "Utilities",
        "Identify file types by magic bytes.",
        "https://www.darwinsys.com/file/", "BSD-2-Clause",
        ("--version",), kali_package="file", termux_package="file",
    ),
    ToolSpec(
        "jq", "jq", "Utilities",
        "Command-line JSON processor.",
        "https://jqlang.github.io/jq/", "MIT",
        ("--version",), kali_package="jq", termux_package="jq",
    ),
    ToolSpec(
        "curl", "curl", "Utilities",
        "HTTP client.",
        "https://curl.se", "curl license",
        ("--version",), kali_package="curl", termux_package="curl",
    ),
    ToolSpec(
        "git", "git", "Utilities",
        "Version control.",
        "https://git-scm.com", "GPL-2.0",
        ("--version",), kali_package="git", termux_package="git",
    ),
    ToolSpec(
        "python3", "python3", "Utilities",
        "Python 3 interpreter (the KINGDOM X runtime).",
        "https://www.python.org", "PSF-2.0",
        ("--version",), kali_package="python3", termux_package="python",
    ),
    ToolSpec(
        "pipx", "pipx", "Utilities",
        "Isolated Python application installer.",
        "https://pipx.pypa.io", "MIT",
        ("--version",),
    ),
    ToolSpec(
        "docker", "docker", "Containers",
        "Container runtime.",
        "https://www.docker.com", "Apache-2.0",
        ("--version",), kali_package="docker.io",
    ),
    ToolSpec(
        "podman", "podman", "Containers",
        "Daemonless container engine.",
        "https://podman.io", "Apache-2.0",
        ("--version",), kali_package="podman",
    ),
    ToolSpec(
        "kubectl", "kubectl", "Containers",
        "Kubernetes command-line client.",
        "https://kubernetes.io/docs/reference/kubectl/", "Apache-2.0",
        ("version", "--client"),
    ),
    ToolSpec(
        "helm", "helm", "Containers",
        "Kubernetes package manager.",
        "https://helm.sh", "Apache-2.0",
        ("version", "--short"),
    ),
    ToolSpec(
        "psql", "psql", "Database",
        "PostgreSQL interactive terminal.",
        "https://www.postgresql.org", "PostgreSQL License",
        ("--version",), kali_package="postgresql-client", termux_package="postgresql",
    ),
    ToolSpec(
        "mysql", "mysql", "Database",
        "MySQL/MariaDB client.",
        "https://mariadb.org", "GPL-2.0",
        ("--version",), kali_package="default-mysql-client", termux_package="mariadb",
    ),
    ToolSpec(
        "sqlite3", "sqlite3", "Database",
        "SQLite command-line shell.",
        "https://sqlite.org", "Public domain",
        ("--version",), kali_package="sqlite3", termux_package="sqlite",
    ),
    ToolSpec(
        "redis-cli", "redis-cli", "Database",
        "Redis client.",
        "https://redis.io", "RSALv2/SSPLv1",
        ("--version",), kali_package="redis-tools", termux_package="redis",
    ),
    ToolSpec(
        "mongosh", "mongosh", "Database",
        "MongoDB shell.",
        "https://www.mongodb.com/docs/mongodb-shell/", "SSPL",
        ("--version",),
    ),
    ToolSpec(
        "aws-cli", "aws", "Cloud",
        "Amazon Web Services CLI.",
        "https://aws.amazon.com/cli/", "Apache-2.0",
        ("--version",), kali_package="awscli",
    ),
    ToolSpec(
        "gcloud", "gcloud", "Cloud",
        "Google Cloud CLI.",
        "https://cloud.google.com/sdk", "Apache-2.0",
        ("--version",),
    ),
    ToolSpec(
        "az", "az", "Cloud",
        "Azure CLI.",
        "https://learn.microsoft.com/cli/azure/", "MIT",
        ("version",),
    ),
    ToolSpec(
        "terraform", "terraform", "Cloud",
        "Infrastructure-as-code tool.",
        "https://www.terraform.io", "BUSL-1.1",
        ("version",), kali_package="terraform",
    ),
    ToolSpec(
        "ansible", "ansible", "Automation",
        "Agentless configuration management.",
        "https://www.ansible.com", "GPL-3.0",
        ("--version",), kali_package="ansible",
    ),
    ToolSpec(
        "tor", "tor", "Privacy",
        "The Onion Router.",
        "https://www.torproject.org", "BSD-3-Clause",
        ("--version",), kali_package="tor", termux_package="tor",
    ),
    ToolSpec(
        "proxychains", "proxychains4", "Privacy",
        "Force TCP through a proxy chain.",
        "https://github.com/haad/proxychains", "GPL-2.0",
        ("--version",), kali_package="proxychains4", termux_package="proxychains-ng",
    ),
    ToolSpec(
        "gnupg", "gpg", "Privacy",
        "OpenPGP encryption and signing.",
        "https://gnupg.org", "GPL-3.0",
        ("--version",), kali_package="gnupg", termux_package="gnupg",
    ),
    ToolSpec(
        "age", "age", "Privacy",
        "Simple modern file encryption.",
        "https://github.com/FiloSottile/age", "BSD-3-Clause",
        ("--version",), kali_package="age", termux_package="age",
    ),
    ToolSpec(
        "nc", "nc", "Network",
        "Netcat: TCP/UDP Swiss army knife.",
        "https://nc110.sourceforge.io", "Public domain",
        ("-h",), kali_package="netcat-traditional", termux_package="netcat-openbsd",
    ),
    ToolSpec(
        "socat", "socat", "Network",
        "Multipurpose relay for bidirectional data transfer.",
        "http://www.dest-unreach.org/socat/", "GPL-2.0",
        ("-V",), kali_package="socat", termux_package="socat",
    ),
    ToolSpec(
        "traceroute", "traceroute", "Network",
        "Trace the path packets take to a host.",
        "https://traceroute.org", "GPL-2.0",
        ("--version",), kali_package="traceroute", termux_package="traceroute",
    ),
    ToolSpec(
        "mtr", "mtr", "Network",
        "Combined traceroute and ping.",
        "https://github.com/traviscross/mtr", "GPL-2.0",
        ("--version",), kali_package="mtr", termux_package="mtr",
    ),
    ToolSpec(
        "whois-lookup", "whois", "OSINT",
        "Registry lookup client (alias entry for the OSINT menu).",
        "https://github.com/rfc1036/whois", "GPL-2.0",
        ("--version",), kali_package="whois", termux_package="whois",
    ),
)


@dataclass
class ToolStatus:
    """What we actually found on this machine."""

    spec: ToolSpec
    present: bool
    path: str | None = None
    version: str | None = None
    platform_ok: bool = True
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.spec.name,
            "binary": self.spec.binary,
            "category": self.spec.category,
            "purpose": self.spec.purpose,
            "homepage": self.spec.homepage,
            "license": self.spec.license,
            "present": self.present,
            "path": self.path,
            "version": self.version,
            "platform_ok": self.platform_ok,
            "requires_root": self.spec.requires_root,
            "active": self.spec.active,
            "kali_package": self.spec.kali_package,
            "termux_package": self.spec.termux_package,
            "note": self.note,
        }

    @property
    def summary(self) -> str:
        if not self.present:
            return "not installed"
        if self.version:
            return self.version
        return "installed (version unknown)"


def _first_line(text: str, limit: int = 120) -> str:
    for line in (text or "").splitlines():
        clean = line.strip()
        if clean:
            return clean[:limit]
    return ""


def read_version(
    binary: str,
    args: Sequence[str] = ("--version",),
    *,
    timeout: float = VERSION_TIMEOUT,
) -> str | None:
    """Run ``binary args`` and return the first output line, or None.

    Uses an argv list (never a shell string), drops the environment down to
    PATH so a hostile ``LD_PRELOAD`` cannot influence the probe, and caps output.
    """
    path = shutil.which(binary)
    if not path:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell
            [path, *args],
            capture_output=True,
            timeout=timeout,
            text=True,
            errors="replace",
            env={"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
    line = _first_line(combined)
    if not line:
        return None
    # Trim noisy prefixes some tools print.
    line = re.sub(r"^(?:[A-Za-z0-9_.\-]+ version\s+)", "", line, flags=re.IGNORECASE)
    return line


def detect_tool(spec: ToolSpec, *, read_versions: bool = True) -> ToolStatus:
    """Report whether one tool is present on this machine."""
    platform = current_platform()
    platform_ok = (
        not spec.platforms or platform.family in spec.platforms
    )
    path = shutil.which(spec.binary)
    if not path:
        note = ""
        if not platform_ok:
            note = f"not supported on {platform.label}"
        elif platform.is_termux and not spec.termux_package:
            note = "no known Termux package"
        return ToolStatus(spec=spec, present=False, platform_ok=platform_ok, note=note)

    version = read_version(spec.binary, spec.version_args) if read_versions else None
    note = ""
    if spec.requires_root and not platform.is_root and not platform.is_termux:
        note = "needs sudo for most operations"
    return ToolStatus(
        spec=spec,
        present=True,
        path=path,
        version=version,
        platform_ok=platform_ok,
        note=note,
    )


def detect_all(
    *,
    category: str | None = None,
    read_versions: bool = True,
    only_present: bool = False,
) -> list[ToolStatus]:
    """Detect every catalogued tool (optionally filtered)."""
    wanted = (category or "").strip().lower()
    results: list[ToolStatus] = []
    for spec in TOOLS:
        if wanted and spec.category.lower() != wanted and spec.name.lower() != wanted:
            continue
        status = detect_tool(spec, read_versions=read_versions)
        if only_present and not status.present:
            continue
        results.append(status)
    return sorted(results, key=lambda s: (not s.present, s.spec.category, s.spec.name))


def categories() -> list[str]:
    return sorted({spec.category for spec in TOOLS})


def find_tool(name: str) -> ToolSpec | None:
    needle = (name or "").strip().lower()
    for spec in TOOLS:
        if spec.name.lower() == needle or spec.binary.lower() == needle:
            return spec
    return None


def search(term: str) -> list[ToolSpec]:
    needle = (term or "").strip().lower()
    if not needle:
        return list(TOOLS)
    return [
        spec
        for spec in TOOLS
        if needle in spec.name.lower()
        or needle in spec.purpose.lower()
        or needle in spec.category.lower()
    ]


def install_hint(spec: ToolSpec) -> str:
    """Platform-appropriate install command, or an honest 'unavailable'."""
    platform = current_platform()
    if platform.is_termux:
        if spec.termux_package:
            return f"pkg install {spec.termux_package}"
        return f"No known Termux package for {spec.name}; build from {spec.homepage}"
    if platform.family in {"kali", "parrot", "debian", "ubuntu"} and spec.kali_package:
        return f"sudo apt install -y {spec.kali_package}"
    return f"See {spec.homepage}"


def inventory_summary() -> dict[str, Any]:
    """Counts by category, based on real detection."""
    statuses = detect_all(read_versions=False)
    present = [s for s in statuses if s.present]
    by_category: dict[str, dict[str, int]] = {}
    for status in statuses:
        bucket = by_category.setdefault(status.spec.category, {"present": 0, "total": 0})
        bucket["total"] += 1
        if status.present:
            bucket["present"] += 1
    return {
        "total_catalogued": len(statuses),
        "present": len(present),
        "absent": len(statuses) - len(present),
        "by_category": by_category,
        "active_tools_present": [s.spec.name for s in present if s.spec.active],
        "root_required_present": [s.spec.name for s in present if s.spec.requires_root],
    }
