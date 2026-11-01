"""Module registry — the single source of truth for what actually works.

Every advertised capability appears here with an explicit status. The terminal
menu, the web dashboard and the API all read from this registry, so a feature
cannot be presented as available unless it is registered as ``WORKING`` and its
import path resolves at runtime.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable

from kingdomx.core.platform_detect import current as current_platform


class Status(str, Enum):
    """Honest capability states."""

    WORKING = "WORKING"
    PARTIAL = "PARTIAL"
    PLANNED = "PLANNED"
    UNAVAILABLE = "UNAVAILABLE"
    NEEDS_KEY = "NEEDS_KEY"
    NEEDS_NETWORK = "NEEDS_NETWORK"
    NEEDS_AUTHZ = "NEEDS_AUTHZ"

    @property
    def marker(self) -> str:
        return {
            Status.WORKING: "●",
            Status.PARTIAL: "◐",
            Status.PLANNED: "○",
            Status.UNAVAILABLE: "×",
            Status.NEEDS_KEY: "◆",
            Status.NEEDS_NETWORK: "◇",
            Status.NEEDS_AUTHZ: "▲",
        }[self]

    @property
    def label(self) -> str:
        return {
            Status.WORKING: "WORKING",
            Status.PARTIAL: "PARTIAL",
            Status.PLANNED: "PLANNED",
            Status.UNAVAILABLE: "UNAVAILABLE",
            Status.NEEDS_KEY: "NEEDS API KEY",
            Status.NEEDS_NETWORK: "NEEDS NETWORK",
            Status.NEEDS_AUTHZ: "NEEDS AUTHORIZATION",
        }[self]

    @property
    def is_live(self) -> bool:
        return self in {
            Status.WORKING,
            Status.PARTIAL,
            Status.NEEDS_KEY,
            Status.NEEDS_NETWORK,
            Status.NEEDS_AUTHZ,
        }


@dataclass
class Module:
    """One registered capability."""

    key: str
    title: str
    section: str
    status: Status
    summary: str
    module_path: str | None = None
    entry: str | None = None
    platform_families: tuple[str, ...] = ()
    """Empty means every platform. Otherwise only these may report WORKING."""
    needs_network: bool = False
    needs_key: str | None = None
    needs_root: bool = False
    destructive: bool = False
    notes: str = ""
    verified_by: str = ""
    """Where the evidence lives — a test file or a doc section."""
    extra: dict[str, Any] = field(default_factory=dict)

    def resolve(self) -> Callable[..., Any] | None:
        """Import the entry callable, or None when it cannot be loaded."""
        if not self.module_path:
            return None
        try:
            target = importlib.import_module(self.module_path)
        except Exception:  # noqa: BLE001 - import errors are data here
            return None
        if not self.entry:
            return None
        func = getattr(target, self.entry, None)
        return func if callable(func) else None

    def effective_status(self) -> Status:
        """Status after platform and runtime checks."""
        plat = current_platform()
        if self.platform_families and plat.family not in self.platform_families:
            return Status.UNAVAILABLE
        if self.needs_root and not plat.is_root and not plat.is_termux:
            return Status.PARTIAL
        if self.status in {Status.PLANNED, Status.UNAVAILABLE}:
            return self.status
        if self.module_path and self.resolve() is None:
            return Status.PLANNED
        return self.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "section": self.section,
            "status": self.status.value,
            "effective_status": self.effective_status().value,
            "summary": self.summary,
            "module_path": self.module_path,
            "platform_families": list(self.platform_families),
            "needs_network": self.needs_network,
            "needs_key": self.needs_key,
            "needs_root": self.needs_root,
            "destructive": self.destructive,
            "notes": self.notes,
            "verified_by": self.verified_by,
        }


class Registry:
    """Ordered collection of modules grouped by menu section."""

    def __init__(self) -> None:
        self._modules: dict[str, Module] = {}

    def register(self, module: Module) -> Module:
        if module.key in self._modules:
            raise ValueError(f"duplicate module key: {module.key}")
        self._modules[module.key] = module
        return module

    def get(self, key: str) -> Module | None:
        return self._modules.get(key)

    def require(self, key: str) -> Module:
        module = self.get(key)
        if module is None:
            raise KeyError(f"unknown module: {key}")
        return module

    def all(self) -> list[Module]:
        return list(self._modules.values())

    def by_section(self) -> dict[str, list[Module]]:
        grouped: dict[str, list[Module]] = {}
        for module in self._modules.values():
            grouped.setdefault(module.section, []).append(module)
        return grouped

    def with_status(self, *statuses: Status) -> list[Module]:
        wanted = set(statuses)
        return [m for m in self._modules.values() if m.effective_status() in wanted]

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {status.value: 0 for status in Status}
        for module in self._modules.values():
            counts[module.effective_status().value] += 1
        counts["total"] = len(self._modules)
        return counts

    def search(self, term: str) -> list[Module]:
        needle = (term or "").strip().lower()
        if not needle:
            return self.all()
        scored: list[tuple[int, Module]] = []
        for module in self._modules.values():
            haystack = f"{module.key} {module.title} {module.summary} {module.section}".lower()
            if needle in module.key.lower():
                scored.append((0, module))
            elif needle in module.title.lower():
                scored.append((1, module))
            elif needle in haystack:
                scored.append((2, module))
        return [module for _score, module in sorted(scored, key=lambda pair: pair[0])]


#: The process-wide registry.
REGISTRY = Registry()


def register(
    key: str,
    title: str,
    section: str,
    status: Status,
    summary: str,
    *,
    module_path: str | None = None,
    entry: str | None = None,
    platform_families: Iterable[str] = (),
    needs_network: bool = False,
    needs_key: str | None = None,
    needs_root: bool = False,
    destructive: bool = False,
    notes: str = "",
    verified_by: str = "",
    extra: dict[str, Any] | None = None,
) -> Module:
    """Convenience wrapper around :data:`REGISTRY`."""
    return REGISTRY.register(
        Module(
            key=key,
            title=title,
            section=section,
            status=status,
            summary=summary,
            module_path=module_path,
            entry=entry,
            platform_families=tuple(platform_families),
            needs_network=needs_network,
            needs_key=needs_key,
            needs_root=needs_root,
            destructive=destructive,
            notes=notes,
            verified_by=verified_by,
            extra=dict(extra or {}),
        )
    )


# --------------------------------------------------------------------------- menu
MENU_SECTIONS: tuple[tuple[int, str, str], ...] = (
    (1, "AI INTELLIGENCE CENTER", "ai"),
    (2, "CYBERSECURITY CENTER", "cyber"),
    (3, "GLOBAL DEVICE INTELLIGENCE", "devices"),
    (4, "MOBILE INTELLIGENCE", "mobile"),
    (5, "PHONE NUMBER INTELLIGENCE", "phone"),
    (6, "COMPUTER INTELLIGENCE", "computers"),
    (7, "WEBSITE INTELLIGENCE", "websites"),
    (8, "DOMAIN INTELLIGENCE", "domains"),
    (9, "IP & NETWORK INTELLIGENCE", "network"),
    (10, "DNS INTELLIGENCE", "dns"),
    (11, "CLOUD & SERVER CENTER", "cloud"),
    (12, "API INTELLIGENCE CENTER", "apis"),
    (13, "DIGITAL FORENSICS", "forensics"),
    (14, "MALWARE ANALYSIS", "malware"),
    (15, "VULNERABILITY INTELLIGENCE", "vulnerabilities"),
    (16, "OSINT CENTER", "osint"),
    (17, "GLOBAL TOOL DIRECTORY", "tools"),
    (18, "AI MODEL MANAGER", "models"),
    (19, "PROGRAMMING CENTER", "programming"),
    (20, "DATABASE CENTER", "databases"),
    (21, "AUTOMATION CENTER", "automation"),
    (22, "PLUGIN MARKETPLACE", "plugins"),
    (23, "REPORTS & ANALYTICS", "reports"),
    (24, "SYSTEM DIAGNOSTICS", "monitoring"),
    (25, "SETTINGS & CONFIGURATION", "settings"),
)

SECTION_TITLES: dict[str, str] = {key: title for _num, title, key in MENU_SECTIONS}


def menu_entries() -> list[tuple[str, str, str, int]]:
    """(number, title, section, live_module_count) for the main menu."""
    grouped = REGISTRY.by_section()
    out: list[tuple[str, str, str, int]] = []
    for number, title, key in MENU_SECTIONS:
        modules = grouped.get(key, [])
        live = sum(1 for m in modules if m.effective_status().is_live)
        out.append((f"{number:02d}", title, key, live))
    return out


# --------------------------------------------------------------------------- the catalogue
#
# Registration below is the honest inventory. A module is WORKING only when its
# code exists in this repository *and* its callable imports at runtime. Modules
# that need an API key, internet access or written authorization say so with the
# matching status. Everything not built yet is PLANNED with a roadmap note — it
# is never dressed up as available.


def _register_all() -> None:
    """Populate :data:`REGISTRY`. Called once at import time."""

    # ---- core -------------------------------------------------------------
    register(
        "core.platform", "Platform detection", "settings", Status.WORKING,
        "Detects Kali, Parrot, Debian, Ubuntu, Termux, macOS and Windows, plus root state.",
        module_path="kingdomx.core.platform_detect", entry="current",
        verified_by="tests/test_core.py",
    )
    register(
        "core.config", "Configuration store", "settings", Status.WORKING,
        "Layered config (defaults → file → env → CLI) with an encrypted secret vault.",
        module_path="kingdomx.core.config", entry="Config",
        verified_by="tests/test_core.py",
    )
    register(
        "core.validation", "Input validation", "settings", Status.WORKING,
        "Domain, URL, host, IP and port validation, including SSRF target checks.",
        module_path="kingdomx.core.validation", entry="validate_domain",
        verified_by="tests/test_core.py",
    )
    register(
        "core.http", "SSRF-guarded HTTP client", "settings", Status.WORKING,
        "Every outbound request is checked against private ranges before it is sent.",
        module_path="kingdomx.core.http", entry="SafeHttpClient",
        verified_by="tests/test_core.py",
    )
    register(
        "core.storage", "SQLite storage", "settings", Status.WORKING,
        "Migrated schema, parameterised queries, audit log, provider and usage tables.",
        module_path="kingdomx.core.storage", entry="Database",
        verified_by="tests/test_storage.py",
    )
    register(
        "core.registry", "Module registry", "settings", Status.WORKING,
        "Single source of truth for what is WORKING, PLANNED or unavailable." ,
        module_path="kingdomx.core.registry", entry="menu_entries",
        verified_by="tests/test_registry.py",
    )
    register(
        "core.authorization", "Authorization gate", "settings", Status.WORKING,
        "Active operations require a recorded, target-specific written authorization.",
        module_path="kingdomx.core.authorization", entry="require_authorization",
        verified_by="tests/test_authorization.py",
    )
    register(
        "core.redaction", "Secret redaction", "settings", Status.WORKING,
        "Strips API keys, tokens and passwords from logs, reports and error output.",
        module_path="kingdomx.core.redaction", entry="redact_text",
        verified_by="tests/test_redaction.py",
    )

    # ---- AI ---------------------------------------------------------------
    register(
        "ai.catalog", "AI provider catalogue", "ai", Status.WORKING,
        "10 providers across 4 wire protocols: OpenAI, Gemini, Anthropic, DeepSeek, "
        "Mistral, Groq, Together, OpenRouter, Ollama, Hugging Face.",
        module_path="kingdomx.ai.catalog", entry="all_specs",
        verified_by="tests/test_ai.py",
    )
    register(
        "ai.client", "Request builder and parser", "ai", Status.WORKING,
        "Builds and parses each protocol's payload; tested offline against fixtures.",
        module_path="kingdomx.ai.client", entry="build_request",
        verified_by="tests/test_ai.py",
    )
    register(
        "ai.health", "Provider health checks", "ai", Status.WORKING,
        "A model is only reported available after a real, timestamped check.",
        module_path="kingdomx.ai.health", entry="check_provider",
        needs_network=True, verified_by="tests/test_ai.py",
    )
    register(
        "ai.manager", "Model registry and usage", "models", Status.WORKING,
        "Provider CRUD, per-model verification, token usage accounting, comparison runs.",
        module_path="kingdomx.ai.manager", entry="AIManager",
        verified_by="tests/test_ai.py",
    )
    register(
        "ai.chat", "AI chat assistant", "ai", Status.NEEDS_KEY,
        "Real completions against the configured provider. Requires an API key or Ollama.",
        module_path="kingdomx.ai.assistant", entry="Assistant",
        needs_key="provider key or local Ollama", needs_network=True,
        verified_by="manual (requires a key)",
    )
    register(
        "ai.local_fallback", "Offline rule engine", "ai", Status.WORKING,
        "Answers a small set of questions deterministically when no model is reachable, "
        "and labels the answer as local rather than model output.",
        module_path="kingdomx.ai.assistant", entry="local_answer",
        verified_by="tests/test_ai.py",
    )

    # ---- cybersecurity ----------------------------------------------------
    register(
        "cyber.tools", "Installed tool detection", "cyber", Status.WORKING,
        "Detects 85+ security tools by real PATH lookup and version probe.",
        module_path="kingdomx.cybersecurity.tools", entry="detect_all",
        verified_by="tests/test_cyber.py",
    )
    register(
        "cyber.headers", "Security header audit", "cyber", Status.NEEDS_NETWORK,
        "Grades HSTS, CSP, X-Frame-Options, cookie flags and version disclosure.",
        module_path="kingdomx.cybersecurity.headers", entry="audit_headers",
        needs_network=True, verified_by="tests/test_cyber.py",
    )
    register(
        "cyber.tls", "TLS certificate inspection", "cyber", Status.NEEDS_NETWORK,
        "Real handshake: protocol, cipher, issuer, SAN coverage, expiry days.",
        module_path="kingdomx.cybersecurity.tls", entry="inspect_certificate",
        needs_network=True, verified_by="tests/test_cyber.py",
    )
    register(
        "cyber.passwords", "Password strength audit", "cyber", Status.WORKING,
        "Entropy estimate plus pattern penalties, entirely local. Never transmits the value.",
        module_path="kingdomx.cybersecurity.passwords", entry="analyse",
        verified_by="tests/test_cyber.py",
    )
    register(
        "cyber.integrity", "File integrity monitoring", "cyber", Status.WORKING,
        "SHA-256 manifests with added/removed/modified/permission diffing.",
        module_path="kingdomx.cybersecurity.integrity", entry="integrity_report",
        verified_by="tests/test_cyber.py",
    )
    register(
        "cyber.dependencies", "Dependency scanning", "cyber", Status.WORKING,
        "Parses requirements.txt, package.json, go.mod, Cargo.toml, pyproject.toml; "
        "local advisory cache, optional live OSV query.",
        module_path="kingdomx.cybersecurity.dependencies", entry="scan_directory",
        verified_by="tests/test_cyber.py",
    )
    register(
        "cyber.logs", "Log analysis", "cyber", Status.WORKING,
        "Syslog and ISO formats; brute-force, sudo, OOM, segfault and disk-full detection.",
        module_path="kingdomx.cybersecurity.logs", entry="analyse_path",
        verified_by="tests/test_cyber.py",
    )
    register(
        "cyber.audit", "Linux host audit", "cyber", Status.WORKING,
        "15 read-only checks: SSH config, firewall, permissions, ASLR, MAC, time sync.",
        module_path="kingdomx.cybersecurity.audit", entry="run_audit",
        verified_by="tests/test_cyber.py",
    )
    register(
        "cyber.ports", "Port knowledge base", "cyber", Status.WORKING,
        "80 curated ports with service, transport and real exposure risk.",
        module_path="kingdomx.cybersecurity.ports", entry="describe_port",
        verified_by="tests/test_cyber.py",
    )

    # ---- intelligence -----------------------------------------------------
    register(
        "dns.lookup", "DNS resolution", "dns", Status.NEEDS_NETWORK,
        "dnspython backend for A/AAAA/MX/TXT/NS/SOA/CAA/SRV/PTR/DS, socket fallback.",
        module_path="kingdomx.dns.lookup", entry="lookup",
        needs_network=True, verified_by="tests/test_dns.py",
    )
    register(
        "dns.diagnose", "DNS diagnostics", "dns", Status.NEEDS_NETWORK,
        "NS, SOA, addressing, MX, SPF, DMARC, CAA, wildcard and MX-target checks.",
        module_path="kingdomx.dns.lookup", entry="diagnose",
        needs_network=True, verified_by="tests/test_dns.py",
    )
    register(
        "dns.axfr", "Zone transfer test", "dns", Status.NEEDS_NETWORK,
        "Attempts AXFR per nameserver; a refusal is the correct result and is reported as such.",
        module_path="kingdomx.dns.lookup", entry="zone_transfer",
        needs_network=True, verified_by="manual (needs a live nameserver)",
    )
    register(
        "ip.classify", "IP classification", "network", Status.WORKING,
        "Offline: global/private/loopback/CGNAT/multicast/reserved plus reverse DNS.",
        module_path="kingdomx.ip.intel", entry="classify",
        verified_by="tests/test_ip.py",
    )
    register(
        "ip.geo", "IP geolocation", "network", Status.NEEDS_NETWORK,
        "Approximate location and ASN from ip-api.com, with provider and fetch time recorded.",
        module_path="kingdomx.ip.intel", entry="geolocate",
        needs_network=True, verified_by="tests/test_ip.py",
    )
    register(
        "ip.rdap", "IP registry data", "network", Status.NEEDS_NETWORK,
        "RDAP network block, holder entities and status for a public address.",
        module_path="kingdomx.ip.intel", entry="rdap_network",
        needs_network=True, verified_by="manual (requires the RDAP service)",
    )
    register(
        "ip.latency", "Latency measurement", "network", Status.NEEDS_NETWORK,
        "TCP handshake timing to well-known resolvers; min/avg/max/jitter.",
        module_path="kingdomx.ip.intel", entry="latency_test",
        needs_network=True, verified_by="tests/test_ip.py",
    )
    register(
        "domains.rdap", "Domain registry lookup", "domains", Status.NEEDS_NETWORK,
        "RDAP: registrar, creation/expiry dates, status codes, nameservers, DNSSEC.",
        module_path="kingdomx.domains.rdap", entry="rdap_lookup",
        needs_network=True, verified_by="tests/test_domains.py",
    )
    register(
        "domains.homograph", "Homograph detection", "domains", Status.WORKING,
        "Flags IDN and mixed-script labels and shows the skeleton form. Offline.",
        module_path="kingdomx.domains.rdap", entry="homograph_check",
        verified_by="tests/test_domains.py",
    )
    register(
        "websites.audit", "Website audit", "websites", Status.NEEDS_NETWORK,
        "One fetch: status, headers, TLS, technology fingerprints with cited evidence.",
        module_path="kingdomx.websites.audit", entry="audit_website",
        needs_network=True, verified_by="tests/test_websites.py",
    )
    register(
        "websites.fingerprint", "Technology fingerprinting", "websites", Status.WORKING,
        "50+ signatures matched against real header, cookie and body evidence.",
        module_path="kingdomx.websites.audit", entry="fingerprint",
        verified_by="tests/test_websites.py",
    )
    register(
        "websites.availability", "Availability check", "websites", Status.NEEDS_NETWORK,
        "Repeated real requests with per-attempt latency and a clear up/down verdict.",
        module_path="kingdomx.websites.audit", entry="availability_check",
        needs_network=True, verified_by="manual (requires a live URL)",
    )
    register(
        "network.local", "Local network state", "network", Status.WORKING,
        "Listeners, connections, routes, interfaces and the ARP cache, read-only.",
        module_path="kingdomx.network.local", entry="listening_ports",
        verified_by="tests/test_network.py",
    )
    register(
        "network.scan", "Authorized port scan", "network", Status.NEEDS_AUTHZ,
        "Three allow-listed nmap profiles. Requires recorded written authorization.",
        module_path="kingdomx.network.scan", entry="authorize_and_scan",
        needs_root=False, verified_by="tests/test_network.py",
    )
    register(
        "network.nmap_parse", "nmap output parser", "network", Status.WORKING,
        "Parses nmap XML into structured results; separated so it is testable offline.",
        module_path="kingdomx.network.scan", entry="parse_nmap_output",
        verified_by="tests/test_network.py",
    )
    register(
        "computers.system", "System diagnostics", "computers", Status.WORKING,
        "CPU, memory, disks, uptime, load and health verdicts from /proc and psutil.",
        module_path="kingdomx.computers.system", entry="collect",
        verified_by="tests/test_computers.py",
    )
    register(
        "computers.packages", "Package inventory", "computers", Status.WORKING,
        "Installed package list from pkg (Termux), dpkg or rpm.",
        module_path="kingdomx.computers.system", entry="installed_packages",
        verified_by="tests/test_computers.py",
    )
    register(
        "phone.numbering", "Phone numbering plans", "phone", Status.WORKING,
        "Country code, structural validity, line type and formatting for 21 documented plans.",
        module_path="kingdomx.phone.numbering", entry="parse_number",
        verified_by="tests/test_phone.py",
    )
    register(
        "devices.catalog", "Device reference catalogue", "devices", Status.WORKING,
        "16 manufacturers, 14 models, Android release table — each row carries provenance.",
        module_path="kingdomx.devices.catalog", entry="catalog_summary",
        verified_by="tests/test_devices.py",
    )
    register(
        "devices.classify", "Device classification", "devices", Status.WORKING,
        "User-Agent parsing into category, OS and browser with the matching token as evidence.",
        module_path="kingdomx.devices.catalog", entry="classify_device",
        verified_by="tests/test_devices.py",
    )
    register(
        "globaltech.datasets", "Global technology datasets", "devices", Status.WORKING,
        "Country infrastructure, cloud regions, AI providers, languages — all with "
        "source, as_of, coverage, confidence and limitations.",
        module_path="kingdomx.globaltech.intel", entry="registry_summary",
        verified_by="tests/test_globaltech.py",
    )
    register(
        "tools.directory", "Global tool directory", "tools", Status.WORKING,
        "85+ legitimate tools with official URL, licence, platform packages and "
        "platform-appropriate install command.",
        module_path="kingdomx.cybersecurity.tools", entry="detect_all",
        verified_by="tests/test_cyber.py",
    )

    # ---- operations -------------------------------------------------------
    register(
        "reports.export", "Report export", "reports", Status.WORKING,
        "JSON, CSV, Markdown and text exporters with provenance and redaction.",
        module_path="kingdomx.reports.export", entry="save_report",
        verified_by="tests/test_reports.py",
    )
    register(
        "plugins.loader", "Plugin system", "plugins", Status.WORKING,
        "Manifest validation, permission allow-list, sandboxed subprocess execution.",
        module_path="kingdomx.plugins.loader", entry="run_plugin",
        verified_by="tests/test_plugins.py",
    )
    register(
        "automation.scheduler", "Task scheduler", "automation", Status.WORKING,
        "Persisted interval tasks with run history; fired explicitly, no daemon.",
        module_path="kingdomx.automation.scheduler", entry="run_due",
        verified_by="tests/test_automation.py",
    )
    register(
        "automation.executor", "Allow-listed actions", "automation", Status.WORKING,
        "Eight named actions. There is no shell path, by design.",
        module_path="kingdomx.automation.executor", entry="run_action",
        verified_by="tests/test_automation.py",
    )
    register(
        "monitoring.health", "System health monitoring", "monitoring", Status.WORKING,
        "Threshold-based health verdicts for memory, disk and load.",
        module_path="kingdomx.computers.system", entry="health_report",
        verified_by="tests/test_computers.py",
    )

    # ---- CLI and web ------------------------------------------------------
    register(
        "cli.main", "Terminal command center", "settings", Status.WORKING,
        "Rich-based menu, module status board, JSON output mode.",
        module_path="kingdomx.cli.main", entry="main",
        verified_by="tests/test_cli.py",
    )
    register(
        "web.app", "Web dashboard", "monitoring", Status.WORKING,
        "FastAPI dashboard serving module status and read-only diagnostics.",
        module_path="kingdomx.web.app", entry="create_app",
        verified_by="tests/test_web.py",
    )

    # ---- PLANNED: honest roadmap entries ----------------------------------
    planned: tuple[tuple[str, str, str, str, str], ...] = (
        ("cyber.api_security", "API Security", "cyber",
         "No OpenAPI/GraphQL security analyser is implemented. Header and TLS checks apply to an API endpoint, but nothing parses a spec to find broken object-level authorization, mass assignment or excessive data exposure.",
         "Parse OpenAPI 3 and GraphQL schemas; lint for BOLA/BFLA patterns, missing schemas, and unconstrained query depth."),
        ("cyber.cloud_security", "Cloud Security", "cyber",
         "No cloud provider integration exists. There is no IAM policy evaluation, no S3 bucket public-access check, no security-group analysis.",
         "Add read-only credential profiles per provider and implement CIS Benchmark rule sets, starting with S3/GCS bucket ACLs and security groups."),
        ("cyber.container_security", "Container Security", "cyber",
         "Only detects whether trivy, grype, syft, docker or podman are installed. No image is pulled, scanned or inspected.",
         "Wrap trivy/grype when present, then add Dockerfile and Kubernetes manifest linting without pulling images."),
        ("cyber.supply_chain", "Supply Chain Security", "cyber",
         "Dependency scanning covers five manifest formats. There is no SBOM generation, no signature verification, no provenance attestation.",
         "Generate CycloneDX SBOMs via syft when installed; verify cosign signatures where an allow-list of keys is configured."),
        ("cyber.threat_intel", "Threat Intelligence", "cyber",
         "No IOC feed integration. No STIX/TAXII, no MISP, no blocklist subscriptions.",
         "Add a signed local IOC store plus connector interfaces for MISP and TAXII 2.1, with explicit allow-listing of sources."),
        ("cyber.malware", "Malware Analysis", "cyber",
         "Detects yara and clamscan if installed; does not ship rules, does not execute samples, has no sandbox.",
         "Bundle a curated YARA rule set, add static PE/ELF/APK triage (imports, entropy, strings) with no execution at all."),
        ("cyber.forensics", "Digital Forensics", "cyber",
         "Detects binwalk, foremost and The Sleuth Kit but implements no evidence handling, no chain-of-custody, no carving.",
         "Add read-only image mounting via The Sleuth Kit, hashing on acquisition, and a signed chain-of-custody log."),
        ("cyber.incident_response", "Incident Response", "cyber",
         "Log analysis and the host audit provide raw material, but there is no case management, no timeline assembly, no playbooks.",
         "Introduce a case file that aggregates findings, builds a unified timeline and records each response step with an audit trail."),
        ("cyber.compliance", "Security Compliance", "cyber",
         "The host audit produces findings but no mapping to CIS Controls, ISO 27001 or PCI DSS.",
         "Attach control identifiers to each audit check and generate a control-coverage matrix with explicit gaps."),
        ("cyber.knowledge", "Security Knowledge Center", "cyber",
         "Explanations exist inline as remediation text; there is no searchable knowledge base.",
         "Extract remediation text into a versioned, searchable knowledge base keyed by finding category, with references."),
        ("cyber.phishing", "Phishing Detection", "cyber",
         "Homograph detection exists. There is no URL reputation feed, no attachment analysis, no email-header parsing.",
         "Add SPF/DKIM/DMARC header validation for pasted raw messages and a heuristic URL scorer with no external reputation call."),
        ("cyber.endpoint", "Endpoint Security", "cyber",
         "Process listing and listening sockets only. No EDR, no behaviour monitoring, no persistence inspection.",
         "Add autostart/persistence enumeration (systemd units, cron, ~/.config/autostart) and compare against a baseline."),
        ("cyber.database_security", "Database Security", "cyber",
         "KINGDOM X audits its own SQLite schema; it does not audit an external database server.",
         "Add read-only PostgreSQL audit: role privileges, pg_hba.conf parsing, public schema grants, connection TLS."),
        ("cyber.android", "Android Security", "cyber",
         "Termux detection works, but there is no APK metadata inspection or permission analysis.",
         "Implement APK parsing with zipfile + androguard (optional): manifest permissions, exported components, debuggable flag, cleartext traffic."),
        ("cyber.mobile_app", "Mobile Application Security", "cyber",
         "Nothing implemented beyond noting the platform. No APK/IPA static analysis.",
         "Reuse the Android module's APK parser for a MASVS-aligned checklist; iOS is reference-only without a device."),
        ("cyber.reporting", "Security Reporting", "reports",
         "JSON/CSV/Markdown/text export exists; there is no PDF renderer and no executive summary layer.",
         "Render the Markdown report to PDF via a local engine, and generate a one-page executive summary from the severity counts."),
        ("cyber.defensive_automation", "Defensive Automation", "automation",
         "Eight allow-listed actions run on a schedule; nothing reacts to an event.",
         "Add rule-based triggers (e.g. new HIGH finding → queue a notification) with explicit operator approval before any block action."),
        ("osint.center", "OSINT Center", "osint",
         "RDAP, DNS and homograph lookups cover the technical side. No email, username or social-media search is implemented, and much of that domain is legally constrained.",
         "Add only lawful, publicly-documented sources: certificate transparency query, DNS history where licensed, and a documented refusal list for people-search sources."),
        ("vulnerability.intel", "Vulnerability Intelligence", "vulnerabilities",
         "The OSV batch API and a local advisory cache are wired. There is no CVE/NVD sync, no EPSS, no KEV tracking.",
         "Add a cached OSV download with delta sync, then EPSS scores and the CISA KEV list for prioritisation."),
        ("cloud.server_center", "Cloud and Server Center", "cloud",
         "Local server diagnostics exist. No cloud API is called and no remote server is managed.",
         "Add SSH-based read-only server audit using the existing host-audit checks, plus cloud metadata (regions, quotas) per provider."),
        ("api.center", "API Intelligence Center", "apis",
         "No public API catalogue, no request tester, no rate-limit monitor exists yet.",
         "Ship a catalogue of documented public APIs with health checks, plus a credential-scoped request tester that refuses to store secrets in plaintext."),
        ("programming.center", "Programming Center", "programming",
         "Only tool detection (ruff, bandit, semgrep, shellcheck) and the language reference table exist.",
         "Add per-language lint/format/test runners using detected tooling, with results normalised into the unified report format."),
        ("database.center", "Database Center", "databases",
         "KINGDOM X stores its own state in SQLite; there is no external database management.",
         "Add read-only PostgreSQL and Redis inspection: table sizes, slow queries, replica lag, key cardinality."),
        ("forensics.module", "Forensics Module", "forensics",
         "Not implemented. The tool directory lists forensic tools but none is orchestrated.",
         "See cyber.forensics — this entry exists so the menu section does not overstate coverage."),
        ("malware.module", "Malware Module", "malware",
         "Not implemented. See cyber.malware for the intended static-analysis-only roadmap.",
         "Static triage only; no sample execution."),
    )
    for key, title, section, notes, roadmap in planned:
        register(
            key, title, section, Status.PLANNED,
            notes,
            notes=f"ROADMAP: {roadmap}",
            verified_by="not implemented",
        )


_register_all()
