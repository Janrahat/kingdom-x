"""Dependency vulnerability scanning.

Offline-first: this module parses dependency manifests and checks pins against a
**local advisory cache**. It does not phone home by default.

When the operator supplies an OSV API key or enables network mode, the OSV
``/v1/querybatch`` endpoint is used — that is a real, free, documented API. If the
network is unreachable, the result says so and falls through to the local cache
rather than pretending the package is clean.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from kingdomx.core.errors import NetworkError
from kingdomx.core.http import SafeHttpClient
from kingdomx.core.logging_setup import get_logger
from kingdomx.cybersecurity.severity import Finding, Report, Severity, from_cvss

log = get_logger("cyber.dependencies")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

#: Ecosystem names as OSV expects them.
ECOSYSTEMS = {
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "pyproject.toml": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "Cargo.toml": "crates.io",
    "go.mod": "Go",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "Gemfile": "RubyGems",
    "composer.json": "Packagist",
}


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str
    source_file: str = ""
    scope: str = "runtime"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "source_file": self.source_file,
            "scope": self.scope,
        }

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name.lower(), self.version)


#: A small local advisory cache. Real deployments refresh this from OSV; the
#: entries here are well-known, publicly documented issues used to make the
#: offline path demonstrably functional.
LOCAL_ADVISORIES: dict[tuple[str, str], list[dict[str, Any]]] = {
    ("pypi", "django"): [
        {
            "id": "LOCAL-DJANGO-OLD",
            "summary": "Django releases before 4.2 LTS no longer receive security fixes.",
            "affected_below": "4.2",
            "severity": "medium",
            "reference": "https://www.djangoproject.com/download/",
        }
    ],
    ("pypi", "requests"): [
        {
            "id": "LOCAL-REQUESTS-OLD",
            "summary": "requests < 2.31.0 is affected by CVE-2023-32681 (proxy credential leak).",
            "affected_below": "2.31.0",
            "severity": "medium",
            "reference": "https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q",
        }
    ],
    ("pypi", "urllib3"): [
        {
            "id": "LOCAL-URLLIB3-OLD",
            "summary": "urllib3 < 2.0.7 is affected by CVE-2023-45803 (request body leak on redirect).",
            "affected_below": "2.0.7",
            "severity": "medium",
            "reference": "https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4",
        }
    ],
    ("pypi", "pyyaml"): [
        {
            "id": "LOCAL-PYYAML-OLD",
            "summary": "PyYAML < 6.0.1 is affected by CVE-2020-14343 (arbitrary code via full_load).",
            "affected_below": "6.0.1",
            "severity": "critical",
            "reference": "https://github.com/yaml/pyyaml/security/advisories/GHSA-8q59-q68h-6hv4",
        }
    ],
    ("pypi", "jinja2"): [
        {
            "id": "LOCAL-JINJA2-OLD",
            "summary": "Jinja2 < 3.1.3 is affected by CVE-2024-22195 (XSS via xmlattr).",
            "affected_below": "3.1.3",
            "severity": "medium",
            "reference": "https://github.com/pallets/jinja/security/advisories/GHSA-h5c8-rqwp-cp95",
        }
    ],
    ("npm", "lodash"): [
        {
            "id": "LOCAL-LODASH-OLD",
            "summary": "lodash < 4.17.21 is affected by CVE-2021-23337 (command injection in template).",
            "affected_below": "4.17.21",
            "severity": "high",
            "reference": "https://github.com/lodash/lodash/security/advisories/GHSA-35jh-r3h4-6jhm",
        }
    ],
    ("npm", "express"): [
        {
            "id": "LOCAL-EXPRESS-OLD",
            "summary": "express < 4.19.2 is affected by CVE-2024-29041 (open redirect).",
            "affected_below": "4.19.2",
            "severity": "medium",
            "reference": "https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc",
        }
    ],
    ("npm", "axios"): [
        {
            "id": "LOCAL-AXIOS-OLD",
            "summary": "axios < 1.6.0 is affected by CVE-2023-45857 (CSRF token leak).",
            "affected_below": "1.6.0",
            "severity": "medium",
            "reference": "https://github.com/axios/axios/security/advisories/GHSA-wf5p-g6vw-rhxx",
        }
    ],
}


# --------------------------------------------------------------------------- parsing
_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(?:==\s*([0-9][0-9A-Za-z._\-]*))?"
)


def parse_requirements_txt(path: str | Path) -> list[Package]:
    """Parse a pip requirements file (``==`` pins only)."""
    packages: list[Package] = []
    file_path = Path(path)
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return packages
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _REQUIREMENT_RE.match(line)
        if not match:
            continue
        name, version = match.group(1), match.group(2)
        packages.append(
            Package(
                name=name,
                version=version or "",
                ecosystem="PyPI",
                source_file=file_path.name,
            )
        )
    return packages


def parse_package_json(path: str | Path) -> list[Package]:
    """Parse npm dependencies (exact versions only; ranges are noted as unknown)."""
    packages: list[Package] = []
    file_path = Path(path)
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return packages
    for scope_key, scope_name in (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
    ):
        block = data.get(scope_key) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            version = _exact_npm_version(str(spec))
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    source_file=file_path.name,
                    scope=scope_name,
                )
            )
    return packages


def _exact_npm_version(spec: str) -> str:
    """Extract a concrete version from an npm range, or '' when it is a range."""
    text = spec.strip()
    if text.startswith(("^", "~", ">", "<", "=", "*", "latest", "workspace:")):
        # A caret range has a known floor, which is what matters for advisories.
        cleaned = text.lstrip("^~>=< ")
        return cleaned if cleaned and cleaned[0].isdigit() else ""
    if text[:1].isdigit():
        return text
    return ""


def parse_go_mod(path: str | Path) -> list[Package]:
    packages: list[Package] = []
    file_path = Path(path)
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return packages
    in_block = False
    for raw in lines:
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require ") and "(" not in line:
            line = line[len("require ") :].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2:
            name, version = parts[0], parts[1].lstrip("v")
            if version.startswith("v"):
                version = version[1:]
            packages.append(
                Package(name=name, version=version, ecosystem="Go", source_file=file_path.name)
            )
    return packages


def parse_cargo_toml(path: str | Path) -> list[Package]:
    packages: list[Package] = []
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return packages
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip()
            continue
        if section not in {"dependencies", "dev-dependencies", "build-dependencies"}:
            continue
        match = re.match(r"^([A-Za-z0-9_\-]+)\s*=\s*(?:\"([^\"]+)\"|\{[^}]*version\s*=\s*\"([^\"]+)\")", line)
        if not match:
            continue
        name = match.group(1)
        version = (match.group(2) or match.group(3) or "").lstrip("^~= ")
        packages.append(
            Package(name=name, version=version, ecosystem="crates.io", source_file=file_path.name)
        )
    return packages


def parse_manifest(path: str | Path) -> list[Package]:
    """Dispatch on filename."""
    name = Path(path).name
    if name == "requirements.txt" or name.endswith(".txt") and "requirement" in name.lower():
        return parse_requirements_txt(path)
    if name == "package.json":
        return parse_package_json(path)
    if name == "go.mod":
        return parse_go_mod(path)
    if name == "Cargo.toml":
        return parse_cargo_toml(path)
    if name == "pyproject.toml":
        return _parse_pyproject(path)
    return []


def _parse_pyproject(path: str | Path) -> list[Package]:
    """Minimal pyproject reader for [project].dependencies."""
    packages: list[Package] = []
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return packages
    in_deps = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("dependencies") and "[" in line:
            in_deps = True
            continue
        if in_deps:
            if line.startswith("]"):
                in_deps = False
                continue
            cleaned = line.strip('",')
            match = _REQUIREMENT_RE.match(cleaned)
            if match:
                packages.append(
                    Package(
                        name=match.group(1),
                        version=match.group(2) or "",
                        ecosystem="PyPI",
                        source_file=file_path.name,
                    )
                )
    return packages


# --------------------------------------------------------------------------- versions
def _version_tuple(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in re.split(r"[._\-+]", version or ""):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            match = re.match(r"^(\d+)", chunk)
            if match:
                parts.append(int(match.group(1)))
            elif parts:
                break
    return tuple(parts)


def version_below(present: str, threshold: str) -> bool:
    """Is ``present`` older than ``threshold``?"""
    if not present or not threshold:
        return False
    return _version_tuple(present) < _version_tuple(threshold)


def _advisories_for(package: Package) -> list[dict[str, Any]]:
    """Advisories for a package whose affected threshold the version is below."""
    entries = LOCAL_ADVISORIES.get((package.ecosystem.lower(), package.name.lower()), [])
    hits: list[dict[str, Any]] = []
    for entry in entries:
        threshold = entry.get("affected_below", "")
        if not package.version:
            # Unpinned: report as unverifiable rather than clean.
            hits.append({**entry, "note": "version not pinned, cannot verify"})
        elif version_below(package.version, threshold):
            hits.append(entry)
    return hits


# --------------------------------------------------------------------------- online
def query_osv(packages: list[Package], *, timeout: float = 15.0) -> dict[str, Any]:
    """Query the real OSV.dev batch endpoint."""
    if not packages:
        return {"ok": True, "results": [], "error": None}
    payload = {
        "queries": [
            {
                "package": {"name": pkg.name, "ecosystem": pkg.ecosystem},
                "version": pkg.version or None,
            }
            for pkg in packages
            if pkg.version
        ]
    }
    if not payload["queries"]:
        return {"ok": True, "results": [], "error": "no pinned versions to query"}

    client = SafeHttpClient(timeout=timeout, user_agent="KingdomX/1.0 osv-scan")
    try:
        response = client.post_json(OSV_BATCH_URL, payload, timeout=timeout)
    except NetworkError as exc:
        return {"ok": False, "results": [], "error": exc.message}
    if response.status >= 400:
        return {"ok": False, "results": [], "error": f"OSV returned HTTP {response.status}"}
    try:
        data = response.json()
    except NetworkError as exc:
        return {"ok": False, "results": [], "error": exc.message}
    return {"ok": True, "results": data.get("results") or [], "error": None}


# --------------------------------------------------------------------------- scan
@dataclass
class DependencyScan:
    packages: list[Package] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    online_used: bool = False
    online_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifests": list(self.manifests),
            "package_count": len(self.packages),
            "online_used": self.online_used,
            "online_error": self.online_error,
            "findings": [f.to_dict() for f in self.findings],
        }


def scan_directory(
    root: str | Path,
    *,
    network: bool = False,
    timeout: float = 15.0,
    max_depth: int = 4,
) -> DependencyScan:
    """Find manifests under ``root`` and scan their dependencies."""
    base = Path(root).expanduser().resolve()
    scan = DependencyScan()
    if not base.exists():
        return scan

    if base.is_file():
        candidates = [base]
    else:
        candidates = []
        for candidate in base.rglob("*"):
            if not candidate.is_file():
                continue
            try:
                depth = len(candidate.relative_to(base).parts)
            except ValueError:
                continue
            if depth > max_depth:
                continue
            if candidate.name in {
                "requirements.txt", "package.json", "go.mod", "Cargo.toml", "pyproject.toml",
            }:
                candidates.append(candidate)

    seen: set[tuple[str, str, str]] = set()
    for manifest in sorted(candidates):
        parsed = parse_manifest(manifest)
        if not parsed:
            continue
        scan.manifests.append(str(manifest))
        for package in parsed:
            if package.key in seen:
                continue
            seen.add(package.key)
            scan.packages.append(package)

    for package in scan.packages:
        for advisory in _advisories_for(package):
            severity = Severity.parse(advisory.get("severity", "medium"))
            scan.findings.append(
                Finding(
                    title=f"{package.name} {package.version or '(unpinned)'}: {advisory['summary']}",
                    severity=severity,
                    category="dependency",
                    detail=advisory.get("note")
                    or f"Fix available: upgrade to {advisory.get('affected_below')} or later.",
                    reference=advisory.get("reference"),
                    evidence=f"{package.name}=={package.version} ({package.ecosystem}) from {package.source_file}",
                    remediation=f"Upgrade {package.name} to at least {advisory.get('affected_below')}.",
                    extra={"advisory_id": advisory.get("id")},
                )
            )

    if network and scan.packages:
        result = query_osv(scan.packages, timeout=timeout)
        scan.online_used = bool(result["ok"])
        scan.online_error = result.get("error")
        if result["ok"]:
            pinned = [p for p in scan.packages if p.version]
            for package, entry in zip(pinned, result["results"]):
                for vuln in (entry or {}).get("vulns") or []:
                    if not isinstance(vuln, dict):
                        continue
                    score = _osv_score(vuln)
                    severity = from_cvss(score) if score else Severity.MEDIUM
                    scan.findings.append(
                        Finding(
                            title=f"{package.name} {package.version}: {vuln.get('id', 'advisory')}"
                            + (f" — {vuln.get('summary')}" if vuln.get("summary") else ""),
                            severity=severity,
                            category="dependency",
                            detail=(vuln.get("details") or "")[:400],
                            reference=f"https://osv.dev/vulnerability/{vuln.get('id')}",
                            evidence=f"{package.name}=={package.version} from {package.source_file}",
                            remediation="Upgrade to a fixed release listed in the advisory.",
                            extra={"osv_id": vuln.get("id"), "cvss": score},
                        )
                    )

    if not scan.packages:
        scan.findings.append(
            Finding(
                title="No dependency manifests found",
                severity=Severity.INFO,
                category="dependency",
                detail="Looked for requirements.txt, package.json, go.mod, Cargo.toml and pyproject.toml.",
                passed=True,
            )
        )
    elif not scan.findings:
        scan.findings.append(
            Finding(
                title=f"No known advisories for {len(scan.packages)} package(s)",
                severity=Severity.INFO,
                category="dependency",
                detail="Checked against the local advisory cache"
                + (" and the OSV API" if scan.online_used else " only — network mode was off."),
                passed=True,
            )
        )
    return scan


def _osv_score(vuln: dict[str, Any]) -> float:
    """Best-effort CVSS base score from an OSV entry."""
    for severity in vuln.get("severity") or []:
        if not isinstance(severity, dict):
            continue
        if str(severity.get("type", "")).upper().startswith("CVSS"):
            vector = str(severity.get("score", ""))
            match = re.search(r"/(\d+\.\d+)$", vector)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    continue
    database = vuln.get("database_specific") or {}
    if isinstance(database.get("severity"), str):
        mapping = {
            "critical": 9.5, "high": 8.0, "moderate": 5.5, "medium": 5.5, "low": 2.5,
        }
        return mapping.get(database["severity"].lower(), 0.0)
    return 0.0


def dependency_report(root: str | Path, *, network: bool = False) -> Report:
    report = Report(module="dependencies", target=str(root), started_at=time.time())
    scan = scan_directory(root, network=network)
    report.findings.extend(scan.findings)
    report.meta = scan.to_dict()
    if scan.online_error:
        report.errors.append(f"OSV lookup failed: {scan.online_error}")
    report.finished_at = time.time()
    return report
