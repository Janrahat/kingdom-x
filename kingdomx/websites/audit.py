"""Website audit: one fetch, then everything that can be learned from it.

The fingerprint table maps *observed evidence* to a technology. Every match
carries the evidence string, so a report can justify each claim. On failure the
result says the site was unreachable — it never reports "clean".
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from kingdomx.core.errors import NetworkError, UnsafeTargetError, ValidationError
from kingdomx.core.http import SafeHttpClient
from kingdomx.core.validation import normalise_url, validate_domain
from kingdomx.cybersecurity.headers import audit_headers
from kingdomx.cybersecurity.severity import Finding, Report, Severity
from kingdomx.cybersecurity.tls import quick_check


@dataclass(frozen=True)
class Fingerprint:
    """A technology signature and the observable that reveals it."""

    name: str
    category: str
    source: str
    """``header``, ``cookie``, ``body``, ``cookie_name`` or ``header_name``."""

    pattern: str
    """Header name, cookie name, or a regex against the body."""

    value: str | None = None
    """For ``header``: a substring the header value must contain."""

    note: str = ""


#: Curated signatures. Order matters only for display.
FINGERPRINTS: tuple[Fingerprint, ...] = (
    Fingerprint("WordPress", "CMS", "body", r"/wp-content/", note="wp-content paths in HTML"),
    Fingerprint("WordPress", "CMS", "body", r"/wp-includes/"),
    Fingerprint("Drupal", "CMS", "header", "x-generator", "Drupal"),
    Fingerprint("Drupal", "CMS", "body", r'sites/default/files'),
    Fingerprint("Joomla", "CMS", "body", r'/media/system/js/'),
    Fingerprint("Shopify", "E-commerce", "header", "x-shopid"),
    Fingerprint("Shopify", "E-commerce", "body", r"cdn\.shopify\.com"),
    Fingerprint("Magento", "E-commerce", "body", r"/static/version\d+/"),
    Fingerprint("WooCommerce", "E-commerce", "body", r"woocommerce"),
    Fingerprint("Next.js", "Framework", "header", "x-nextjs-cache"),
    Fingerprint("Next.js", "Framework", "header", "x-nextjs"),
    Fingerprint("Next.js", "Framework", "body", r"__NEXT_DATA__"),
    Fingerprint("Nuxt", "Framework", "body", r"__NUXT__"),
    Fingerprint("React", "Library", "body", r'reactroot|data-reactroot'),
    Fingerprint("Vue.js", "Library", "body", r'data-v-[0-9a-f]{6,8}'),
    Fingerprint("Angular", "Framework", "body", r"ng-version="),
    Fingerprint("Svelte", "Framework", "body", r"svelte-[a-z0-9]{6,}"),
    Fingerprint("jQuery", "Library", "body", r"jquery(?:-[\d.]+)?(?:\.min)?\.js"),
    Fingerprint("Bootstrap", "CSS", "body", r"bootstrap(?:\.min)?\.css"),
    Fingerprint("Tailwind CSS", "CSS", "body", r'class="[^"]*\b(?:flex|grid)\b[^"]*\b(?:px-\d|py-\d|gap-\d)'),
    Fingerprint("PHP", "Language", "header", "x-powered-by", "PHP"),
    Fingerprint("ASP.NET", "Framework", "header", "x-powered-by", "ASP.NET"),
    Fingerprint("ASP.NET", "Framework", "header", "x-aspnet-version"),
    Fingerprint("Express", "Framework", "header", "x-powered-by", "Express"),
    Fingerprint("Django", "Framework", "cookie_name", "csrftoken"),
    Fingerprint("Laravel", "Framework", "cookie_name", "laravel_session"),
    Fingerprint("Laravel", "Framework", "cookie_name", "XSRF-TOKEN"),
    Fingerprint("Rails", "Framework", "cookie_name", "_session_id"),
    Fingerprint("Flask", "Framework", "cookie_name", "session"),
    Fingerprint("Spring Boot", "Framework", "cookie_name", "JSESSIONID"),
    Fingerprint("Java", "Language", "cookie_name", "JSESSIONID"),
    Fingerprint("Cloudflare", "CDN", "header", "cf-ray"),
    Fingerprint("Cloudflare", "CDN", "header", "server", "cloudflare"),
    Fingerprint("Fastly", "CDN", "header", "x-served-by", "cache-"),
    Fingerprint("Fastly", "CDN", "header", "x-fastly-request-id"),
    Fingerprint("Akamai", "CDN", "header", "x-akamai-transformed"),
    Fingerprint("Amazon CloudFront", "CDN", "header", "x-amz-cf-id"),
    Fingerprint("Amazon CloudFront", "CDN", "header", "via", "cloudfront"),
    Fingerprint("Varnish", "Cache", "header", "x-varnish"),
    Fingerprint("Nginx", "Web server", "header", "server", "nginx"),
    Fingerprint("Apache", "Web server", "header", "server", "apache"),
    Fingerprint("IIS", "Web server", "header", "server", "microsoft-iis"),
    Fingerprint("LiteSpeed", "Web server", "header", "server", "litespeed"),
    Fingerprint("Caddy", "Web server", "header", "server", "caddy"),
    Fingerprint("Google Analytics", "Analytics", "body", r"googletagmanager\.com|google-analytics\.com"),
    Fingerprint("Plausible", "Analytics", "body", r"plausible\.io/js/"),
    Fingerprint("Matomo", "Analytics", "body", r"matomo\.js|piwik\.js"),
    Fingerprint("HubSpot", "Marketing", "body", r"hs-scripts\.com|hubspot"),
    Fingerprint("Stripe", "Payments", "body", r"js\.stripe\.com"),
    Fingerprint("Google Tag Manager", "Tag manager", "body", r"googletagmanager\.com/gtm\.js"),
    Fingerprint("Sentry", "Monitoring", "body", r"sentry-cdn\.com|@sentry/"),
    Fingerprint("Grafana", "Monitoring", "body", r"grafana"),
    Fingerprint("Swagger UI", "Docs", "body", r"swagger-ui"),
    Fingerprint("HSTS preload", "Security", "header", "strict-transport-security", "preload"),
)


@dataclass
class WebsiteAudit:
    """Everything observed about one site in a single pass."""

    url: str
    final_url: str = ""
    reachable: bool = False
    status: int = 0
    scheme: str = ""
    host: str = ""
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: int = 0
    elapsed_ms: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    technologies: list[dict[str, str]] = field(default_factory=list)
    tls: dict[str, Any] = field(default_factory=dict)
    header_findings: list[Finding] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "reachable": self.reachable,
            "status": self.status,
            "scheme": self.scheme,
            "host": self.host,
            "title": self.title,
            "server": self.server,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "redirect_chain": list(self.redirect_chain),
            "technologies": list(self.technologies),
            "tls": dict(self.tls),
            "header_findings": [f.to_dict() for f in self.header_findings],
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


def fingerprint(
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    cookies: list[str] | None = None,
) -> list[dict[str, str]]:
    """Match observed evidence against :data:`FINGERPRINTS`."""
    lowered = {key.lower(): value for key, value in (headers or {}).items()}
    cookie_header = "; ".join(cookies or []) + "; " + lowered.get("set-cookie", "")
    cookie_names = {
        part.split("=", 1)[0].strip()
        for part in cookie_header.split(";")
        if "=" in part
    }

    matches: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for signature in FINGERPRINTS:
        evidence: str | None = None

        if signature.source == "header":
            value = lowered.get(signature.pattern.lower())
            if value is None:
                continue
            if signature.value and signature.value.lower() not in value.lower():
                continue
            evidence = f"header {signature.pattern}: {value[:80]}"
        elif signature.source == "header_name":
            if signature.pattern.lower() not in lowered:
                continue
            evidence = f"header {signature.pattern} present"
        elif signature.source == "cookie_name":
            if signature.pattern not in cookie_names:
                continue
            evidence = f"cookie {signature.pattern} present"
        elif signature.source == "body":
            if not body:
                continue
            match = re.search(signature.pattern, body, re.IGNORECASE)
            if not match:
                continue
            evidence = f"body match: {match.group(0)[:60]}"
        else:
            continue

        key = (signature.name, signature.category)
        if key in seen:
            continue
        seen.add(key)
        matches.append(
            {
                "name": signature.name,
                "category": signature.category,
                "evidence": evidence or "",
                "note": signature.note,
            }
        )

    return sorted(matches, key=lambda item: (item["category"], item["name"]))


def availability_check(url: str, *, timeout: float = 10.0, attempts: int = 2) -> dict[str, Any]:
    """Is the site up right now? Real requests, measured."""
    target = normalise_url(url)
    client = SafeHttpClient(timeout=timeout, user_agent="KingdomX/1.0 availability")
    samples: list[dict[str, Any]] = []

    for _ in range(max(1, attempts)):
        started = time.perf_counter()
        try:
            response = client.get(target, timeout=timeout, max_bytes=64 * 1024)
            samples.append(
                {
                    "ok": response.status < 500,
                    "status": response.status,
                    "ms": round((time.perf_counter() - started) * 1000, 1),
                }
            )
        except (NetworkError, UnsafeTargetError) as exc:
            samples.append({"ok": False, "status": None, "ms": None, "error": exc.message})

    responding = [sample for sample in samples if sample["ok"]]
    latencies = [sample["ms"] for sample in responding if sample.get("ms") is not None]
    return {
        "url": target,
        "up": bool(responding),
        "attempts": len(samples),
        "successful": len(responding),
        "samples": samples,
        "avg_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "checked_at": time.time(),
        "note": (
            "An HTTP 5xx is counted as down; a 4xx counts as up, because the server "
            "answered — it just refused that path."
        ),
    }


def audit_website(url: str, *, timeout: float = 15.0, include_tls: bool = True) -> WebsiteAudit:
    """Fetch once and analyse everything observable."""
    try:
        target = normalise_url(url)
    except (ValidationError, ValueError) as exc:
        return WebsiteAudit(url=url, error=getattr(exc, "message", str(exc)))

    audit = WebsiteAudit(url=target)
    parsed = urlsplit(target)
    audit.host = parsed.hostname or ""
    audit.scheme = parsed.scheme

    try:
        header_audit = audit_headers(target, timeout=timeout)
    except (NetworkError, UnsafeTargetError, ValidationError) as exc:
        audit.error = getattr(exc, "message", str(exc))
        audit.findings.append(
            Finding(
                title="Site is unreachable",
                severity=Severity.HIGH,
                category="availability",
                detail=audit.error,
                remediation="Confirm the host resolves and serves HTTP(S) on this port.",
            )
        )
        return audit

    audit.final_url = header_audit.url
    audit.status = header_audit.status
    audit.server = header_audit.server
    audit.title = header_audit.title
    audit.elapsed_ms = header_audit.elapsed_ms
    audit.reachable = True
    audit.header_findings = header_audit.findings
    audit.redirect_chain = [target] if header_audit.url != target else []

    # The header audit fetched the page; re-fetch only the bits we need from it.
    client = SafeHttpClient(timeout=timeout, user_agent="KingdomX/1.0 web-audit")
    body = ""
    cookies: list[str] = list(header_audit.cookies)
    try:
        response = client.get(header_audit.url, timeout=timeout, max_bytes=2 * 1024 * 1024)
        body = response.text
        audit.content_type = response.headers.get("content-type", "")
        audit.content_length = len(response.body)
        cookies = [
            value for key, value in response.headers.items() if key.lower() == "set-cookie"
        ] or cookies
        audit.final_url = response.url
    except (NetworkError, UnsafeTargetError):
        pass

    audit.technologies = fingerprint(
        headers=header_audit.headers,
        body=body,
        cookies=cookies,
    )

    if include_tls and audit.scheme == "https" and audit.host:
        audit.tls = quick_check(audit.host, parsed.port or 443, timeout=min(timeout, 10.0))

    audit.findings = _build_findings(audit)
    return audit


def _build_findings(audit: WebsiteAudit) -> list[Finding]:
    findings: list[Finding] = []

    if 400 <= audit.status < 500:
        findings.append(
            Finding(
                title=f"Site answered with HTTP {audit.status}",
                severity=Severity.LOW,
                category="availability",
                detail="The server is up but refused this path. Confirm the requested URL.",
            )
        )
    elif audit.status >= 500:
        findings.append(
            Finding(
                title=f"Server error: HTTP {audit.status}",
                severity=Severity.HIGH,
                category="availability",
                detail="The application returned a server-side error.",
                remediation="Check the application log for the matching stack trace.",
            )
        )
    elif audit.reachable:
        findings.append(
            Finding(
                title=f"Site responded HTTP {audit.status} in {audit.elapsed_ms:.0f} ms",
                severity=Severity.INFO,
                category="availability",
                passed=True,
                evidence=f"final URL {audit.final_url}",
            )
        )

    if audit.elapsed_ms > 3000:
        findings.append(
            Finding(
                title=f"Slow first response ({audit.elapsed_ms:.0f} ms)",
                severity=Severity.LOW,
                category="performance",
                detail="Over 3s to first byte is a poor experience and hurts search ranking.",
            )
        )

    tls = audit.tls or {}
    if tls and not tls.get("ok", True):
        findings.append(
            Finding(
                title="TLS problem on this host",
                severity=Severity.HIGH,
                category="transport",
                detail=str(tls.get("error") or "certificate is not valid for this host"),
                evidence=f"expires {tls.get('expires')}; matches_host={tls.get('matches_host')}",
                remediation="Renew or reissue the certificate so it covers this hostname.",
            )
        )
    elif tls.get("days_remaining") is not None:
        findings.append(
            Finding(
                title=f"Certificate valid for {tls['days_remaining']} more days",
                severity=Severity.INFO,
                category="transport",
                passed=True,
                evidence=f"{tls.get('protocol')} via {tls.get('issuer')}",
            )
        )

    if not audit.technologies:
        findings.append(
            Finding(
                title="No technology signatures matched",
                severity=Severity.INFO,
                category="fingerprint",
                detail=(
                    "The response carried none of the markers KINGDOM X knows. That means "
                    "nothing was detected — not that nothing is running."
                ),
                passed=True,
            )
        )

    return sorted(findings, key=lambda f: (f.passed, -f.severity.weight))


def web_report(url: str, *, timeout: float = 15.0) -> Report:
    """The website audit as a standard report (headers included)."""
    report = Report(module="website", target=url, started_at=time.time())
    try:
        audit = audit_website(url, timeout=timeout)
    except ValidationError as exc:
        report.errors.append(exc.message)
        report.finished_at = time.time()
        return report

    if audit.error:
        report.errors.append(audit.error)

    report.findings.extend(audit.findings)
    # Header findings are deduplicated by title so the report stays readable.
    seen_titles = {finding.title for finding in report.findings}
    for finding in audit.header_findings:
        if finding.title not in seen_titles:
            report.findings.append(finding)
            seen_titles.add(finding.title)

    report.meta = {
        "final_url": audit.final_url,
        "status": audit.status,
        "technologies": audit.technologies,
        "tls": audit.tls,
        "server": audit.server,
        "title": audit.title,
        "elapsed_ms": round(audit.elapsed_ms, 1),
    }
    report.finished_at = time.time()
    return report
