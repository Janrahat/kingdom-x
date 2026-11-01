"""HTTP security-header audit.

Passive: one GET to a public URL, then evaluate what came back. Nothing is
fuzzed, nothing is brute-forced, so this does not require target authorization —
but it does refuse private addresses, because that is the SSRF boundary.

Each check states the header, the observed value, why it matters, and the exact
header to send instead.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from kingdomx.core.errors import NetworkError, UnsafeTargetError, ValidationError
from kingdomx.core.http import SafeHttpClient
from kingdomx.core.validation import normalise_url
from kingdomx.cybersecurity.severity import Finding, Report, Severity


@dataclass(frozen=True)
class HeaderCheck:
    """One expected header and how to judge it."""

    header: str
    severity: Severity
    category: str
    why: str
    good_example: str
    missing_detail: str


CHECKS: tuple[HeaderCheck, ...] = (
    HeaderCheck(
        header="strict-transport-security",
        severity=Severity.HIGH,
        category="transport",
        why=(
            "HSTS tells the browser to refuse plain HTTP for this host, which closes "
            "the SSL-stripping window after the first visit."
        ),
        good_example="max-age=31536000; includeSubDomains; preload",
        missing_detail=(
            "Without HSTS, the very first request of a session can be downgraded to "
            "HTTP by an attacker on the path."
        ),
    ),
    HeaderCheck(
        header="content-security-policy",
        severity=Severity.HIGH,
        category="xss",
        why=(
            "CSP restricts where scripts, styles and frames may come from, and it is "
            "the primary defence-in-depth against XSS when output encoding fails."
        ),
        good_example="default-src 'self'; object-src 'none'; base-uri 'none'",
        missing_detail=(
            "Any injected script executes with full page privileges. This is the single "
            "most valuable header to add for an application that renders user input."
        ),
    ),
    HeaderCheck(
        header="x-content-type-options",
        severity=Severity.MEDIUM,
        category="mime",
        why="Stops browsers from MIME-sniffing a response into a different type.",
        good_example="nosniff",
        missing_detail=(
            "A text/plain upload containing HTML can be sniffed and executed as HTML in "
            "older browsers."
        ),
    ),
    HeaderCheck(
        header="x-frame-options",
        severity=Severity.MEDIUM,
        category="clickjacking",
        why="Prevents the page being framed and used as clickjacking bait.",
        good_example="DENY",
        missing_detail=(
            "An attacker can overlay invisible frames and capture clicks. CSP "
            "frame-ancestors supersedes this header when present."
        ),
    ),
    HeaderCheck(
        header="referrer-policy",
        severity=Severity.LOW,
        category="privacy",
        why="Controls how much URL information leaks to third parties on navigation.",
        good_example="strict-origin-when-cross-origin",
        missing_detail=(
            "Full URLs — potentially including tokens in query strings — are sent to "
            "every third-party resource the page loads."
        ),
    ),
    HeaderCheck(
        header="permissions-policy",
        severity=Severity.LOW,
        category="privacy",
        why="Restricts access to powerful browser features such as camera and geolocation.",
        good_example="geolocation=(), camera=(), microphone=()",
        missing_detail=(
            "Embedded third-party frames may request powerful permissions the page does "
            "not need."
        ),
    ),
    HeaderCheck(
        header="x-xss-protection",
        severity=Severity.INFO,
        category="legacy",
        why=(
            "Deprecated. The only correct value is 0 (or the header absent); a non-zero "
            "value can introduce vulnerabilities in old browsers."
        ),
        good_example="0",
        missing_detail="",
    ),
    HeaderCheck(
        header="cross-origin-opener-policy",
        severity=Severity.LOW,
        category="isolation",
        why="Isolates the browsing context from cross-origin windows (Spectre mitigations).",
        good_example="same-origin",
        missing_detail="Cross-origin windows retain a reference and can influence the page.",
    ),
)

#: Headers that leak implementation detail.
LEAKY_HEADERS: tuple[tuple[str, Severity, str], ...] = (
    (
        "server",
        Severity.LOW,
        "Reveals the web server and often its version, which tells an attacker exactly "
        "which exploits to try.",
    ),
    (
        "x-powered-by",
        Severity.LOW,
        "Discloses the application framework and version.",
    ),
    (
        "x-aspnet-version",
        Severity.MEDIUM,
        "Discloses the ASP.NET version, which maps to known CVEs.",
    ),
    (
        "x-aspnetmvc-version",
        Severity.LOW,
        "Discloses the ASP.NET MVC version.",
    ),
    (
        "x-generator",
        Severity.INFO,
        "Discloses the CMS or generator.",
    ),
)

#: Cookies must carry these flags.
COOKIE_FLAGS: tuple[tuple[str, Severity, str], ...] = (
    ("secure", Severity.HIGH, "Without Secure, the cookie travels over plain HTTP."),
    ("httponly", Severity.HIGH, "Without HttpOnly, JavaScript can read the cookie and XSS becomes session theft."),
    ("samesite", Severity.MEDIUM, "Without SameSite, cross-site requests carry the cookie (CSRF exposure)."),
)


@dataclass
class HeaderAudit:
    """The result of a header audit."""

    url: str
    status: int
    headers: dict[str, str]
    findings: list[Finding] = field(default_factory=list)
    elapsed_ms: float = 0.0
    server: str = ""
    title: str = ""
    cookies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "server": self.server,
            "title": self.title,
            "header_count": len(self.headers),
            "findings": [f.to_dict() for f in self.findings],
        }


def audit_headers(
    url: str,
    *,
    timeout: float = 12.0,
    client: SafeHttpClient | None = None,
) -> HeaderAudit:
    """Fetch ``url`` once and grade its security headers."""
    target = normalise_url(url)
    active_client = client or SafeHttpClient(timeout=timeout, user_agent="KingdomX/1.0 header-audit")
    started = time.perf_counter()
    response = active_client.get(target, timeout=timeout, max_bytes=512 * 1024)
    elapsed = (time.perf_counter() - started) * 1000

    lowered = {key.lower(): value for key, value in response.headers.items()}
    body = response.text
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    title = (title_match.group(1).strip()[:120] if title_match else "") or ""
    cookies = [
        value for key, value in response.headers.items() if key.lower() == "set-cookie"
    ]

    audit = HeaderAudit(
        url=response.url,
        status=response.status,
        headers=lowered,
        elapsed_ms=elapsed,
        server=lowered.get("server", ""),
        title=title,
        cookies=cookies,
    )

    # HTTPS-only checks first: several headers are meaningless over plain HTTP.
    scheme = urlsplit(response.url).scheme.lower()
    if scheme != "https":
        audit.findings.append(
            Finding(
                title="Site is served over plain HTTP",
                severity=Severity.CRITICAL,
                category="transport",
                detail=(
                    "The response arrived over HTTP, so every byte — including session "
                    "cookies and credentials — is readable and modifiable in transit."
                ),
                evidence=f"scheme={scheme}",
                remediation="Redirect all HTTP to HTTPS and deploy a valid certificate.",
            )
        )

    for check in CHECKS:
        value = lowered.get(check.header)
        if value is None:
            if check.header == "x-xss-protection":
                audit.findings.append(
                    Finding(
                        title="No X-XSS-Protection header (correct)",
                        severity=Severity.INFO,
                        category=check.category,
                        detail="The header is deprecated; omitting it is the modern correct choice.",
                        passed=True,
                    )
                )
                continue
            audit.findings.append(
                Finding(
                    title=f"Missing {check.header}",
                    severity=check.severity,
                    category=check.category,
                    detail=check.missing_detail or check.why,
                    evidence=f"header absent; response headers: {_header_names(lowered)}",
                    remediation=f"Send: {check.header}: {check.good_example}",
                    reference="https://owasp.org/www-project-secure-headers/",
                )
            )
            continue

        problem = _evaluate(check.header, value)
        if problem:
            audit.findings.append(
                Finding(
                    title=f"Weak {check.header}",
                    severity=check.severity,
                    category=check.category,
                    detail=problem,
                    evidence=f"{check.header}: {_truncate(value)}",
                    remediation=f"Use: {check.header}: {check.good_example}",
                    reference="https://owasp.org/www-project-secure-headers/",
                )
            )
        else:
            audit.findings.append(
                Finding(
                    title=f"{check.header} correctly set",
                    severity=Severity.INFO,
                    category=check.category,
                    detail=check.why,
                    evidence=f"{check.header}: {_truncate(value)}",
                    passed=True,
                )
            )

    for header, severity, why in LEAKY_HEADERS:
        value = lowered.get(header)
        if not value:
            continue
        has_version = bool(re.search(r"\d+\.\d+", value))
        audit.findings.append(
            Finding(
                title=f"Version disclosure in {header}",
                severity=severity if has_version else Severity.INFO,
                category="disclosure",
                detail=why,
                evidence=f"{header}: {_truncate(value)}",
                remediation=f"Remove or genericise the {header} header at the proxy.",
            )
        )

    for cookie in cookies:
        audit.findings.extend(_cookie_findings(cookie))

    return audit


def _evaluate(header: str, value: str) -> str | None:
    """Return a problem description, or None when the value is acceptable."""
    low = (value or "").strip().lower()

    if header == "strict-transport-security":
        match = re.search(r"max-age\s*=\s*(\d+)", low)
        if not low:
            return "Header present but empty."
        if not match:
            return "No max-age directive, so the policy is not enforceable."
        age = int(match.group(1))
        if age == 0:
            return "max-age=0 explicitly disables HSTS."
        if age < 15552000:
            return (
                f"max-age is {age}s (about {age // 86400} days); the preload list and "
                "most guidance expect at least 15552000s (180 days)."
            )
        return None

    if header == "content-security-policy":
        if "'unsafe-inline'" in low or "'unsafe-eval'" in low:
            return (
                "The policy allows 'unsafe-inline' or 'unsafe-eval', which defeats most "
                "of the XSS protection CSP is meant to provide."
            )
        if "default-src" not in low and "script-src" not in low:
            return "The policy constrains no script source; script-src is the directive that matters."
        if re.search(r"(?<![a-z-])\*(?![a-z-])", low) and "script-src *" in low:
            return "script-src allows any origin (*)."
        return None

    if header == "x-content-type-options":
        return None if low == "nosniff" else "Expected exactly 'nosniff'."

    if header == "x-frame-options":
        return None if low in {"deny", "sameorigin"} else "Expected DENY or SAMEORIGIN."

    if header == "referrer-policy":
        acceptable = {
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "no-referrer-when-downgrade",
        }
        return None if low in acceptable else f"'{low}' is not a recommended policy value."

    if header == "x-xss-protection":
        if low == "0":
            return None
        return "Non-zero X-XSS-Protection can introduce XSS in older browsers; set it to 0 or remove it."

    return None


def _cookie_findings(cookie: str) -> list[Finding]:
    """Grade one Set-Cookie header."""
    findings: list[Finding] = []
    parts = [part.strip() for part in cookie.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else "cookie"
    lowered = cookie.lower()

    for flag, severity, why in COOKIE_FLAGS:
        if flag in lowered:
            continue
        findings.append(
            Finding(
                title=f"Cookie '{name}' missing {flag.capitalize()}",
                severity=severity,
                category="cookies",
                detail=why,
                evidence=f"Set-Cookie: {_truncate(cookie)}",
                remediation=f"Add the {flag.capitalize()} attribute to the cookie.",
                reference="https://owasp.org/www-community/controls/SecureCookieAttribute",
            )
        )
    if "domain=" in lowered:
        findings.append(
            Finding(
                title=f"Cookie '{name}' scoped to a parent domain",
                severity=Severity.LOW,
                category="cookies",
                detail=(
                    "An explicit Domain attribute widens the cookie to every subdomain, "
                    "including ones that may be less trustworthy."
                ),
                evidence=f"Set-Cookie: {_truncate(cookie)}",
                remediation="Drop the Domain attribute so the cookie is host-only.",
            )
        )
    return findings


def audit_report(url: str, **kwargs: Any) -> Report:
    """Wrap the audit in the standard :class:`Report` shape."""
    report = Report(module="headers", target=url, started_at=time.time())
    try:
        audit = audit_headers(url, **kwargs)
    except (NetworkError, UnsafeTargetError, ValidationError) as exc:
        report.errors.append(exc.message)
        report.finished_at = time.time()
        return report

    report.findings.extend(audit.findings)
    report.meta = {
        "status": audit.status,
        "server": audit.server,
        "title": audit.title,
        "elapsed_ms": round(audit.elapsed_ms, 1),
        "cookie_count": len(audit.cookies),
    }
    report.finished_at = time.time()
    return report


def _header_names(headers: dict[str, str]) -> str:
    return ", ".join(sorted(headers)) or "(none)"


def _truncate(text: str, limit: int = 160) -> str:
    clean = (text or "").strip().replace("\n", " ")
    return clean if len(clean) <= limit else clean[: limit - 1] + "…"


def expected_headers() -> list[dict[str, Any]]:
    """The checklist itself, for the terminal menu and the docs."""
    return [
        {
            "header": check.header,
            "severity": check.severity.label,
            "category": check.category,
            "why": check.why,
            "example": check.good_example,
        }
        for check in CHECKS
    ]
