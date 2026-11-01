"""Website Intelligence.

Combines: HTTP response analysis, security headers, TLS certificate, technology
fingerprinting from observed response markers, and an availability check.

Technology detection is based on **real markers in the response** (headers,
cookies, HTML paths). Anything not observed is not claimed.
"""

from kingdomx.websites.audit import (
    WebsiteAudit,
    audit_website,
    fingerprint,
    availability_check,
    web_report,
)

__all__ = ["WebsiteAudit", "audit_website", "fingerprint", "availability_check", "web_report"]
