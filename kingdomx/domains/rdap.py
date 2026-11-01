"""RDAP domain lookup, expiry analysis and homograph detection.

RDAP is the modern replacement for WHOIS: HTTPS, JSON, IANA-bootstrapped. We use
``rdap.org`` as the bootstrap redirector so a single endpoint covers every TLD.

Because registry data is uneven, anything we could not obtain is reported as
``None`` with a reason, never as a plausible-looking placeholder.
"""

from __future__ import annotations

import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from kingdomx.core.errors import NetworkError, UnsafeTargetError, ValidationError
from kingdomx.core.http import SafeHttpClient
from kingdomx.core.logging_setup import get_logger
from kingdomx.core.validation import validate_domain
from kingdomx.cybersecurity.severity import Finding, Report, Severity

log = get_logger("domains.rdap")

RDAP_DOMAIN_URL = "https://rdap.org/domain/{domain}"
RDAP_TLD_URL = "https://rdap.org/domain/{tld}"

#: Characters that render like Latin letters but are not. Used for homograph checks.
CONFUSABLES: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t",
    "β": "b", "ε": "e", "η": "n", "μ": "u", "χ": "x",
}

#: Registrars and their public abuse-contact notes (informational only).
ABUSE_HINT = (
    "RDAP returns the registrar's own abuse contact when the registry publishes one. "
    "KINGDOM X shows it verbatim; it does not verify the address is monitored."
)


@dataclass
class DomainRecord:
    """What RDAP told us, or why it told us nothing."""

    domain: str
    ok: bool
    handle: str | None = None
    ldh_name: str | None = None
    unicode_name: str | None = None
    status: list[str] = field(default_factory=list)
    registrar: str | None = None
    registrar_id: str | None = None
    abuse_email: str | None = None
    created: str | None = None
    updated: str | None = None
    expires: str | None = None
    days_to_expiry: int | None = None
    expired: bool | None = None
    nameservers: list[str] = field(default_factory=list)
    dnssec_signed: bool | None = None
    registrant_country: str | None = None
    source: str = "rdap.org"
    fetched_at: float = field(default_factory=time.time)
    error: str | None = None
    redacted_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "ok": self.ok,
            "handle": self.handle,
            "ldh_name": self.ldh_name,
            "unicode_name": self.unicode_name,
            "status": list(self.status),
            "registrar": self.registrar,
            "registrar_id": self.registrar_id,
            "abuse_email": self.abuse_email,
            "created": self.created,
            "updated": self.updated,
            "expires": self.expires,
            "days_to_expiry": self.days_to_expiry,
            "expired": self.expired,
            "nameservers": list(self.nameservers),
            "dnssec_signed": self.dnssec_signed,
            "registrant_country": self.registrant_country,
            "source": self.source,
            "fetched_at": self.fetched_at,
            "error": self.error,
            "redacted_fields": list(self.redacted_fields),
            "abuse_note": ABUSE_HINT,
        }

    @property
    def summary(self) -> str:
        if not self.ok:
            return f"unavailable: {self.error}"
        bits = [self.domain]
        if self.registrar:
            bits.append(f"registrar={self.registrar}")
        if self.days_to_expiry is not None:
            bits.append(f"expires in {self.days_to_expiry}d")
        return " | ".join(bits)


def _parse_rfc3339(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _find_event(events: list[Any], action: str) -> str | None:
    for event in events:
        if not isinstance(event, dict):
            continue
        if str(event.get("eventAction", "")).lower() == action:
            return str(event.get("eventDate") or "") or None
    return None


def _entity_name(entity: dict[str, Any]) -> str | None:
    for vcard in entity.get("vcardArray") or []:
        if not isinstance(vcard, list) or len(vcard) < 2:
            continue
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return str(entity.get("handle") or "") or None


def _entity_email(entity: dict[str, Any]) -> str | None:
    for vcard in entity.get("vcardArray") or []:
        if not isinstance(vcard, list) or len(vcard) < 2:
            continue
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
                return str(item[3])
    return None


def rdap_lookup(domain: str, *, timeout: float = 12.0) -> DomainRecord:
    """Fetch registry data for one domain."""
    check = validate_domain(domain)
    if not check.ok:
        return DomainRecord(
            domain=domain, ok=False, error=f"invalid domain: {check.reason}"
        )
    clean = check.normalised or domain.lower()

    client = SafeHttpClient(timeout=timeout, user_agent="KingdomX/1.0 rdap")
    try:
        response = client.get(RDAP_DOMAIN_URL.format(domain=clean), timeout=timeout)
    except (NetworkError, UnsafeTargetError) as exc:
        return DomainRecord(domain=clean, ok=False, error=exc.message)

    if response.status == 404:
        return DomainRecord(
            domain=clean,
            ok=False,
            error="not found in RDAP — the domain is unregistered or its TLD has no RDAP service",
        )
    if response.status >= 400:
        return DomainRecord(
            domain=clean, ok=False, error=f"RDAP returned HTTP {response.status}"
        )

    try:
        data = response.json()
    except NetworkError as exc:
        return DomainRecord(domain=clean, ok=False, error=exc.message)
    if not isinstance(data, dict):
        return DomainRecord(domain=clean, ok=False, error="unexpected RDAP response shape")

    events = data.get("events") or []
    record = DomainRecord(
        domain=clean,
        ok=True,
        handle=data.get("handle"),
        ldh_name=data.get("ldhName"),
        unicode_name=data.get("unicodeName"),
        status=[str(s) for s in (data.get("status") or [])],
        created=_find_event(events, "registration"),
        updated=_find_event(events, "last changed") or _find_event(events, "last update"),
        expires=_find_event(events, "expiration"),
    )

    for ns in data.get("nameservers") or []:
        if isinstance(ns, dict):
            name = ns.get("ldhName") or ns.get("unicodeName")
            if name:
                record.nameservers.append(str(name).lower())

    secure_dns = data.get("secureDNS")
    if isinstance(secure_dns, dict):
        record.dnssec_signed = bool(secure_dns.get("delegationSigned"))

    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        roles = [str(role).lower() for role in (entity.get("roles") or [])]
        if "registrar" in roles and record.registrar is None:
            record.registrar = _entity_name(entity)
            record.registrar_id = str(entity.get("handle") or "") or None
            record.abuse_email = _entity_email(entity)
            for child in entity.get("entities") or []:
                if isinstance(child, dict) and "abuse" in [
                    str(r).lower() for r in (child.get("roles") or [])
                ]:
                    record.abuse_email = _entity_email(child) or record.abuse_email
        if "registrant" in roles and record.registrant_country is None:
            for vcard in entity.get("vcardArray") or []:
                if not isinstance(vcard, list) or len(vcard) < 2:
                    continue
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "adr":
                        pass
            record.registrant_country = str(entity.get("country") or "") or None

    expires_at = _parse_rfc3339(record.expires)
    if expires_at is not None:
        delta = expires_at - datetime.now(timezone.utc)
        record.days_to_expiry = int(delta.total_seconds() // 86400)
        record.expired = record.days_to_expiry < 0
    else:
        # Say so plainly rather than inventing a date.
        record.redacted_fields.append("expiration date not published by this registry")

    if record.registrar is None:
        record.redacted_fields.append("registrar not published by this registry")

    return record


def homograph_check(domain: str) -> dict[str, Any]:
    """Detect non-ASCII labels and mixed-script labels, which are homograph vectors."""
    clean = (domain or "").strip().lower()
    labels = [label for label in clean.split(".") if label]

    non_ascii_labels: list[str] = []
    mixed_script_labels: list[str] = []
    skeleton_parts: list[str] = []

    for label in labels:
        if all(ord(ch) < 128 for ch in label):
            skeleton_parts.append(label)
            continue
        non_ascii_labels.append(label)
        # Count scripts across the WHOLE label, ASCII included. The spoof vector is
        # a Latin letter hiding next to a Cyrillic/Greek lookalike, so restricting
        # this set to non-ASCII code points would miss every realistic homograph.
        scripts = {
            unicodedata.name(ch, "?").split(" ")[0]
            for ch in label
            if unicodedata.name(ch, "")
        }
        if len(scripts) > 1:
            mixed_script_labels.append(label)
        skeleton_parts.append("".join(CONFUSABLES.get(ch, ch) for ch in label))

    try:
        punycode = clean.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        punycode = clean

    skeleton = ".".join(skeleton_parts)
    risky = bool(non_ascii_labels) or punycode.startswith("xn--") or ".xn--" in punycode

    return {
        "domain": clean,
        "punycode": punycode,
        "is_idn": "." in punycode and ("xn--" in punycode),
        "non_ascii_labels": non_ascii_labels,
        "mixed_script_labels": mixed_script_labels,
        "skeleton": skeleton,
        "skeleton_differs_from_latin": bool(non_ascii_labels),
        "risky": risky,
        "note": (
            "A non-ASCII label is not malicious by itself (many legitimate domains are "
            "IDN). Treat it as a prompt to compare the punycode form against the "
            "displayed form before trusting it."
            if risky
            else "Every label is plain ASCII, so homograph confusion does not apply here."
        ),
    }


def domain_report(domain: str, *, timeout: float = 12.0) -> Report:
    """RDAP plus homograph analysis, as a standard report."""
    report = Report(module="domain", target=domain, started_at=time.time())

    try:
        record = rdap_lookup(domain, timeout=timeout)
    except ValidationError as exc:
        report.errors.append(exc.message)
        report.finished_at = time.time()
        return report

    if not record.ok:
        report.issue(
            title="Registry data unavailable",
            severity=Severity.INFO,
            category="registry",
            detail=record.error or "unknown reason",
            remediation="The domain may be unregistered, or this TLD may not publish RDAP.",
        )
        report.meta = record.to_dict()
        report.finished_at = time.time()
        return report

    report.passed(
        "Registry record retrieved",
        "registry",
        detail=f"handle {record.handle or 'n/a'}; source {record.source}",
    )

    if record.expired:
        report.issue(
            title="Domain has expired",
            severity=Severity.CRITICAL,
            category="lifecycle",
            detail=f"Expired {abs(record.days_to_expiry or 0)} days ago.",
            remediation="Renew immediately; expired domains are hijackable within hours.",
        )
    elif record.days_to_expiry is not None:
        if record.days_to_expiry <= 14:
            report.issue(
                title=f"Domain expires in {record.days_to_expiry} days",
                severity=Severity.HIGH,
                category="lifecycle",
                detail=f"expiration: {record.expires}",
                remediation="Renew now and enable auto-renew.",
            )
        elif record.days_to_expiry <= 45:
            report.issue(
                title=f"Domain expires in {record.days_to_expiry} days",
                severity=Severity.MEDIUM,
                category="lifecycle",
                detail=f"expiration: {record.expires}",
                remediation="Confirm auto-renew is enabled.",
            )
        else:
            report.passed(
                f"Domain valid for {record.days_to_expiry} days",
                "lifecycle",
                detail=f"expiration: {record.expires}",
            )

    dangerous_status = {
        "clienthold", "serverhold", "pendingdelete", "redemptionperiod", "pendingtransfer",
    }
    active = {status.lower() for status in record.status}
    held = active & dangerous_status
    if held:
        report.issue(
            title="Domain is in a suspended or deleting state",
            severity=Severity.HIGH,
            category="lifecycle",
            detail="Registry status: " + ", ".join(sorted(held)),
            remediation="Contact the registrar; the domain is not resolving normally.",
        )
    elif record.status:
        report.passed(
            "No suspension status codes",
            "lifecycle",
            detail=", ".join(record.status[:6]),
        )

    if not record.nameservers:
        report.issue(
            title="No nameservers delegated",
            severity=Severity.HIGH,
            category="delegation",
            detail="The domain has no NS records at the registry, so it cannot resolve.",
        )
    else:
        report.passed(
            f"{len(record.nameservers)} nameserver(s) delegated",
            "delegation",
            detail=", ".join(record.nameservers[:6]),
        )

    if record.dnssec_signed is False:
        report.issue(
            title="DNSSEC is not enabled",
            severity=Severity.LOW,
            category="dnssec",
            detail="Without DNSSEC, a resolver cannot detect a forged DNS answer.",
            remediation="Enable DNSSEC at the registrar and publish DS records.",
        )
    elif record.dnssec_signed:
        report.passed("DNSSEC is enabled", "dnssec")

    homograph = homograph_check(record.ldh_name or domain)
    report.meta = {**record.to_dict(), "homograph": homograph}
    if homograph["risky"]:
        report.issue(
            title="Non-ASCII (IDN) labels present",
            severity=Severity.MEDIUM,
            category="homograph",
            detail=homograph["note"],
            evidence=f"punycode: {homograph['punycode']}; skeleton: {homograph['skeleton']}",
            remediation="Display the punycode form wherever the domain is shown to a user.",
        )
    else:
        report.passed("All labels are plain ASCII", "homograph")

    report.finished_at = time.time()
    return report


def registrars_note() -> str:
    return (
        "KINGDOM X does not maintain its own registrar list. Registrar names in a report "
        "come verbatim from the registry's RDAP response, which is the authoritative "
        "source for that domain."
    )
