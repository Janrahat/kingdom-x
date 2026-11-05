"""DNS lookups with an explicit backend.

Two backends:

``dnspython``
    Full record-type support (A, AAAA, MX, TXT, NS, SOA, CAA, SRV, PTR, DS, DNSKEY),
    custom resolvers, and real DNSSEC AD-bit reporting.
``socket``
    Fallback using ``getaddrinfo`` — A/AAAA and PTR only.

The fallback is a genuine limitation, so :class:`DnsResult` records
``backend`` and ``supported_types``; a report never claims to have checked MX
records when only the socket backend was used.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from kingdomx.core.errors import NetworkError, ValidationError
from kingdomx.core.logging_setup import get_logger
from kingdomx.core.validation import validate_domain, validate_ip

log = get_logger("dns.lookup")

DEFAULT_TIMEOUT = 5.0
DEFAULT_LIFETIME = 8.0


class Backend(str, Enum):
    DNSPYTHON = "dnspython"
    SOCKET = "socket"


#: Record types each backend can genuinely answer.
BACKEND_TYPES: dict[Backend, tuple[str, ...]] = {
    Backend.DNSPYTHON: (
        "A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR", "DS", "DNSKEY",
        "NSEC", "TLSA", "SPF",
    ),
    Backend.SOCKET: ("A", "AAAA", "PTR"),
}

ALL_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "SRV")

#: Public resolvers an operator can choose explicitly. Never used silently.
PUBLIC_RESOLVERS: dict[str, str] = {
    "cloudflare": "1.1.1.1",
    "cloudflare-alt": "1.0.0.1",
    "google": "8.8.8.8",
    "google-alt": "8.8.4.4",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
}


def dnspython_available() -> bool:
    try:
        import dns.resolver  # noqa: F401
        import dns.rdatatype  # noqa: F401
        import dns.reversename  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


def available_backends() -> list[Backend]:
    backends = [Backend.SOCKET]
    if dnspython_available():
        backends.insert(0, Backend.DNSPYTHON)
    return backends


def default_backend() -> Backend:
    return Backend.DNSPYTHON if dnspython_available() else Backend.SOCKET


@dataclass
class DnsAnswer:
    """One record."""

    name: str
    record_type: str
    value: str
    ttl: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
        }

    def __str__(self) -> str:
        return f"{self.name}\t{self.ttl if self.ttl is not None else '?'}\tIN\t{self.record_type}\t{self.value}"


@dataclass
class DnsResult:
    """The outcome of one query (or a set of queries)."""

    name: str
    record_type: str
    answers: list[DnsAnswer] = field(default_factory=list)
    backend: str = Backend.SOCKET.value
    resolver: str | None = None
    elapsed_ms: float = 0.0
    rcode: str = "NOERROR"
    error: str | None = None
    dnssec_validated: bool | None = None
    authoritative: bool | None = None
    supported_types: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return bool(self.answers)

    @property
    def values(self) -> list[str]:
        return [answer.value for answer in self.answers]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.record_type,
            "backend": self.backend,
            "resolver": self.resolver,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "rcode": self.rcode,
            "dnssec_validated": self.dnssec_validated,
            "authoritative": self.authoritative,
            "answer_count": len(self.answers),
            "answers": [answer.to_dict() for answer in self.answers],
            "error": self.error,
        }


def lookup(
    name: str,
    record_type: str = "A",
    *,
    resolver: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    backend: Backend | None = None,
) -> DnsResult:
    """Resolve ``name``/``record_type`` using an explicit backend."""
    clean = (name or "").strip().rstrip(".")
    if not clean:
        raise ValidationError("empty DNS name")

    # PTR takes an address, everything else takes a domain name.
    upper_type = (record_type or "A").strip().upper()
    if upper_type == "PTR":
        if not validate_ip(clean).ok:
            raise ValidationError(f"PTR lookups need an IP address, got: {clean}")
    elif not validate_domain(clean).ok and not clean.startswith("_"):
        raise ValidationError(f"invalid domain name: {clean}")

    chosen = backend or default_backend()
    if chosen is Backend.DNSPYTHON and not dnspython_available():
        chosen = Backend.SOCKET

    if chosen is Backend.DNSPYTHON:
        return _lookup_dnspython(clean, upper_type, resolver=resolver, timeout=timeout)
    return _lookup_socket(clean, upper_type, timeout=timeout)


def _lookup_dnspython(
    name: str, record_type: str, *, resolver: str | None, timeout: float
) -> DnsResult:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.resolver
    import dns.reversename

    started = time.perf_counter()
    query_name = name
    if record_type == "PTR":
        try:
            query_name = dns.reversename.from_address(name).to_text()
        except Exception as exc:  # noqa: BLE001
            return DnsResult(
                name=name, record_type=record_type, backend=Backend.DNSPYTHON.value,
                error=f"cannot build PTR name: {exc}", rcode="FORMERR",
                supported_types=BACKEND_TYPES[Backend.DNSPYTHON],
            )

    res = dns.resolver.Resolver(configure=True)
    res.timeout = timeout
    res.lifetime = timeout * 1.6
    if resolver:
        target = PUBLIC_RESOLVERS.get(resolver.lower(), resolver)
        if not validate_ip(target).ok:
            raise ValidationError(f"invalid resolver address: {target}")
        res.nameservers = [target]

    result = DnsResult(
        name=name,
        record_type=record_type,
        backend=Backend.DNSPYTHON.value,
        resolver=",".join(res.nameservers),
        supported_types=BACKEND_TYPES[Backend.DNSPYTHON],
    )

    try:
        answer = res.resolve(query_name, record_type, lifetime=timeout * 1.6)
    except dns.resolver.NXDOMAIN:
        result.rcode = "NXDOMAIN"
        result.error = "the domain does not exist"
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result
    except dns.resolver.NoAnswer:
        result.rcode = "NOERROR"
        result.error = f"no {record_type} records at this name (NODATA)"
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result
    except dns.resolver.NoNameservers:
        result.rcode = "SERVFAIL"
        result.error = "no nameserver answered authoritatively"
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        result.rcode = "TIMEOUT"
        result.error = f"query timed out after {timeout}s"
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result
    except Exception as exc:  # noqa: BLE001 - dns raises many types
        result.rcode = "ERROR"
        result.error = f"{type(exc).__name__}: {exc}"
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result

    ttl = getattr(answer.rrset, "ttl", None)
    for record in answer:
        result.answers.append(
            DnsAnswer(
                name=answer.qname.to_text().rstrip("."),
                record_type=record_type,
                value=_render_rdata(record, record_type),
                ttl=int(ttl) if ttl is not None else None,
            )
        )

    result.elapsed_ms = (time.perf_counter() - started) * 1000

    # Ask for the AD bit separately; resolve() does not expose it.
    try:
        query = dns.message.make_query(query_name, record_type, want_dnssec=True)
        query.flags |= dns.flags.AD
        response = dns.query.udp(query, res.nameservers[0], timeout=timeout)
        result.dnssec_validated = bool(response.flags & dns.flags.AD)
        result.authoritative = bool(response.flags & dns.flags.AA)
    except Exception:  # noqa: BLE001 - DNSSEC check is best-effort
        result.dnssec_validated = None
        result.authoritative = None

    return result


def _render_rdata(record: Any, record_type: str) -> str:
    """Render an rdata object consistently across record types."""
    try:
        import dns.rdtypes.ANY.SOA  # noqa: F401
    except Exception:  # noqa: BLE001
        pass

    text = record.to_text() if hasattr(record, "to_text") else str(record)
    if record_type == "TXT":
        # dnspython renders TXT with quotes and splits long strings.
        text = "".join(part.strip('"') for part in text.split('" "'))
        text = text.strip('"')
    # MX keeps dnspython's native "<priority> <host>" form. An earlier version
    # rewrote it to "<priority> priority=<host>", which then broke every caller
    # that split the value to recover the host name.
    return text


def _lookup_socket(name: str, record_type: str, *, timeout: float) -> DnsResult:
    started = time.perf_counter()
    result = DnsResult(
        name=name,
        record_type=record_type,
        backend=Backend.SOCKET.value,
        supported_types=BACKEND_TYPES[Backend.SOCKET],
    )

    if record_type == "PTR":
        previous = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)
            hostname, aliases, _addresses = socket.gethostbyaddr(name)
        except (socket.herror, socket.gaierror) as exc:
            result.rcode = "NXDOMAIN"
            result.error = f"reverse lookup failed: {exc}"
            result.elapsed_ms = (time.perf_counter() - started) * 1000
            return result
        except OSError as exc:
            result.rcode = "TIMEOUT"
            result.error = str(exc)
            result.elapsed_ms = (time.perf_counter() - started) * 1000
            return result
        finally:
            socket.setdefaulttimeout(previous)
        result.answers.append(DnsAnswer(name=name, record_type="PTR", value=hostname))
        for alias in aliases:
            result.answers.append(DnsAnswer(name=name, record_type="PTR", value=alias))
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result

    if record_type not in {"A", "AAAA"}:
        result.error = (
            f"the socket backend cannot query {record_type}; install dnspython "
            "(`pip install dnspython`) for full record-type support"
        )
        result.rcode = "UNSUPPORTED"
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result

    family = socket.AF_INET if record_type == "A" else socket.AF_INET6
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        result.rcode = "NXDOMAIN"
        result.error = f"resolution failed: {exc.strerror or exc}"
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result
    except OSError as exc:
        result.rcode = "TIMEOUT"
        result.error = str(exc)
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result
    finally:
        socket.setdefaulttimeout(previous)

    seen: set[str] = set()
    for info in infos:
        address = info[4][0]
        if address in seen:
            continue
        seen.add(address)
        result.answers.append(
            DnsAnswer(name=name, record_type=record_type, value=address, ttl=None)
        )
    result.elapsed_ms = (time.perf_counter() - started) * 1000
    return result


def lookup_all(
    name: str,
    *,
    types: Iterable[str] = ALL_TYPES,
    resolver: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, DnsResult]:
    """Run several record types, keyed by type."""
    out: dict[str, DnsResult] = {}
    for record_type in types:
        try:
            out[record_type] = lookup(
                name, record_type, resolver=resolver, timeout=timeout
            )
        except ValidationError as exc:
            out[record_type] = DnsResult(
                name=name,
                record_type=record_type,
                rcode="INVALID",
                error=exc.message,
            )
    return out


def reverse_lookup(address: str, *, timeout: float = DEFAULT_TIMEOUT) -> DnsResult:
    """PTR lookup for an IP address."""
    if not validate_ip(address).ok:
        raise ValidationError(f"not an IP address: {address}")
    return lookup(address, "PTR", timeout=timeout)


def zone_transfer(
    domain: str,
    *,
    nameserver: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Attempt an AXFR against each authoritative nameserver.

    A refused transfer is the normal, correct configuration — it is reported as
    such rather than as a failure of the tool.
    """
    clean = validate_domain(domain).raise_if_invalid("domain")
    if not dnspython_available():
        return {
            "ok": False,
            "domain": clean,
            "error": "dnspython is required for AXFR",
            "nameservers": [],
            "records": [],
        }

    import dns.exception
    import dns.query
    import dns.zone

    ns_result = lookup(clean, "NS", timeout=timeout)
    targets = [nameserver] if nameserver else ns_result.values
    if not targets:
        return {
            "ok": False,
            "domain": clean,
            "error": "no NS records found, so there is nothing to test",
            "nameservers": [],
            "records": [],
        }

    attempts: list[dict[str, Any]] = []
    transferred: list[str] = []
    for target in targets:
        address = target
        if not validate_ip(target).ok:
            resolved = lookup(target, "A", timeout=timeout)
            address = resolved.values[0] if resolved.values else target
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(address, clean, timeout=timeout, lifetime=timeout * 2))
            records = sorted(str(name) for name in zone.nodes.keys())
            transferred.append(str(target))
            attempts.append(
                {
                    "nameserver": target,
                    "address": address,
                    "result": "TRANSFER SUCCEEDED",
                    "records": records,
                }
            )
        except Exception as exc:  # noqa: BLE001 - refusal is expected
            attempts.append(
                {
                    "nameserver": target,
                    "address": address,
                    "result": "refused or failed",
                    "reason": type(exc).__name__,
                }
            )

    return {
        "ok": bool(transferred),
        "domain": clean,
        "nameservers": attempts,
        "records": sorted({r for a in attempts for r in a.get("records", [])}),
        "note": (
            "A successful transfer means the nameserver is misconfigured and leaks the "
            "complete zone — treat it as a finding."
            if transferred
            else "Every nameserver refused the transfer, which is the correct configuration."
        ),
    }


def _mx_host(value: str) -> str:
    """Extract the host from an MX value rendered as ``"<priority> <host>"``.

    Tolerates the legacy ``priority=`` form so records cached by an older build
    still parse, and returns an empty string when no host can be recovered.
    """
    text = (value or "").strip()
    if not text:
        return ""
    parts = text.split()
    host = parts[-1] if parts else ""
    if host.startswith("priority="):
        host = host.split("=", 1)[1]
    host = host.rstrip(".")
    # A bare priority with no host is not a usable target.
    return "" if host.isdigit() else host


def diagnose(domain: str, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """A compact diagnostic used by the DNS menu."""
    clean = validate_domain(domain).raise_if_invalid("domain")
    checks: list[dict[str, Any]] = []

    ns = lookup(clean, "NS", timeout=timeout)
    checks.append(
        {
            "check": "NS records",
            "ok": ns.ok,
            "detail": ", ".join(ns.values) if ns.ok else (ns.error or "none"),
        }
    )

    soa = lookup(clean, "SOA", timeout=timeout)
    checks.append(
        {
            "check": "SOA record",
            "ok": soa.ok,
            "detail": soa.values[0] if soa.ok else (soa.error or "none"),
        }
    )

    a = lookup(clean, "A", timeout=timeout)
    aaaa = lookup(clean, "AAAA", timeout=timeout)
    checks.append(
        {
            "check": "Address records",
            "ok": a.ok or aaaa.ok,
            "detail": f"A={', '.join(a.values) or 'none'}; AAAA={', '.join(aaaa.values) or 'none'}",
        }
    )

    mx = lookup(clean, "MX", timeout=timeout)
    checks.append(
        {
            "check": "MX records",
            "ok": mx.ok,
            "detail": ", ".join(mx.values) if mx.ok else (mx.error or "none"),
        }
    )

    txt = lookup(clean, "TXT", timeout=timeout)
    spf = [value for value in txt.values if value.lower().startswith("v=spf1")]
    dmarc = lookup("_dmarc." + clean, "TXT", timeout=timeout)
    dmarc_values = [value for value in dmarc.values if value.lower().startswith("v=dmarc1")]
    checks.append(
        {
            "check": "SPF record",
            "ok": bool(spf),
            "detail": spf[0] if spf else "none — mail from this domain can be spoofed",
        }
    )
    checks.append(
        {
            "check": "DMARC record",
            "ok": bool(dmarc_values),
            "detail": dmarc_values[0] if dmarc_values else "none — no policy for failed SPF/DKIM",
        }
    )

    caa = lookup(clean, "CAA", timeout=timeout)
    checks.append(
        {
            "check": "CAA records",
            "ok": caa.ok,
            "detail": ", ".join(caa.values) if caa.ok else "none — any CA may issue certificate",
        }
    )

    # MX targets must resolve, or mail silently fails.
    mx_problems: list[str] = []
    for value in mx.values:
        host = _mx_host(value)
        if host and not lookup(host, "A", timeout=timeout).ok and not lookup(host, "AAAA", timeout=timeout).ok:
            mx_problems.append(host)
    checks.append(
        {
            "check": "MX targets resolve",
            "ok": not mx_problems,
            "detail": "all MX hosts resolve" if not mx_problems else "unresolvable: " + ", ".join(mx_problems),
        }
    )

    wildcard = lookup("kingdomx-wildcard-probe-9f3a." + clean, "A", timeout=timeout)
    checks.append(
        {
            "check": "Wildcard DNS",
            "ok": True,
            "detail": "present — every subdomain resolves" if wildcard.ok else "absent",
        }
    )

    passed = sum(1 for check in checks if check["ok"])
    return {
        "domain": clean,
        "backend": default_backend().value,
        "checks": checks,
        "passed": passed,
        "total": len(checks),
        "note": (
            "An SPF/DMARC 'ok' here means a syntactically valid record exists; it does "
            "not prove the policy is enforced at the receiving end."
        ),
    }


def whois_servers_hint() -> dict[str, str]:
    """Registry hints, for the terminal help panel."""
    return {
        "iana": "https://www.iana.org/domains/root/db",
        "rdap_bootstrap": "https://rdap.org/",
        "note": "KINGDOM X uses RDAP (structured JSON) rather than port-43 WHOIS.",
    }


def parse_resolv_conf(path: str = "/etc/resolv.conf") -> list[str]:
    """Read the configured nameservers."""
    from pathlib import Path

    target = Path(path)
    servers: list[str] = []
    try:
        for line in target.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver" and validate_ip(parts[1]).ok:
                servers.append(parts[1])
    except OSError:
        return []
    return servers
