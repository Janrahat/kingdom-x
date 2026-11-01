"""TLS certificate inspection.

Reads the certificate a host actually presents, using Python's own ``ssl`` module
so there is no dependency on the ``openssl`` binary being installed. Everything
here is a read of public material — the same handshake a browser performs.

We deliberately report *what the certificate says*, not what a third-party API
claims about it.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from kingdomx.core.errors import NetworkError, UnsafeTargetError, ValidationError
from kingdomx.core.validation import check_target_safe, validate_domain, validate_host
from kingdomx.cybersecurity.severity import Finding, Report, Severity

DEFAULT_TIMEOUT = 10.0

#: Protocols we consider acceptable for a public endpoint.
DEPRECATED_PROTOCOLS = frozenset({"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"})


@dataclass
class CertificateInfo:
    """The facts extracted from a peer certificate."""

    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    subject_alt_names: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    serial: str | None = None
    version: int | None = None
    signature_algorithm: str | None = None
    days_remaining: int | None = None
    expired: bool = False
    not_yet_valid: bool = False
    self_signed: bool = False
    san_matches_host: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": dict(self.subject),
            "issuer": dict(self.issuer),
            "subject_alt_names": list(self.subject_alt_names),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial": self.serial,
            "version": self.version,
            "signature_algorithm": self.signature_algorithm,
            "days_remaining": self.days_remaining,
            "expired": self.expired,
            "not_yet_valid": self.not_yet_valid,
            "self_signed": self.self_signed,
            "san_matches_host": self.san_matches_host,
        }


@dataclass
class TlsResult:
    host: str
    port: int
    connected: bool
    protocol: str | None = None
    cipher: str | None = None
    bits: int | None = None
    certificate: CertificateInfo | None = None
    chain_length: int = 0
    error: str | None = None
    error_code: str | None = None
    elapsed_ms: float = 0.0
    verify_mode: str = "CERT_REQUIRED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "connected": self.connected,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "bits": self.bits,
            "chain_length": self.chain_length,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "error": self.error,
            "error_code": self.error_code,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "verify_mode": self.verify_mode,
        }


def _parse_asn1_time(value: str) -> datetime | None:
    """Parse the two ASN.1 time formats Python returns."""
    if not value:
        return None
    text = value.strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _flatten_name(name: Any) -> dict[str, str]:
    """Turn the nested RDN tuple into ``{field: value}``."""
    out: dict[str, str] = {}
    if not name:
        return out
    for rdn in name:
        for key, value in rdn:
            out[str(key)] = str(value)
    return out


def _extract_sans(cert: dict[str, Any]) -> list[str]:
    sans: list[str] = []
    for key in ("subjectAltName", "subjectAltNames"):
        raw = cert.get(key)
        if not raw:
            continue
        for entry in str(raw).split(","):
            part = entry.strip()
            if not part:
                continue
            if ":" in part:
                kind, _, value = part.partition(":")
                if kind.strip().upper() in {"DNS", "IP ADDRESS", "IP"}:
                    sans.append(value.strip())
            else:
                sans.append(part)
    return sans


def inspect_certificate(
    host: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = True,
    server_hostname: str | None = None,
) -> TlsResult:
    """Perform a real TLS handshake and describe the certificate."""
    host_check = validate_host(host)
    if not host_check.ok:
        return TlsResult(
            host=host, port=port, connected=False,
            error=f"invalid host: {host_check.reason}", error_code="kingdomx.validation",
        )
    clean_host = (host_check.normalised or host).split(":")[0]

    if not 1 <= int(port) <= 65535:
        raise ValidationError(f"invalid port: {port}")

    try:
        check_target_safe(clean_host, allow_private=False)
    except UnsafeTargetError as exc:
        return TlsResult(
            host=clean_host, port=port, connected=False,
            error=exc.message, error_code=exc.code,
        )

    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    started = time.perf_counter()
    try:
        with socket.create_connection((clean_host, int(port)), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_hostname or clean_host) as tls:
                cert = tls.getpeercert() or {}
                protocol = tls.version()
                cipher_info = tls.cipher()
                chain = getattr(tls, "get_verified_chain", lambda: [])() or getattr(
                    tls, "get_unverified_chain", lambda: []
                )()
                elapsed = (time.perf_counter() - started) * 1000
    except ssl.SSLCertVerificationError as exc:
        return TlsResult(
            host=clean_host, port=port, connected=True,
            error=f"certificate verification failed: {exc.verify_message or exc}",
            error_code="kingdomx.tls.verify_failed",
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
    except ssl.SSLError as exc:
        return TlsResult(
            host=clean_host, port=port, connected=False,
            error=f"TLS handshake failed: {exc.reason or exc}",
            error_code="kingdomx.tls.handshake",
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
    except (socket.timeout, TimeoutError):
        return TlsResult(
            host=clean_host, port=port, connected=False,
            error=f"timed out after {timeout}s",
            error_code="kingdomx.tls.timeout",
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
    except OSError as exc:
        return TlsResult(
            host=clean_host, port=port, connected=False,
            error=f"connection failed: {exc.strerror or exc}",
            error_code="kingdomx.tls.connect",
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )

    info = CertificateInfo(
        subject=_flatten_name(cert.get("subject")),
        issuer=_flatten_name(cert.get("issuer")),
        subject_alt_names=_extract_sans(cert),
        not_before=cert.get("notBefore"),
        not_after=cert.get("notAfter"),
        serial=str(cert.get("serialNumber", "")) or None,
        version=cert.get("version"),
    )

    not_after = _parse_asn1_time(info.not_after or "")
    not_before = _parse_asn1_time(info.not_before or "")
    now = datetime.now(timezone.utc)
    if not_after:
        info.days_remaining = int((not_after - now).total_seconds() // 86400)
        info.expired = not_after < now
    if not_before:
        info.not_yet_valid = not_before > now
    info.self_signed = bool(info.subject) and info.subject == info.issuer
    info.san_matches_host = _san_matches(clean_host, info.subject_alt_names, info.subject) if cert else None

    return TlsResult(
        host=clean_host,
        port=int(port),
        connected=True,
        protocol=protocol,
        cipher=cipher_info[0] if cipher_info else None,
        bits=cipher_info[2] if cipher_info and len(cipher_info) > 2 else None,
        certificate=info,
        chain_length=len(chain) if chain else 0,
        elapsed_ms=elapsed,
    )


def _san_matches(host: str, sans: list[str], subject: dict[str, str]) -> bool:
    """Does any SAN (or the CN) cover ``host``, allowing one leading wildcard?"""
    needle = host.lower().rstrip(".")

    def matches(pattern: str) -> bool:
        pattern = pattern.lower().rstrip(".")
        if pattern == needle:
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if "." not in needle:
                return False
            # A wildcard covers exactly one label.
            return needle.split(".", 1)[1] == suffix
        return False

    if any(matches(san) for san in sans):
        return True
    common_name = subject.get("commonName", "")
    return bool(common_name) and matches(common_name)


def grade(result: TlsResult) -> list[Finding]:
    """Turn a TLS result into findings."""
    findings: list[Finding] = []

    if not result.connected:
        findings.append(
            Finding(
                title="Could not establish a TLS connection",
                severity=Severity.HIGH,
                category="transport",
                detail=result.error or "handshake did not complete",
                remediation="Confirm the host serves HTTPS on this port and that a valid "
                "certificate is deployed.",
            )
        )
        return findings

    if result.error and "verification failed" in (result.error or ""):
        findings.append(
            Finding(
                title="Certificate failed verification",
                severity=Severity.CRITICAL,
                category="transport",
                detail=result.error,
                remediation="Deploy a chain that chains to a trusted root for this hostname.",
            )
        )

    if result.protocol and result.protocol in DEPRECATED_PROTOCOLS:
        findings.append(
            Finding(
                title=f"Deprecated TLS version negotiated: {result.protocol}",
                severity=Severity.CRITICAL,
                category="transport",
                detail="Only TLS 1.2 and 1.3 are considered safe.",
                reference="https://datatracker.ietf.org/doc/rfc8996/",
            )
        )
    elif result.protocol:
        findings.append(
            Finding(
                title=f"Negotiated {result.protocol} with {result.cipher or 'unknown cipher'}",
                severity=Severity.INFO,
                category="transport",
                evidence=f"{result.protocol} / {result.cipher} / {result.bits or '?'} bits",
                passed=True,
            )
        )

    cert = result.certificate
    if cert is None:
        findings.append(
            Finding(
                title="No certificate presented",
                severity=Severity.HIGH,
                category="transport",
                detail="The handshake completed without a peer certificate.",
            )
        )
        return findings

    if cert.expired:
        findings.append(
            Finding(
                title="Certificate has expired",
                severity=Severity.CRITICAL,
                category="certificate",
                detail=f"notAfter = {cert.not_after}",
                remediation="Renew the certificate and automate renewal.",
            )
        )
    elif cert.days_remaining is not None:
        if cert.days_remaining <= 14:
            findings.append(
                Finding(
                    title=f"Certificate expires in {cert.days_remaining} days",
                    severity=Severity.HIGH,
                    category="certificate",
                    detail=f"notAfter = {cert.not_after}",
                    remediation="Renew now; a short-notice expiry is how outages happen.",
                )
            )
        elif cert.days_remaining <= 30:
            findings.append(
                Finding(
                    title=f"Certificate expires in {cert.days_remaining} days",
                    severity=Severity.MEDIUM,
                    category="certificate",
                    detail=f"notAfter = {cert.not_after}",
                    remediation="Schedule renewal and confirm automation is working.",
                )
            )
        else:
            findings.append(
                Finding(
                    title=f"Certificate valid for {cert.days_remaining} days",
                    severity=Severity.INFO,
                    category="certificate",
                    evidence=f"notAfter = {cert.not_after}",
                    passed=True,
                )
            )

    if cert.not_yet_valid:
        findings.append(
            Finding(
                title="Certificate is not yet valid",
                severity=Severity.HIGH,
                category="certificate",
                detail=f"notBefore = {cert.not_before}",
                remediation="Check the issuing host's clock; a future notBefore breaks clients.",
            )
        )

    if cert.self_signed:
        findings.append(
            Finding(
                title="Certificate is self-signed",
                severity=Severity.HIGH,
                category="certificate",
                detail="Subject and issuer are identical; no public client will trust it.",
                remediation="Use a certificate from a publicly trusted CA (e.g. Let's Encrypt).",
            )
        )

    if cert.san_matches_host is False:
        findings.append(
            Finding(
                title="Certificate does not cover this hostname",
                severity=Severity.CRITICAL,
                category="certificate",
                detail=f"Checked against {result.host}",
                evidence="SANs: " + (", ".join(cert.subject_alt_names) or "(none)"),
                remediation="Issue a certificate whose SAN list includes this exact hostname.",
            )
        )
    elif cert.san_matches_host:
        findings.append(
            Finding(
                title="Certificate covers this hostname",
                severity=Severity.INFO,
                category="certificate",
                passed=True,
                evidence="SANs: " + ", ".join(cert.subject_alt_names[:8]),
            )
        )

    issuer_cn = cert.issuer.get("commonName") or cert.issuer.get("organizationName") or "unknown"
    findings.append(
        Finding(
            title=f"Issued by {issuer_cn}",
            severity=Severity.INFO,
            category="certificate",
            passed=True,
            evidence="subject: "
            + (cert.subject.get("commonName") or "unknown")
            + f"; chain length {result.chain_length}",
        )
    )

    return findings


def tls_report(host: str, port: int = 443, *, timeout: float = DEFAULT_TIMEOUT) -> Report:
    """Full inspection wrapped in the standard report shape."""
    report = Report(module="tls", target=f"{host}:{port}", started_at=time.time())
    result = inspect_certificate(host, port, timeout=timeout)
    report.findings.extend(grade(result))
    report.meta = result.to_dict()
    report.finished_at = time.time()
    if not result.connected:
        report.errors.append(result.error or "no TLS connection")
    return report


def quick_check(host: str, port: int = 443, *, timeout: float = 6.0) -> dict[str, Any]:
    """A minimal summary used by the website module."""
    result = inspect_certificate(host, port, timeout=timeout)
    if not result.connected or result.certificate is None:
        return {
            "host": host,
            "port": port,
            "ok": False,
            "error": result.error,
            "protocol": result.protocol,
        }
    cert = result.certificate
    return {
        "host": host,
        "port": port,
        "ok": not (cert.expired or cert.not_yet_valid) and cert.san_matches_host is not False,
        "protocol": result.protocol,
        "cipher": result.cipher,
        "issuer": cert.issuer.get("commonName") or cert.issuer.get("organizationName"),
        "expires": cert.not_after,
        "days_remaining": cert.days_remaining,
        "expired": cert.expired,
        "self_signed": cert.self_signed,
        "matches_host": cert.san_matches_host,
        "error": result.error,
    }
