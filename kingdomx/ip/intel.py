"""IP address classification, geolocation and ASN lookup.

The classification part is pure and offline. Geolocation calls a real API and is
labelled with the provider name and the fetch time, because geolocation is an
*approximation* — city-level accuracy from a free database is tens of kilometres
at best, and an ISP-level toggle changes what you get.
"""

from __future__ import annotations

import ipaddress
import socket
import statistics
import time
from dataclasses import dataclass, field
from typing import Any

from kingdomx.core.errors import NetworkError, UnsafeTargetError, ValidationError
from kingdomx.core.http import SafeHttpClient
from kingdomx.core.logging_setup import get_logger
from kingdomx.core.validation import is_private_address, validate_ip

log = get_logger("ip.intel")

IPAPI_URL = "https://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
IPAPI_SELF_URL = "https://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
RDAP_IP_URL = "https://rdap.org/ip/{ip}"

#: How to describe the special-purpose ranges, from RFC 6890 and friends.
SPECIAL_RANGES: tuple[tuple[str, str, str], ...] = (
    ("0.0.0.0/8", "this-network", "RFC 1122: 'this network', never a valid destination."),
    ("10.0.0.0/8", "private", "RFC 1918 private space."),
    ("100.64.0.0/10", "cgnat", "RFC 6598 carrier-grade NAT; not reachable from the internet."),
    ("127.0.0.0/8", "loopback", "RFC 1122 loopback — this machine only."),
    ("169.254.0.0/16", "link-local", "RFC 3927 APIPA; a sign DHCP failed."),
    ("172.16.0.0/12", "private", "RFC 1918 private space."),
    ("192.0.0.0/24", "ietf", "RFC 6890 IETF protocol assignments."),
    ("192.0.2.0/24", "documentation", "TEST-NET-1, documentation only."),
    ("192.88.99.0/24", "6to4-relay", "Deprecated 6to4 relay anycast."),
    ("192.168.0.0/16", "private", "RFC 1918 private space."),
    ("198.18.0.0/15", "benchmark", "RFC 2544 benchmarking."),
    ("198.51.100.0/24", "documentation", "TEST-NET-2, documentation only."),
    ("203.0.113.0/24", "documentation", "TEST-NET-3, documentation only."),
    ("224.0.0.0/4", "multicast", "RFC 5771 multicast."),
    ("240.0.0.0/4", "reserved", "Reserved, except the broadcast address."),
    ("255.255.255.255/32", "broadcast", "Limited broadcast."),
    ("::1/128", "loopback", "IPv6 loopback."),
    ("::/128", "unspecified", "IPv6 unspecified address."),
    ("fc00::/7", "private", "RFC 4193 unique local address."),
    ("fe80::/10", "link-local", "IPv6 link-local."),
    ("ff00::/8", "multicast", "IPv6 multicast."),
    ("2001:db8::/32", "documentation", "IPv6 documentation prefix."),
)


@dataclass
class IpInfo:
    """What we can say about an address without leaving the machine."""

    address: str
    version: int
    kind: str
    """``global``, ``private``, ``loopback``, ``link-local``, ``cgnat`` …"""

    notes: str
    is_global: bool
    is_private: bool
    is_multicast: bool
    is_reserved: bool
    reverse_dns: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "version": self.version,
            "kind": self.kind,
            "notes": self.notes,
            "is_global": self.is_global,
            "is_private": self.is_private,
            "is_multicast": self.is_multicast,
            "is_reserved": self.is_reserved,
            "reverse_dns": self.reverse_dns,
        }

    @property
    def reachable_from_internet(self) -> bool:
        return self.is_global


def _match_special(addr) -> tuple[str, str] | None:
    for cidr, kind, notes in SPECIAL_RANGES:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return kind, notes
        except ValueError:
            continue
    return None


def classify(address: str) -> IpInfo:
    """Classify an address with no network access."""
    check = validate_ip(address)
    if not check.ok:
        raise ValidationError(f"not an IP address: {address}", detail=check.reason)
    addr = ipaddress.ip_address(check.normalised or address)

    special = _match_special(addr)
    if special:
        kind, notes = special
    elif addr.is_multicast:
        kind, notes = "multicast", "Multicast address."
    elif addr.is_loopback:
        kind, notes = "loopback", "Loopback — this machine only."
    elif addr.is_link_local:
        kind, notes = "link-local", "Link-local; not routable beyond the local segment."
    elif is_private_address(addr):
        kind, notes = "private", "Not globally routable."
    elif addr.is_global:
        kind, notes = "global", "Globally routable unicast address."
    else:
        kind, notes = "reserved", "Reserved or otherwise not globally routable."

    info = IpInfo(
        address=str(addr),
        version=addr.version,
        kind=kind,
        notes=notes,
        is_global=bool(addr.is_global),
        is_private=is_private_address(addr),
        is_multicast=bool(addr.is_multicast),
        is_reserved=bool(addr.is_reserved),
    )
    info.reverse_dns = _reverse_dns(str(addr))
    return info


def _reverse_dns(address: str, *, timeout: float = 3.0) -> str | None:
    """Best-effort PTR, without raising when there is none."""
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _aliases, _addresses = socket.gethostbyaddr(address)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous)


def is_private(address: str) -> bool:
    try:
        return is_private_address(ipaddress.ip_address(address))
    except ValueError:
        return False


# --------------------------------------------------------------------------- geo
@dataclass
class GeoResult:
    """Approximate geolocation from a documented public API."""

    query: str
    status: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    postal: str = ""
    latitude: float | None = None
    longitude: float | None = None
    timezone: str = ""
    isp: str = ""
    organization: str = ""
    asn: str = ""
    as_name: str = ""
    is_mobile: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    source: str = "ip-api.com"
    fetched_at: float = field(default_factory=time.time)
    error: str | None = None
    skipped_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "success" and not self.error

    @property
    def approx_location(self) -> str:
        parts = [part for part in (self.city, self.region, self.country) if part]
        return ", ".join(parts) if parts else "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "status": self.status,
            "source": self.source,
            "fetched_at": self.fetched_at,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "postal": self.postal,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "isp": self.isp,
            "organization": self.organization,
            "asn": self.asn,
            "as_name": self.as_name,
            "is_mobile": self.is_mobile,
            "is_proxy": self.is_proxy,
            "is_hosting": self.is_hosting,
            "approx_location": self.approx_location,
            "error": self.error,
            "skipped_reason": self.skipped_reason,
            "accuracy_note": (
                "Coordinates are the ISP's registered network centroid, not a device "
                "location. Expect tens of kilometres of error."
            ),
        }


@dataclass
class AsnResult:
    """ASN and organisation, from the same source as geo."""

    query: str
    asn: str = ""
    as_name: str = ""
    organization: str = ""
    route: str | None = None
    source: str = "ip-api.com"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "asn": self.asn,
            "as_name": self.as_name,
            "organization": self.organization,
            "route": self.route,
            "source": self.source,
            "error": self.error,
        }


def geolocate(
    address: str,
    *,
    timeout: float = 8.0,
    allow_private: bool = False,
    client: SafeHttpClient | None = None,
) -> GeoResult:
    """Look up an address in a public geolocation database."""
    check = validate_ip(address)
    if not check.ok:
        return GeoResult(
            query=address, status="fail", error=f"not an IP address: {check.reason}"
        )
    clean = check.normalised or address

    if is_private(clean) and not allow_private:
        return GeoResult(
            query=clean,
            status="skipped",
            skipped_reason=(
                "private/loopback address — it is not in any public geolocation "
                "database, so no lookup was attempted"
            ),
            error=None,
        )

    http = client or SafeHttpClient(timeout=timeout, user_agent="KingdomX/1.0 ip-intel")
    try:
        response = http.get(IPAPI_URL.format(ip=clean), timeout=timeout)
    except (NetworkError, UnsafeTargetError) as exc:
        return GeoResult(query=clean, status="error", error=exc.message)

    if response.status >= 400:
        return GeoResult(
            query=clean, status="error", error=f"geolocation API returned HTTP {response.status}"
        )

    try:
        data = response.json()
    except NetworkError as exc:
        return GeoResult(query=clean, status="error", error=exc.message)

    if not isinstance(data, dict):
        return GeoResult(query=clean, status="error", error="unexpected response shape")

    if data.get("status") != "success":
        return GeoResult(
            query=clean,
            status=str(data.get("status") or "fail"),
            error=str(data.get("message") or "lookup failed"),
        )

    return GeoResult(
        query=str(data.get("query") or clean),
        status="success",
        country=str(data.get("country") or ""),
        country_code=str(data.get("countryCode") or ""),
        region=str(data.get("regionName") or ""),
        city=str(data.get("city") or ""),
        postal=str(data.get("zip") or ""),
        latitude=_as_float(data.get("lat")),
        longitude=_as_float(data.get("lon")),
        timezone=str(data.get("timezone") or ""),
        isp=str(data.get("isp") or ""),
        organization=str(data.get("org") or ""),
        asn=str(data.get("as") or "").split(" ")[0] if data.get("as") else "",
        as_name=str(data.get("asname") or ""),
        is_mobile=bool(data.get("mobile")),
        is_proxy=bool(data.get("proxy")),
        is_hosting=bool(data.get("hosting")),
    )


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def asn_lookup(address: str, *, timeout: float = 8.0) -> AsnResult:
    """ASN/organisation lookup, reusing the geo response (one call, not two)."""
    geo = geolocate(address, timeout=timeout)
    if not geo.ok:
        return AsnResult(query=address, error=geo.error or geo.skipped_reason)
    return AsnResult(
        query=geo.query,
        asn=geo.asn,
        as_name=geo.as_name,
        organization=geo.organization,
        error=None,
    )


def rdap_network(address: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Registry data (RDAP) for the network block containing ``address``."""
    check = validate_ip(address)
    if not check.ok:
        return {"ok": False, "address": address, "error": check.reason}
    clean = check.normalised or address
    if is_private(clean):
        return {
            "ok": False,
            "address": clean,
            "error": "private address — no registry record exists",
        }

    client = SafeHttpClient(timeout=timeout, user_agent="KingdomX/1.0 rdap")
    try:
        response = client.get(RDAP_IP_URL.format(ip=clean), timeout=timeout)
    except (NetworkError, UnsafeTargetError) as exc:
        return {"ok": False, "address": clean, "error": exc.message}

    if response.status == 404:
        return {"ok": False, "address": clean, "error": "no RDAP record for this address"}
    if response.status >= 400:
        return {
            "ok": False,
            "address": clean,
            "error": f"RDAP returned HTTP {response.status}",
        }

    try:
        data = response.json()
    except NetworkError as exc:
        return {"ok": False, "address": clean, "error": exc.message}

    return {
        "ok": True,
        "address": clean,
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "ip_version": data.get("ipVersion"),
        "country": data.get("country"),
        "parent_handle": data.get("parentHandle"),
        "status": data.get("status") or [],
        "entities": _rdap_entities(data.get("entities") or []),
        "source": "rdap.org",
        "fetched_at": time.time(),
    }


def _rdap_entities(entities: list[Any], *, depth: int = 0) -> list[dict[str, Any]]:
    """Flatten RDAP entities into ``{role, name, abn}``."""
    out: list[dict[str, Any]] = []
    if depth > 2:
        return out
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        name = ""
        for vcard in entity.get("vcardArray") or []:
            for item in vcard if isinstance(vcard, list) else []:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    name = str(item[3])
                    break
        out.append(
            {
                "handle": entity.get("handle"),
                "roles": entity.get("roles") or [],
                "name": name,
            }
        )
        out.extend(_rdap_entities(entity.get("entities") or [], depth=depth + 1))
    return out


# --------------------------------------------------------------------------- local
def local_interfaces() -> list[dict[str, Any]]:
    """This machine's interfaces, via psutil when available."""
    try:
        import psutil
    except ModuleNotFoundError:
        return _local_interfaces_fallback()

    interfaces: list[dict[str, Any]] = []
    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception as exc:  # noqa: BLE001 - psutil raises OSError variants
        log.debug("psutil interface read failed: %s", exc)
        return _local_interfaces_fallback()

    for name, entries in addresses.items():
        stat = stats.get(name)
        for entry in entries:
            if entry.family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            address = entry.address.split("%")[0]
            interfaces.append(
                {
                    "interface": name,
                    "family": "IPv4" if entry.family == socket.AF_INET else "IPv6",
                    "address": address,
                    "netmask": entry.netmask,
                    "broadcast": entry.broadcast,
                    "kind": classify(address).kind if validate_ip(address).ok else "unknown",
                    "is_up": bool(stat.isup) if stat else None,
                    "speed_mbps": stat.speed if stat else None,
                }
            )
    return sorted(interfaces, key=lambda item: (item["interface"], item["family"]))


def _local_interfaces_fallback() -> list[dict[str, Any]]:
    """Without psutil, report only the primary address."""
    out: list[dict[str, Any]] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            address = info[4][0].split("%")[0]
            if any(item["address"] == address for item in out):
                continue
            out.append(
                {
                    "interface": "(primary)",
                    "family": "IPv4" if info[0] == socket.AF_INET else "IPv6",
                    "address": address,
                    "netmask": None,
                    "broadcast": None,
                    "kind": classify(address).kind if validate_ip(address).ok else "unknown",
                    "is_up": True,
                    "speed_mbps": None,
                    "note": "psutil not installed: only the primary address is shown",
                }
            )
    except OSError:
        pass
    return out


def my_public_ip(*, timeout: float = 8.0) -> dict[str, Any]:
    """This machine's public egress address, from a documented API."""
    client = SafeHttpClient(timeout=timeout, user_agent="KingdomX/1.0 ip-intel")
    try:
        response = client.get(IPAPI_SELF_URL, timeout=timeout)
    except (NetworkError, UnsafeTargetError) as exc:
        return {"ok": False, "error": exc.message}
    if response.status >= 400:
        return {"ok": False, "error": f"HTTP {response.status}"}
    try:
        data = response.json()
    except NetworkError as exc:
        return {"ok": False, "error": exc.message}
    if not isinstance(data, dict) or data.get("status") != "success":
        return {"ok": False, "error": str(data.get("message") if isinstance(data, dict) else "bad response")}
    return {
        "ok": True,
        "ip": data.get("query"),
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "organization": data.get("org"),
        "asn": (data.get("as") or "").split(" ")[0] if data.get("as") else "",
        "proxy_detected": bool(data.get("proxy")),
        "hosting": bool(data.get("hosting")),
        "source": "ip-api.com",
        "note": "This is the address the internet sees for this machine, not a device location.",
    }


# --------------------------------------------------------------------------- latency
#: Reachable, operator-independent targets for a latency measurement.
LATENCY_TARGETS: dict[str, tuple[str, int]] = {
    "cloudflare-dns": ("1.1.1.1", 53),
    "google-dns": ("8.8.8.8", 53),
    "quad9-dns": ("9.9.9.9", 53),
    "cloudflare-https": ("1.1.1.1", 443),
    "google-https": ("8.8.8.8", 443),
}


def tcp_ping(host: str, port: int, *, timeout: float = 3.0, attempts: int = 4) -> dict[str, Any]:
    """Measure TCP handshake latency — no raw socket, no root needed."""
    samples: list[float] = []
    failures = 0
    for _ in range(max(1, attempts)):
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                samples.append((time.perf_counter() - started) * 1000)
        except OSError:
            failures += 1

    if not samples:
        return {
            "host": host,
            "port": port,
            "ok": False,
            "error": "no successful handshake",
            "attempts": attempts,
            "failures": failures,
        }
    return {
        "host": host,
        "port": port,
        "ok": True,
        "attempts": attempts,
        "failures": failures,
        "min_ms": round(min(samples), 1),
        "max_ms": round(max(samples), 1),
        "avg_ms": round(sum(samples) / len(samples), 1),
        "jitter_ms": round(statistics.pstdev(samples), 1) if len(samples) > 1 else 0.0,
    }


def latency_test(
    targets: dict[str, tuple[str, int]] | None = None,
    *,
    timeout: float = 3.0,
    attempts: int = 3,
) -> dict[str, Any]:
    """Measure TCP latency to several well-known endpoints."""
    chosen = targets or LATENCY_TARGETS
    results: dict[str, Any] = {}
    for name, (host, port) in chosen.items():
        results[name] = tcp_ping(host, port, timeout=timeout, attempts=attempts)

    successful = [r["avg_ms"] for r in results.values() if r.get("ok")]
    return {
        "results": results,
        "reachable": len(successful),
        "total": len(results),
        "median_avg_ms": round(statistics.median(successful), 1) if successful else None,
        "note": "TCP handshake time. ICMP ping is often blocked and would understate reachability.",
    }


def ip_info(address: str, *, network: bool = True, timeout: float = 8.0) -> dict[str, Any]:
    """The full picture for one address: classification, geo, ASN, RDAP."""
    info = classify(address)
    payload: dict[str, Any] = {"classification": info.to_dict(), "network_used": network}
    if not network:
        payload["note"] = "network lookups were disabled; only local classification is shown"
        return payload

    if info.is_private:
        payload["geo"] = geolocate(address).to_dict()
        payload["note"] = (
            "Private address: geolocation and registry lookups are meaningless, so none "
            "were attempted."
        )
        return payload

    payload["geo"] = geolocate(address, timeout=timeout).to_dict()
    payload["rdap"] = rdap_network(address, timeout=timeout)
    return payload
