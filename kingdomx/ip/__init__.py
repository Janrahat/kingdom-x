"""IP and network intelligence.

Sources, all real and all documented:

* ``ip-api.com`` free tier — geolocation and ASN (no key, rate limited)
* ``rdap.org`` — registry data for an address block
* local ``psutil`` — this machine's own interfaces and routes

Every result records its source and fetch time. When a lookup fails the module
says which source failed and why; it never fills a gap with a guess.
"""

from kingdomx.ip.intel import (
    IpInfo,
    GeoResult,
    AsnResult,
    ip_info,
    is_private,
    classify,
    local_interfaces,
    my_public_ip,
    LATENCY_TARGETS,
    latency_test,
)

__all__ = [
    "IpInfo",
    "GeoResult",
    "AsnResult",
    "ip_info",
    "is_private",
    "classify",
    "local_interfaces",
    "my_public_ip",
    "LATENCY_TARGETS",
    "latency_test",
]
