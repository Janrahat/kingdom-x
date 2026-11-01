"""DNS Intelligence.

Real queries via :mod:`dns.resolver` when dnspython is installed, otherwise the
system resolver through ``socket``. Every result records which backend produced
it and how long it took, so a report can state its own provenance.
"""

from kingdomx.dns.lookup import (
    DnsAnswer,
    DnsResult,
    Backend,
    available_backends,
    lookup,
    lookup_all,
    reverse_lookup,
    zone_transfer,
    diagnose,
)

__all__ = [
    "DnsAnswer",
    "DnsResult",
    "Backend",
    "available_backends",
    "lookup",
    "lookup_all",
    "reverse_lookup",
    "zone_transfer",
    "diagnose",
]
