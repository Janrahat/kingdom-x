"""Domain Intelligence.

Registry data comes from RDAP (structured JSON, the IETF successor to port-43
WHOIS). Nothing here guesses: a failed RDAP call reports the failure.
"""

from kingdomx.domains.rdap import (
    DomainRecord,
    rdap_lookup,
    domain_report,
    homograph_check,
    registrars_note,
)

__all__ = ["DomainRecord", "rdap_lookup", "domain_report", "homograph_check", "registrars_note"]
