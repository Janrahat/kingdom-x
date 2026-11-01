"""Network Intelligence.

Local network inspection uses ``psutil`` / ``/proc``; remote inspection is
gated behind explicit authorization (:mod:`kingdomx.core.authorization`).
"""

from kingdomx.network.local import (
    listening_ports,
    connections,
    routes,
    interface_table,
    arp_table,
    bandwidth,
)
from kingdomx.network.scan import (
    ScanResult,
    authorize_and_scan,
    parse_nmap_output,
)

__all__ = [
    "listening_ports",
    "connections",
    "routes",
    "interface_table",
    "arp_table",
    "bandwidth",
    "ScanResult",
    "authorize_and_scan",
    "parse_nmap_output",
]
