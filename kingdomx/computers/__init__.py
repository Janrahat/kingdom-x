"""Computer and OS Intelligence — real local system information.

Everything here is read from ``/proc``, ``/sys``, ``platform`` and ``psutil`` on
the machine KINGDOM X is running on. There is no remote agent and no claim about
any other computer.
"""

from kingdomx.computers.system import (
    SystemSnapshot,
    collect,
    disk_usage,
    processes,
    services,
    health_report,
    installed_packages,
    kernel_info,
)

__all__ = [
    "SystemSnapshot",
    "collect",
    "disk_usage",
    "processes",
    "services",
    "health_report",
    "installed_packages",
    "kernel_info",
]
