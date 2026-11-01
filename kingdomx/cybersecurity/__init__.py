"""Cybersecurity Center.

Defensive-first. Every active operation is gated by
:func:`kingdomx.core.authorization.require_authorization`, and passive checks
(header inspection, TLS read, local file integrity) run without ceremony.

Module map
----------
``severity``      shared finding model
``ports``         port and service knowledge base
``tools``         detection of installed security tooling
``headers``       HTTP security-header audit (passive)
``tls``           certificate inspection (passive)
``passwords``     password strength audit (local, offline)
``integrity``     file integrity monitoring (local)
``dependencies``  dependency vulnerability scan (local manifests)
``logs``          log analysis (local)
``audit``         Linux host configuration audit (local, read-only)
"""

from kingdomx.cybersecurity.severity import Finding, Severity, summarise_findings

__all__ = ["Finding", "Severity", "summarise_findings"]
