"""Web dashboard.

The dashboard is **read-only by design**: it exposes module status, host
diagnostics and registry data. It never accepts a target and never triggers an
active operation, so exposing it on a network cannot be used to scan a third
party. Binding is 127.0.0.1 by default.
"""

from kingdomx.web.app import create_app, serve

__all__ = ["create_app", "serve"]
