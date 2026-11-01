"""Plugin system.

A plugin is a directory containing ``plugin.json`` and a Python module with a
``run(context)`` function. Loading is deliberately conservative:

* the manifest is validated against a schema before import,
* declared permissions are checked against what the plugin asks to do,
* every call is written to the audit table,
* plugin code runs in a subprocess with a timeout, so a runaway plugin cannot
  take the console down.

Plugins are never downloaded automatically. Installing one is an explicit
operator action on a path they supply.
"""

from kingdomx.plugins.loader import (
    PluginManifest,
    PluginRecord,
    PluginError,
    list_installed,
    install_plugin,
    remove_plugin,
    run_plugin,
    validate_manifest,
    PERMISSIONS,
)

__all__ = [
    "PluginManifest",
    "PluginRecord",
    "PluginError",
    "list_installed",
    "install_plugin",
    "remove_plugin",
    "run_plugin",
    "validate_manifest",
    "PERMISSIONS",
]
