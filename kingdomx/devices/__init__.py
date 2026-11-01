"""Global Device Intelligence — public reference data only.

Answers "what is this device model?" from a curated public catalogue. It does
**not** discover devices on any network, and cannot see private inventories.
Local network discovery lives in :mod:`kingdomx.network` and requires
authorization.
"""

from kingdomx.devices.catalog import (
    DEVICE_DATASETS,
    MANUFACTURERS,
    DEVICE_MODELS,
    ANDROID_VERSIONS,
    classify_device,
    find_model,
    find_manufacturer,
    catalog_summary,
    parse_user_agent_device,
)

__all__ = [
    "DEVICE_DATASETS",
    "MANUFACTURERS",
    "DEVICE_MODELS",
    "ANDROID_VERSIONS",
    "classify_device",
    "find_model",
    "find_manufacturer",
    "catalog_summary",
    "parse_user_agent_device",
]
