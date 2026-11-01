"""Global Technology Intelligence.

Every dataset here carries ``source``, ``as_of``, ``coverage``, ``confidence`` and
``limitations`` fields. Nothing is a live world total: these are curated
reference tables with cited origins, and the module says so in every result.
"""

from kingdomx.globaltech.intel import (
    DATASETS,
    Dataset,
    dataset_info,
    list_datasets,
    lookup_country,
    registry_summary,
    internet_exchange_points,
    ai_providers_reference,
)

__all__ = [
    "DATASETS",
    "Dataset",
    "dataset_info",
    "list_datasets",
    "lookup_country",
    "registry_summary",
    "internet_exchange_points",
    "ai_providers_reference",
]
