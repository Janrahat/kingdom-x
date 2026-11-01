"""Curated global technology reference data with explicit provenance.

Design rule: **no invented worldwide totals.** When a number would be a global
statistic, this module either cites where it comes from or reports it as
unavailable. The ``confidence`` field is a judgement about the data source, not
about the world.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

#: Dataset provenance and limits, shown alongside every result.
DATASETS: dict[str, dict[str, Any]] = {
    "country_infrastructure": {
        "title": "Country connectivity and infrastructure reference",
        "source": "ITU country calling codes, IANA root zone, RIR delegation records",
        "as_of": "2026-10 (curated)",
        "coverage": "Curated subset of countries; not all 249 ISO entries",
        "confidence": "medium",
        "limitations": (
            "Figures describe publicly documented structure (calling code, TLD, RIR). "
            "They are not live measurements and do not describe current network health."
        ),
        "refresh": "Manual; re-verify against IANA and the relevant RIR",
    },
    "cloud_providers": {
        "title": "Cloud platform reference",
        "source": "Provider public documentation and published region lists",
        "as_of": "2026-10 (curated)",
        "coverage": "Major public cloud platforms only",
        "confidence": "medium",
        "limitations": (
            "Region lists change frequently. Treat the region count as indicative; "
            "confirm against the provider's own region page before relying on it."
        ),
        "refresh": "Manual; regions change several times a year",
    },
    "ai_providers": {
        "title": "AI provider and model reference",
        "source": "Provider public API documentation",
        "as_of": "2026-10 (curated)",
        "coverage": "Providers with a documented public API",
        "confidence": "medium",
        "limitations": (
            "Model catalogues change weekly. KINGDOM X never uses this table to decide "
            "availability — that comes from a live health check in kingdomx.ai.health."
        ),
        "refresh": "Manual; verify with `kingdomx ai check`",
    },
    "languages_and_platforms": {
        "title": "Programming language and platform reference",
        "source": "Public language specifications and package registries",
        "as_of": "2026-10 (curated)",
        "coverage": "Mainstream languages and their primary registries",
        "confidence": "high",
        "limitations": "Stable facts (registry name, licence) only; no popularity ranking.",
    },
    "mobile_platforms": {
        "title": "Mobile OS and store reference",
        "source": "Vendor public developer documentation",
        "as_of": "2026-10 (curated)",
        "coverage": "Android and iOS only",
        "confidence": "high",
        "limitations": "Version support windows differ by device vendor and are not modelled.",
    },
}


@dataclass
class Dataset:
    """A dataset plus the metadata that must accompany it."""

    key: str
    rows: list[dict[str, Any]] = field(default_factory=list)

    @property
    def meta(self) -> dict[str, Any]:
        return dict(DATASETS.get(self.key, {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "meta": self.meta,
            "row_count": len(self.rows),
            "rows": self.rows,
            "note": (
                "Curated reference data, not a live measurement. Read the 'limitations' "
                "field before citing any figure."
            ),
        }


#: Countries: calling code, ccTLD, RIR, and documented internet-exchange presence.
#: Deliberately partial — a curated subset, and it says so.
COUNTRY_INFRASTRUCTURE: list[dict[str, Any]] = [
    {"iso": "SA", "name": "Saudi Arabia", "calling_code": "+966", "tld": ".sa",
     "rir": "RIPE NCC", "ixps": ["SAIX"], "idn_ccTLD": ".السعودية"},
    {"iso": "AE", "name": "United Arab Emirates", "calling_code": "+971", "tld": ".ae",
     "rir": "RIPE NCC", "ixps": ["UAE-IX"], "idn_ccTLD": ".امارات"},
    {"iso": "PK", "name": "Pakistan", "calling_code": "+92", "tld": ".pk",
     "rir": "APNIC", "ixps": ["PKIX"], "idn_ccTLD": None},
    {"iso": "IN", "name": "India", "calling_code": "+91", "tld": ".in",
     "rir": "APNIC", "ixps": ["NIXI", "Mumbai IX", "Chennai IX"], "idn_ccTLD": ".भारत"},
    {"iso": "US", "name": "United States", "calling_code": "+1", "tld": ".us",
     "rir": "ARIN", "ixps": ["DE-CIX NY", "Equinix IX", "SIX"], "idn_ccTLD": None},
    {"iso": "GB", "name": "United Kingdom", "calling_code": "+44", "tld": ".uk",
     "rir": "RIPE NCC", "ixps": ["LINX", "LONAP"], "idn_ccTLD": None},
    {"iso": "DE", "name": "Germany", "calling_code": "+49", "tld": ".de",
     "rir": "RIPE NCC", "ixps": ["DE-CIX Frankfurt"], "idn_ccTLD": None},
    {"iso": "FR", "name": "France", "calling_code": "+33", "tld": ".fr",
     "rir": "RIPE NCC", "ixps": ["France-IX"], "idn_ccTLD": None},
    {"iso": "NL", "name": "Netherlands", "calling_code": "+31", "tld": ".nl",
     "rir": "RIPE NCC", "ixps": ["AMS-IX"], "idn_ccTLD": None},
    {"iso": "SG", "name": "Singapore", "calling_code": "+65", "tld": ".sg",
     "rir": "APNIC", "ixps": ["SGIX"], "idn_ccTLD": None},
    {"iso": "JP", "name": "Japan", "calling_code": "+81", "tld": ".jp",
     "rir": "APNIC", "ixps": ["JPIX", "JPNAP"], "idn_ccTLD": ".日本"},
    {"iso": "CN", "name": "China", "calling_code": "+86", "tld": ".cn",
     "rir": "APNIC", "ixps": ["CNIX"], "idn_ccTLD": ".中国"},
    {"iso": "BR", "name": "Brazil", "calling_code": "+55", "tld": ".br",
     "rir": "LACNIC", "ixps": ["IX.br"], "idn_ccTLD": None},
    {"iso": "ZA", "name": "South Africa", "calling_code": "+27", "tld": ".za",
     "rir": "AFRINIC", "ixps": ["NAP Africa JHB"], "idn_ccTLD": None},
    {"iso": "NG", "name": "Nigeria", "calling_code": "+234", "tld": ".ng",
     "rir": "AFRINIC", "ixps": ["IXPN"], "idn_ccTLD": None},
    {"iso": "EG", "name": "Egypt", "calling_code": "+20", "tld": ".eg",
     "rir": "AFRINIC", "ixps": ["EG-IX"], "idn_ccTLD": ".مصر"},
    {"iso": "TR", "name": "Turkey", "calling_code": "+90", "tld": ".tr",
     "rir": "RIPE NCC", "ixps": ["IST-IX"], "idn_ccTLD": None},
    {"iso": "AU", "name": "Australia", "calling_code": "+61", "tld": ".au",
     "rir": "APNIC", "ixps": ["IX Australia"], "idn_ccTLD": None},
    {"iso": "CA", "name": "Canada", "calling_code": "+1", "tld": ".ca",
     "rir": "ARIN", "ixps": ["TORIX"], "idn_ccTLD": None},
    {"iso": "RU", "name": "Russia", "calling_code": "+7", "tld": ".ru",
     "rir": "RIPE NCC", "ixps": ["MSK-IX"], "idn_ccTLD": ".рф"},
]

#: Cloud platforms: documented region presence (indicative counts only).
CLOUD_PROVIDERS: list[dict[str, Any]] = [
    {"name": "Amazon Web Services", "docs": "https://docs.aws.amazon.com/",
     "regions": 30, "free_tier": True, "note": "Region count indicative; AWS adds regions frequently."},
    {"name": "Microsoft Azure", "docs": "https://learn.microsoft.com/azure/",
     "regions": 60, "free_tier": True, "note": "Includes sovereign clouds; count varies by definition."},
    {"name": "Google Cloud Platform", "docs": "https://cloud.google.com/docs",
     "regions": 40, "free_tier": True, "note": "Region vs zone distinction matters."},
    {"name": "Oracle Cloud Infrastructure", "docs": "https://docs.oracle.com/en-us/iaas/",
     "regions": 45, "free_tier": True, "note": "Always-free tier is unusually generous."},
    {"name": "Alibaba Cloud", "docs": "https://www.alibabacloud.com/help",
     "regions": 28, "free_tier": False, "note": "Region availability differs by account type."},
    {"name": "DigitalOcean", "docs": "https://docs.digitalocean.com/",
     "regions": 14, "free_tier": False, "note": "Developer-focused; no free tier beyond credits."},
    {"name": "Hetzner Cloud", "docs": "https://docs.hetzner.com/cloud/",
     "regions": 5, "free_tier": False, "note": "EU and US locations; strong price/performance."},
    {"name": "Cloudflare", "docs": "https://developers.cloudflare.com/",
     "regions": 300, "free_tier": True, "note": "Edge PoP count, not regions — different unit."},
]

#: AI providers with documented public APIs.
AI_PROVIDERS: list[dict[str, Any]] = [
    {"name": "OpenAI", "docs": "https://platform.openai.com/docs", "api": "OpenAI-compatible",
     "local": False, "kingdomx_provider": "openai"},
    {"name": "Google Gemini", "docs": "https://ai.google.dev/docs", "api": "generateContent",
     "local": False, "kingdomx_provider": "gemini"},
    {"name": "Anthropic", "docs": "https://docs.anthropic.com", "api": "Messages",
     "local": False, "kingdomx_provider": "anthropic"},
    {"name": "DeepSeek", "docs": "https://api-docs.deepseek.com", "api": "OpenAI-compatible",
     "local": False, "kingdomx_provider": "deepseek"},
    {"name": "Mistral AI", "docs": "https://docs.mistral.ai", "api": "OpenAI-compatible",
     "local": False, "kingdomx_provider": "mistral"},
    {"name": "Groq", "docs": "https://console.groq.com/docs", "api": "OpenAI-compatible",
     "local": False, "kingdomx_provider": "groq"},
    {"name": "Together AI", "docs": "https://docs.together.ai", "api": "OpenAI-compatible",
     "local": False, "kingdomx_provider": "together"},
    {"name": "OpenRouter", "docs": "https://openrouter.ai/docs", "api": "OpenAI-compatible",
     "local": False, "kingdomx_provider": "openrouter"},
    {"name": "Ollama", "docs": "https://docs.ollama.com", "api": "Ollama native",
     "local": True, "kingdomx_provider": "ollama"},
    {"name": "Hugging Face", "docs": "https://huggingface.co/docs", "api": "Inference API",
     "local": False, "kingdomx_provider": "huggingface"},
]

#: Languages: registry and licence facts only — no popularity claims.
LANGUAGES: list[dict[str, Any]] = [
    {"name": "Python", "registry": "PyPI", "license": "PSF-2.0", "use_in_kingdomx": "Core runtime"},
    {"name": "Rust", "registry": "crates.io", "license": "MIT/Apache-2.0", "use_in_kingdomx": "Planned for hot paths"},
    {"name": "Go", "registry": "proxy.golang.org", "license": "BSD-3-Clause", "use_in_kingdomx": "Planned for concurrency"},
    {"name": "JavaScript", "registry": "npm", "license": "—", "use_in_kingdomx": "Web dashboard"},
    {"name": "TypeScript", "registry": "npm", "license": "Apache-2.0", "use_in_kingdomx": "Not used yet"},
    {"name": "Java", "registry": "Maven Central", "license": "—", "use_in_kingdomx": "Android APK analysis"},
    {"name": "Kotlin", "registry": "Maven Central", "license": "Apache-2.0", "use_in_kingdomx": "Android reference only"},
    {"name": "Bash", "registry": "—", "license": "GPL-3.0", "use_in_kingdomx": "Installers"},
    {"name": "SQL", "registry": "—", "license": "—", "use_in_kingdomx": "SQLite storage"},
    {"name": "HTML/CSS", "registry": "—", "license": "—", "use_in_kingdomx": "Web dashboard"},
]

MOBILE_PLATFORMS: list[dict[str, Any]] = [
    {"name": "Android", "developer_docs": "https://developer.android.com",
     "store": "Google Play", "package_format": "APK / AAB",
     "privilege_model": "Per-permission grant, app sandbox per UID",
     "kingdomx_support": "Full — Termux and ADB/APK metadata inspection"},
    {"name": "iOS", "developer_docs": "https://developer.apple.com/documentation",
     "store": "App Store", "package_format": "IPA",
     "privilege_model": "Per-permission grant, app sandbox, no cross-app data access",
     "kingdomx_support": "Reference data only — no device access on Linux"},
]


def list_datasets() -> list[dict[str, Any]]:
    return [
        {"key": key, **meta, "rows": _rows_for(key)}
        for key, meta in DATASETS.items()
    ]


def _rows_for(key: str) -> int:
    return {
        "country_infrastructure": len(COUNTRY_INFRASTRUCTURE),
        "cloud_providers": len(CLOUD_PROVIDERS),
        "ai_providers": len(AI_PROVIDERS),
        "languages_and_platforms": len(LANGUAGES),
        "mobile_platforms": len(MOBILE_PLATFORMS),
    }.get(key, 0)


def dataset_info(key: str) -> dict[str, Any]:
    """One dataset with its rows and metadata."""
    tables = {
        "country_infrastructure": COUNTRY_INFRASTRUCTURE,
        "cloud_providers": CLOUD_PROVIDERS,
        "ai_providers": AI_PROVIDERS,
        "languages_and_platforms": LANGUAGES,
        "mobile_platforms": MOBILE_PLATFORMS,
    }
    if key not in tables:
        raise KeyError(f"unknown dataset: {key}. Available: {', '.join(sorted(tables))}")
    return Dataset(key=key, rows=list(tables[key])).to_dict()


def lookup_country(term: str) -> dict[str, Any]:
    """Find a country by ISO code, name fragment, calling code or TLD."""
    needle = (term or "").strip().lower().lstrip("+")
    if not needle:
        raise ValueError("empty search term")
    matches = [
        row
        for row in COUNTRY_INFRASTRUCTURE
        if needle == row["iso"].lower()
        or needle in row["name"].lower()
        or needle == row["calling_code"].lstrip("+")
        or needle == row["tld"].lstrip(".").lower()
    ]
    return {
        "query": term,
        "matches": matches,
        "meta": DATASETS["country_infrastructure"],
        "note": (
            "Infrastructure facts only. Absence from this table means the country is not "
            "in the curated subset, not that it has no internet infrastructure."
        ),
    }


def internet_exchange_points() -> dict[str, Any]:
    """Every IXP in the curated table, with the country it serves."""
    rows: list[dict[str, Any]] = []
    for country in COUNTRY_INFRASTRUCTURE:
        for ixp in country["ixps"]:
            rows.append({"ixp": ixp, "country": country["name"], "iso": country["iso"]})
    return {
        "count": len(rows),
        "rows": sorted(rows, key=lambda row: row["ixp"]),
        "meta": DATASETS["country_infrastructure"],
        "note": (
            "Only IXPs recorded in the curated country table. This is not the global IXP "
            "list — PeeringDB is the authoritative source for that."
        ),
    }


def ai_providers_reference() -> dict[str, Any]:
    """AI providers with their documented API shape."""
    importable = []
    import importlib

    for row in AI_PROVIDERS:
        try:
            importlib.import_module(f"kingdomx.ai.catalog")
            break
        except Exception:  # noqa: BLE001
            break
    try:
        from kingdomx.ai.catalog import PROVIDERS

        importable = sorted(PROVIDERS)
    except Exception:  # noqa: BLE001 - reference table must work even without the AI package
        importable = []

    return {
        "providers": AI_PROVIDERS,
        "implemented_in_kingdomx": importable,
        "meta": DATASETS["ai_providers"],
        "note": (
            "Listing a provider here does not mean it is available: availability comes "
            "from a live health check (`kingdomx ai check`), never from this table."
        ),
    }


def registry_summary() -> dict[str, Any]:
    """A single honest overview of all global-tech data."""
    return {
        "datasets": list_datasets(),
        "total_rows": sum(_rows_for(key) for key in DATASETS),
        "generated_at": time.time(),
        "policy": (
            "KINGDOM X does not publish global totals it cannot verify. Each dataset "
            "states its source, date, coverage, confidence and limitations. Counts are of "
            "curated rows, not of the world."
        ),
    }
