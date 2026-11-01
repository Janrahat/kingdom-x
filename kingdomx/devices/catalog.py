"""Curated device catalogue: manufacturers, models, Android releases.

Scope is deliberately narrow and stated: these are publicly documented facts
about well-known devices. It is not a device inventory, and it cannot enumerate
anyone's hardware.
"""

from __future__ import annotations

import re
from typing import Any

DEVICE_DATASETS: dict[str, dict[str, Any]] = {
    "manufacturers": {
        "title": "Device manufacturer reference",
        "source": "Manufacturer public product pages",
        "as_of": "2026-10 (curated)",
        "coverage": "Major consumer and enterprise OEMs",
        "confidence": "high",
        "limitations": "Company facts only. No market-share or shipment figures.",
    },
    "models": {
        "title": "Device model reference",
        "source": "Manufacturer specification pages",
        "as_of": "2026-10 (curated)",
        "coverage": "Representative models per OEM, not a complete catalogue",
        "confidence": "medium",
        "limitations": (
            "Specs are as published at launch. Firmware and OS support change; verify "
            "against the vendor before relying on support dates."
        ),
    },
    "android_versions": {
        "title": "Android release reference",
        "source": "Android developer platform documentation",
        "as_of": "2026-10 (curated)",
        "coverage": "Android 8 through current",
        "confidence": "high",
        "limitations": "API level and codename are stable; vendor skins differ.",
    },
    "categories": {
        "title": "Device category taxonomy",
        "source": "KINGDOM X internal classification",
        "as_of": "2026-10",
        "coverage": "Categories used across the platform",
        "confidence": "high",
        "limitations": "A classification scheme, not measured data.",
    },
}

MANUFACTURERS: list[dict[str, Any]] = [
    {"name": "Samsung", "country": "South Korea", "platforms": ["Android", "Tizen"],
     "product_lines": ["Galaxy S", "Galaxy A", "Galaxy Z", "Galaxy Tab"],
     "security_page": "https://security.samsungmobile.com/"},
    {"name": "Google", "country": "United States", "platforms": ["Android", "ChromeOS"],
     "product_lines": ["Pixel", "Pixel Tablet", "Pixelbook"],
     "security_page": "https://source.android.com/docs/security/overview/updates-resources"},
    {"name": "Apple", "country": "United States", "platforms": ["iOS", "macOS", "watchOS"],
     "product_lines": ["iPhone", "iPad", "Mac", "Apple Watch"],
     "security_page": "https://support.apple.com/100100"},
    {"name": "Xiaomi", "country": "China", "platforms": ["Android", "HyperOS"],
     "product_lines": ["Xiaomi numbered series", "Redmi", "POCO"],
     "security_page": "https://trust.mi.com/"},
    {"name": "OnePlus", "country": "China", "platforms": ["Android", "OxygenOS"],
     "product_lines": ["OnePlus numbered series", "Nord"],
     "security_page": "https://www.oneplus.com/global/security"},
    {"name": "Huawei", "country": "China", "platforms": ["Android", "HarmonyOS"],
     "product_lines": ["P series", "Mate", "Nova"],
     "security_page": "https://www.huawei.com/en/psirt"},
    {"name": "Lenovo", "country": "China", "platforms": ["Android", "Windows"],
     "product_lines": ["ThinkPad", "IdeaPad", "Legion", "Tab"],
     "security_page": "https://www.lenovo.com/us/en/product-security/"},
    {"name": "Dell", "country": "United States", "platforms": ["Windows", "Linux"],
     "product_lines": ["XPS", "Latitude", "OptiPlex", "PowerEdge"],
     "security_page": "https://www.dell.com/support/security"},
    {"name": "HP", "country": "United States", "platforms": ["Windows", "Linux"],
     "product_lines": ["EliteBook", "ProBook", "ProLiant"],
     "security_page": "https://support.hp.com/us-en/security-bulletins"},
    {"name": "Cisco", "country": "United States", "platforms": ["IOS", "IOS XE", "NX-OS"],
     "product_lines": ["Catalyst", "Nexus", "ASA", "Meraki"],
     "security_page": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"},
    {"name": "MikroTik", "country": "Latvia", "platforms": ["RouterOS"],
     "product_lines": ["RouterBOARD", "hEX", "CCR", "CHR"],
     "security_page": "https://mikrotik.com/supportsec"},
    {"name": "TP-Link", "country": "China", "platforms": ["Embedded Linux"],
     "product_lines": ["Archer", "Deco", "Omada"],
     "security_page": "https://www.tp-link.com/us/support/security-advisories/"},
    {"name": "Raspberry Pi Foundation", "country": "United Kingdom",
     "platforms": ["Raspberry Pi OS", "Linux"],
     "product_lines": ["Pi 4", "Pi 5", "Pi Zero", "Pico"],
     "security_page": "https://www.raspberrypi.com/documentation/"},
    {"name": "Arduino", "country": "Italy", "platforms": ["Embedded"],
     "product_lines": ["Uno", "Nano", "MKR", "Portenta"],
     "security_page": "https://www.arduino.cc/"},
    {"name": "Synology", "country": "Taiwan", "platforms": ["DSM"],
     "product_lines": ["DiskStation", "RackStation"],
     "security_page": "https://www.synology.com/en-global/security/advisory"},
    {"name": "Ubiquiti", "country": "United States", "platforms": ["UniFi", "EdgeOS"],
     "product_lines": ["UniFi AP", "Dream Machine", "EdgeRouter"],
     "security_page": "https://community.ui.com/releases"},
]

DEVICE_MODELS: list[dict[str, Any]] = [
    {"manufacturer": "Samsung", "model": "Galaxy S24 Ultra", "category": "mobile",
     "os": "Android", "os_launch": "14", "screen_inches": 6.8, "cpu": "Snapdragon 8 Gen 3",
     "ram_gb": 12, "storage_gb": 256, "release_year": 2024},
    {"manufacturer": "Samsung", "model": "Galaxy A54", "category": "mobile",
     "os": "Android", "os_launch": "13", "screen_inches": 6.4, "cpu": "Exynos 1380",
     "ram_gb": 8, "storage_gb": 128, "release_year": 2023},
    {"manufacturer": "Google", "model": "Pixel 8 Pro", "category": "mobile",
     "os": "Android", "os_launch": "14", "screen_inches": 6.7, "cpu": "Tensor G3",
     "ram_gb": 12, "storage_gb": 128, "release_year": 2023},
    {"manufacturer": "Google", "model": "Pixel 7a", "category": "mobile",
     "os": "Android", "os_launch": "13", "screen_inches": 6.1, "cpu": "Tensor G2",
     "ram_gb": 8, "storage_gb": 128, "release_year": 2023},
    {"manufacturer": "Apple", "model": "iPhone 15 Pro", "category": "mobile",
     "os": "iOS", "os_launch": "17", "screen_inches": 6.1, "cpu": "A17 Pro",
     "ram_gb": 8, "storage_gb": 128, "release_year": 2023},
    {"manufacturer": "Apple", "model": "iPad Air (5th gen)", "category": "tablet",
     "os": "iPadOS", "os_launch": "16", "screen_inches": 10.9, "cpu": "Apple M1",
     "ram_gb": 8, "storage_gb": 64, "release_year": 2022},
    {"manufacturer": "Samsung", "model": "Galaxy Tab S9", "category": "tablet",
     "os": "Android", "os_launch": "13", "screen_inches": 11.0, "cpu": "Snapdragon 8 Gen 2",
     "ram_gb": 8, "storage_gb": 128, "release_year": 2023},
    {"manufacturer": "Xiaomi", "model": "Redmi Note 13", "category": "mobile",
     "os": "Android", "os_launch": "13", "screen_inches": 6.67, "cpu": "Dimensity 6080",
     "ram_gb": 8, "storage_gb": 128, "release_year": 2024},
    {"manufacturer": "Dell", "model": "XPS 13 Plus", "category": "desktop",
     "os": "Windows", "os_launch": "11", "screen_inches": 13.4, "cpu": "Intel Core i7-1360P",
     "ram_gb": 16, "storage_gb": 512, "release_year": 2023},
    {"manufacturer": "Lenovo", "model": "ThinkPad X1 Carbon Gen 11", "category": "desktop",
     "os": "Windows", "os_launch": "11", "screen_inches": 14.0, "cpu": "Intel Core i7-1355U",
     "ram_gb": 16, "storage_gb": 512, "release_year": 2023},
    {"manufacturer": "Cisco", "model": "Catalyst 2960-X", "category": "switch",
     "os": "IOS", "os_launch": "15", "screen_inches": None, "cpu": "PowerPC",
     "ram_gb": 2, "storage_gb": 1, "release_year": 2013},
    {"manufacturer": "MikroTik", "model": "hEX S", "category": "router",
     "os": "RouterOS", "os_launch": "6", "screen_inches": None, "cpu": "MT7621A",
     "ram_gb": 1, "storage_gb": 0, "release_year": 2018},
    {"manufacturer": "Raspberry Pi Foundation", "model": "Raspberry Pi 5",
     "category": "embedded", "os": "Linux", "os_launch": "Bookworm", "screen_inches": None,
     "cpu": "Cortex-A76", "ram_gb": 8, "storage_gb": 0, "release_year": 2023},
    {"manufacturer": "Synology", "model": "DS923+", "category": "storage",
     "os": "DSM", "os_launch": "7.2", "screen_inches": None, "cpu": "AMD Ryzen R1600",
     "ram_gb": 4, "storage_gb": 0, "release_year": 2022},
]

ANDROID_VERSIONS: list[dict[str, Any]] = [
    {"version": "8.0", "api": 26, "codename": "Oreo", "year": 2017},
    {"version": "9", "api": 28, "codename": "Pie", "year": 2018},
    {"version": "10", "api": 29, "codename": "Q", "year": 2019},
    {"version": "11", "api": 30, "codename": "R", "year": 2020},
    {"version": "12", "api": 31, "codename": "S", "year": 2021},
    {"version": "13", "api": 33, "codename": "Tiramisu", "year": 2022},
    {"version": "14", "api": 34, "codename": "Upside Down Cake", "year": 2023},
    {"version": "15", "api": 35, "codename": "Vanilla Ice Cream", "year": 2024},
]

CATEGORIES: list[dict[str, Any]] = [
    {"key": "mobile", "label": "Mobile phone", "hint": "Has cellular radio"},
    {"key": "tablet", "label": "Tablet", "hint": "Touch-first, large screen"},
    {"key": "desktop", "label": "Desktop / laptop", "hint": "General-purpose computer"},
    {"key": "server", "label": "Server", "hint": "Headless, always on"},
    {"key": "router", "label": "Router", "hint": "Forwards packets between networks"},
    {"key": "switch", "label": "Switch", "hint": "Layer-2 forwarding"},
    {"key": "iot", "label": "IoT device", "hint": "Single-purpose, network-connected"},
    {"key": "embedded", "label": "Embedded / SBC", "hint": "Single-board computer or firmware target"},
    {"key": "storage", "label": "NAS / storage", "hint": "Network storage appliance"},
    {"key": "camera", "label": "Camera", "hint": "Video capture appliance"},
    {"key": "printer", "label": "Printer", "hint": "Print appliance"},
    {"key": "wearable", "label": "Wearable", "hint": "Body-worn device"},
    {"key": "tv", "label": "Smart TV / media", "hint": "Streaming appliance"},
    {"key": "vm", "label": "Virtual machine", "hint": "Guest instance"},
    {"key": "cloud_instance", "label": "Cloud instance", "hint": "Provider-hosted VM"},
]

#: Regexes that map a User-Agent to a device category. Real parsing of real input.
UA_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"iPad|Tablet|PlayBook|Silk", re.I), "tablet", "user-agent tablet token"),
    (re.compile(r"Mobi|Android.*Mobile|iPhone|iPod|Windows Phone", re.I), "mobile", "user-agent mobile token"),
    (re.compile(r"Android", re.I), "tablet", "Android without 'Mobile' is conventionally a tablet"),
    (re.compile(r"SmartTV|AppleTV|Roku|CrKey|HbbTV", re.I), "tv", "TV token"),
    (re.compile(r"watchOS|Apple Watch|Wear OS", re.I), "wearable", "wearable token"),
    (re.compile(r"bot|crawler|spider|curl|wget|python-requests|httpie", re.I), "bot", "automation token"),
    (re.compile(r"Windows NT|Macintosh|X11|CrOS|Linux", re.I), "desktop", "desktop OS token"),
)


def classify_device(*, category: str | None = None, user_agent: str = "") -> dict[str, Any]:
    """Classify a device from a known category or a User-Agent string."""
    if category:
        key = category.strip().lower()
        for entry in CATEGORIES:
            if entry["key"] == key:
                return {
                    "category": entry["key"],
                    "label": entry["label"],
                    "hint": entry["hint"],
                    "evidence": "explicit category supplied",
                    "confidence": "high",
                }
        return {
            "category": "unknown",
            "label": "Unknown",
            "hint": f"'{category}' is not in the taxonomy",
            "evidence": "no match",
            "confidence": "low",
        }

    if not user_agent:
        return {
            "category": "unknown",
            "label": "Unknown",
            "hint": "No User-Agent supplied",
            "evidence": "",
            "confidence": "none",
        }

    for pattern, cat, evidence in UA_PATTERNS:
        if pattern.search(user_agent):
            entry = next(item for item in CATEGORIES if item["key"] == cat)
            return {
                "category": cat,
                "label": entry["label"],
                "hint": entry["hint"],
                "evidence": evidence,
                "confidence": "medium",
            }

    return {
        "category": "unknown",
        "label": "Unknown",
        "hint": "The User-Agent matched no known token",
        "evidence": user_agent[:120],
        "confidence": "low",
    }


def parse_user_agent_device(user_agent: str) -> dict[str, Any]:
    """Extract device family, OS and browser from a User-Agent."""
    ua = user_agent or ""
    result: dict[str, Any] = {
        "user_agent": ua,
        "classification": classify_device(user_agent=ua),
        "os": None,
        "os_version": None,
        "browser": None,
        "browser_version": None,
    }
    os_patterns = (
        (r"Windows NT ([\d.]+)", "Windows"),
        (r"Android ([\d.]+)", "Android"),
        (r"(?:iPhone )?OS ([\d_]+) like Mac OS X", "iOS"),
        (r"Mac OS X ([\d_]+)", "macOS"),
        (r"CrOS \w+ ([\d.]+)", "ChromeOS"),
        (r"Ubuntu", "Linux (Ubuntu)"),
        (r"Linux", "Linux"),
    )
    for pattern, name in os_patterns:
        match = re.search(pattern, ua)
        if match:
            result["os"] = name
            try:
                result["os_version"] = match.group(1).replace("_", ".")
            except IndexError:
                result["os_version"] = None
            break

    browser_patterns = (
        (r"Edg/([\d.]+)", "Edge"),
        (r"OPR/([\d.]+)", "Opera"),
        (r"Firefox/([\d.]+)", "Firefox"),
        (r"Chrome/([\d.]+)", "Chrome"),
        (r"Version/([\d.]+).*Safari", "Safari"),
        (r"curl/([\d.]+)", "curl"),
    )
    for pattern, name in browser_patterns:
        match = re.search(pattern, ua)
        if match:
            result["browser"] = name
            result["browser_version"] = match.group(1)
            break
    return result


def find_manufacturer(term: str) -> list[dict[str, Any]]:
    needle = (term or "").strip().lower()
    if not needle:
        return []
    return [
        row
        for row in MANUFACTURERS
        if needle in row["name"].lower() or any(needle in p.lower() for p in row["platforms"])
    ]


def find_model(term: str) -> list[dict[str, Any]]:
    needle = (term or "").strip().lower()
    if not needle:
        return []
    return [
        row
        for row in DEVICE_MODELS
        if needle in row["model"].lower() or needle in row["manufacturer"].lower()
        or needle == row["category"].lower()
    ]


def find_android_version(version: str) -> dict[str, Any] | None:
    needle = (version or "").strip().lstrip("Android ").lower()
    for row in ANDROID_VERSIONS:
        if needle == row["version"].lower() or needle == str(row["api"]) or needle == row["codename"].lower():
            return row
    return None


def catalog_summary() -> dict[str, Any]:
    """Counts and provenance for the whole device catalogue."""
    by_category: dict[str, int] = {}
    for row in DEVICE_MODELS:
        by_category[row["category"]] = by_category.get(row["category"], 0) + 1
    return {
        "manufacturers": len(MANUFACTURERS),
        "models": len(DEVICE_MODELS),
        "android_versions": len(ANDROID_VERSIONS),
        "categories": len(CATEGORIES),
        "models_by_category": by_category,
        "datasets": {key: meta for key, meta in DEVICE_DATASETS.items()},
        "policy": (
            "Public reference data only. KINGDOM X cannot enumerate private device "
            "inventories and does not claim to. Local device discovery requires network "
            "access on a network you are authorized to inspect."
        ),
    }
