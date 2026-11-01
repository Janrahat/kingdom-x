"""E.164 numbering plans.

Data source: ITU-T E.164 country codes plus public national numbering-plan
structure (length and mobile-prefix ranges). Only countries whose structure is
documented here are analysed; for any other, the country is still identified from
the country code and the module says the structure is unknown rather than
inventing a line type.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

#: E.164 country calling codes. Ordered longest-prefix-first for matching.
COUNTRY_CODES: dict[str, tuple[str, str]] = {
    "1": ("US/CA", "North America (NANP)"),
    "7": ("RU/KZ", "Russia / Kazakhstan"),
    "20": ("EG", "Egypt"),
    "27": ("ZA", "South Africa"),
    "30": ("GR", "Greece"),
    "31": ("NL", "Netherlands"),
    "32": ("BE", "Belgium"),
    "33": ("FR", "France"),
    "34": ("ES", "Spain"),
    "36": ("HU", "Hungary"),
    "39": ("IT", "Italy"),
    "40": ("RO", "Romania"),
    "41": ("CH", "Switzerland"),
    "43": ("AT", "Austria"),
    "44": ("GB", "United Kingdom"),
    "45": ("DK", "Denmark"),
    "46": ("SE", "Sweden"),
    "47": ("NO", "Norway"),
    "48": ("PL", "Poland"),
    "49": ("DE", "Germany"),
    "51": ("PE", "Peru"),
    "52": ("MX", "Mexico"),
    "53": ("CU", "Cuba"),
    "54": ("AR", "Argentina"),
    "55": ("BR", "Brazil"),
    "56": ("CL", "Chile"),
    "57": ("CO", "Colombia"),
    "58": ("VE", "Venezuela"),
    "60": ("MY", "Malaysia"),
    "61": ("AU", "Australia"),
    "62": ("ID", "Indonesia"),
    "63": ("PH", "Philippines"),
    "64": ("NZ", "New Zealand"),
    "65": ("SG", "Singapore"),
    "66": ("TH", "Thailand"),
    "81": ("JP", "Japan"),
    "82": ("KR", "South Korea"),
    "84": ("VN", "Vietnam"),
    "86": ("CN", "China"),
    "90": ("TR", "Turkey"),
    "91": ("IN", "India"),
    "92": ("PK", "Pakistan"),
    "93": ("AF", "Afghanistan"),
    "94": ("LK", "Sri Lanka"),
    "95": ("MM", "Myanmar"),
    "98": ("IR", "Iran"),
    "212": ("MA", "Morocco"),
    "213": ("DZ", "Algeria"),
    "216": ("TN", "Tunisia"),
    "218": ("LY", "Libya"),
    "220": ("GM", "Gambia"),
    "221": ("SN", "Senegal"),
    "233": ("GH", "Ghana"),
    "234": ("NG", "Nigeria"),
    "249": ("SD", "Sudan"),
    "251": ("ET", "Ethiopia"),
    "254": ("KE", "Kenya"),
    "255": ("TZ", "Tanzania"),
    "256": ("UG", "Uganda"),
    "260": ("ZM", "Zambia"),
    "263": ("ZW", "Zimbabwe"),
    "351": ("PT", "Portugal"),
    "352": ("LU", "Luxembourg"),
    "353": ("IE", "Ireland"),
    "354": ("IS", "Iceland"),
    "355": ("AL", "Albania"),
    "356": ("MT", "Malta"),
    "357": ("CY", "Cyprus"),
    "358": ("FI", "Finland"),
    "359": ("BG", "Bulgaria"),
    "370": ("LT", "Lithuania"),
    "371": ("LV", "Latvia"),
    "372": ("EE", "Estonia"),
    "373": ("MD", "Moldova"),
    "380": ("UA", "Ukraine"),
    "381": ("RS", "Serbia"),
    "385": ("HR", "Croatia"),
    "386": ("SI", "Slovenia"),
    "387": ("BA", "Bosnia and Herzegovina"),
    "420": ("CZ", "Czechia"),
    "421": ("SK", "Slovakia"),
    "423": ("LI", "Liechtenstein"),
    "852": ("HK", "Hong Kong"),
    "853": ("MO", "Macao"),
    "855": ("KH", "Cambodia"),
    "856": ("LA", "Laos"),
    "880": ("BD", "Bangladesh"),
    "886": ("TW", "Taiwan"),
    "960": ("MV", "Maldives"),
    "961": ("LB", "Lebanon"),
    "962": ("JO", "Jordan"),
    "963": ("SY", "Syria"),
    "964": ("IQ", "Iraq"),
    "965": ("KW", "Kuwait"),
    "966": ("SA", "Saudi Arabia"),
    "967": ("YE", "Yemen"),
    "968": ("OM", "Oman"),
    "971": ("AE", "United Arab Emirates"),
    "972": ("IL", "Israel"),
    "973": ("BH", "Bahrain"),
    "974": ("QA", "Qatar"),
    "975": ("BT", "Bhutan"),
    "976": ("MN", "Mongolia"),
    "977": ("NP", "Nepal"),
    "992": ("TJ", "Tajikistan"),
    "993": ("TM", "Turkmenistan"),
    "994": ("AZ", "Azerbaijan"),
    "995": ("GE", "Georgia"),
    "996": ("KG", "Kyrgyzstan"),
    "998": ("UZ", "Uzbekistan"),
}

#: NANP area-code prefixes that identify non-geographic services.
NANP_SPECIAL: dict[tuple[str, str], str] = {
    ("800", "fixed"): "toll-free",
    ("833", "fixed"): "toll-free",
    ("844", "fixed"): "toll-free",
    ("855", "fixed"): "toll-free",
    ("866", "fixed"): "toll-free",
    ("877", "fixed"): "toll-free",
    ("888", "fixed"): "toll-free",
    ("900", "fixed"): "premium-rate",
}


@dataclass(frozen=True)
class NumberingPlan:
    """Public structure of one national numbering plan."""

    country_code: str
    iso: str
    name: str
    national_length: int
    """Total national significant number length (excluding the country code)."""

    mobile_prefixes: tuple[str, ...] = ()
    fixed_prefixes: tuple[str, ...] = ()
    tollfree_prefixes: tuple[str, ...] = ()
    national_prefix: str = "0"
    """Trunk prefix dialled domestically (not part of the E.164 number)."""

    length_variants: tuple[int, ...] = ()
    note: str = ""

    @property
    def valid_lengths(self) -> tuple[int, ...]:
        return self.length_variants or (self.national_length,)


#: Documented plans. Deliberately covers common destinations; others still get
#: country identification with line type reported as unknown.
PLANS: dict[str, NumberingPlan] = {
    "966": NumberingPlan(
        "966", "SA", "Saudi Arabia", 9,
        mobile_prefixes=("5",), fixed_prefixes=("1",),
        national_prefix="0",
        note="Mobile numbers start with 5 (e.g. 5X XXX XXXX).",
    ),
    "971": NumberingPlan(
        "971", "AE", "United Arab Emirates", 9,
        mobile_prefixes=("5", "52", "54", "55", "56", "58"),
        fixed_prefixes=("2", "3", "4", "6", "7", "9"),
        tollfree_prefixes=("800",), national_prefix="0",
    ),
    "92": NumberingPlan(
        "92", "PK", "Pakistan", 10,
        mobile_prefixes=("3",), fixed_prefixes=("2", "4", "5", "6", "7", "8", "9"),
        national_prefix="0",
        note="Mobile numbers begin with 3 (e.g. 3XX XXXXXXX).",
    ),
    "91": NumberingPlan(
        "91", "IN", "India", 10,
        mobile_prefixes=("6", "7", "8", "9"),
        fixed_prefixes=("1", "2", "3", "4", "5"),
        tollfree_prefixes=("1800",), national_prefix="0",
    ),
    "44": NumberingPlan(
        "44", "GB", "United Kingdom", 10,
        mobile_prefixes=("7",), fixed_prefixes=("1", "2", "3"),
        tollfree_prefixes=("800",), national_prefix="0",
        length_variants=(10,),
    ),
    "1": NumberingPlan(
        "1", "US/CA", "North America (NANP)", 10,
        mobile_prefixes=(), fixed_prefixes=(),
        tollfree_prefixes=("800", "833", "844", "855", "866", "877", "888"),
        national_prefix="1",
        note="NANP does not separate mobile from fixed by prefix; line type is not derivable.",
    ),
    "49": NumberingPlan(
        "49", "DE", "Germany", 11,
        mobile_prefixes=("15", "16", "17"), fixed_prefixes=("2", "3", "4", "5", "6", "7", "8", "9"),
        tollfree_prefixes=("800",), national_prefix="0",
        length_variants=(10, 11),
        note="German numbers vary in length; mobile prefixes are 15x/16x/17x.",
    ),
    "33": NumberingPlan(
        "33", "FR", "France", 9,
        mobile_prefixes=("6", "7"), fixed_prefixes=("1", "2", "3", "4", "5", "9"),
        tollfree_prefixes=("800",), national_prefix="0",
    ),
    "39": NumberingPlan(
        "39", "IT", "Italy", 10,
        mobile_prefixes=("3",), fixed_prefixes=("0", "1", "2", "4", "5", "6", "7", "8"),
        national_prefix="",
        length_variants=(9, 10),
        note="Italy has no trunk prefix; mobile numbers start with 3.",
    ),
    "90": NumberingPlan(
        "90", "TR", "Turkey", 10,
        mobile_prefixes=("5",), fixed_prefixes=("2", "3", "4"),
        national_prefix="0",
    ),
    "20": NumberingPlan(
        "20", "EG", "Egypt", 10,
        mobile_prefixes=("10", "11", "12", "15"), fixed_prefixes=("2", "3", "4", "5", "6", "7", "8", "9"),
        national_prefix="0",
        note="Egyptian mobile numbers start with 10/11/12/15.",
    ),
    "234": NumberingPlan(
        "234", "NG", "Nigeria", 10,
        mobile_prefixes=("70", "80", "81", "90", "91"), fixed_prefixes=("1", "2", "3", "4", "5", "6", "7", "8", "9"),
        national_prefix="0",
    ),
    "27": NumberingPlan(
        "27", "ZA", "South Africa", 9,
        mobile_prefixes=("6", "7", "8"), fixed_prefixes=("1", "2", "3", "4", "5"),
        national_prefix="0",
    ),
    "61": NumberingPlan(
        "61", "AU", "Australia", 9,
        mobile_prefixes=("4",), fixed_prefixes=("2", "3", "7", "8"),
        tollfree_prefixes=("1800",), national_prefix="0",
    ),
    "86": NumberingPlan(
        "86", "CN", "China", 11,
        mobile_prefixes=("13", "14", "15", "17", "18", "19"),
        fixed_prefixes=("10", "2", "3", "4", "5", "6", "7", "8", "9"),
        national_prefix="0",
    ),
    "81": NumberingPlan(
        "81", "JP", "Japan", 10,
        mobile_prefixes=("70", "80", "90"), fixed_prefixes=("2", "3", "4", "6"),
        national_prefix="0",
        length_variants=(9, 10),
    ),
    "82": NumberingPlan(
        "82", "KR", "South Korea", 10,
        mobile_prefixes=("10",), fixed_prefixes=("2", "3", "4", "5", "6"),
        national_prefix="0",
        length_variants=(9, 10),
    ),
    "55": NumberingPlan(
        "55", "BR", "Brazil", 11,
        mobile_prefixes=("9",), fixed_prefixes=("1", "2", "3", "4", "5", "6", "7", "8"),
        national_prefix="0",
        length_variants=(10, 11),
    ),
    "7": NumberingPlan(
        "7", "RU/KZ", "Russia / Kazakhstan", 10,
        mobile_prefixes=("9",), fixed_prefixes=("3", "4", "8"),
        national_prefix="8",
        note="Russia uses 8 as the national trunk prefix, which is easy to confuse with a leading 8.",
    ),
}

#: Line types we can name.
LINE_TYPES = ("mobile", "fixed", "toll-free", "premium-rate", "voip", "unknown")


@dataclass
class NumberInfo:
    """Everything derivable from the digits alone."""

    raw: str
    digits: str
    ok: bool = False
    country_code: str | None = None
    country_iso: str | None = None
    country_name: str | None = None
    national_number: str | None = None
    national_length: int | None = None
    expected_lengths: tuple[int, ...] = ()
    line_type: str = "unknown"
    e164: str | None = None
    formatted_national: str | None = None
    formatted_international: str | None = None
    rfc3966: str | None = None
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    plan_known: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "digits": self.digits,
            "ok": self.ok,
            "country_code": self.country_code,
            "country_iso": self.country_iso,
            "country_name": self.country_name,
            "national_number": self.national_number,
            "national_length": self.national_length,
            "expected_lengths": list(self.expected_lengths),
            "line_type": self.line_type,
            "e164": self.e164,
            "formatted_national": self.formatted_national,
            "formatted_international": self.formatted_international,
            "rfc3966": self.rfc3966,
            "problems": list(self.problems),
            "notes": list(self.notes),
            "plan_known": self.plan_known,
            "disclaimer": (
                "Derived from the public numbering plan only. A phone number does not "
                "identify its owner: no name, address, live location, call history or "
                "messages are obtainable from it."
            ),
        }

    @property
    def summary(self) -> str:
        if not self.ok:
            return "invalid: " + "; ".join(self.problems)
        return (
            f"{self.e164} — {self.country_name} ({self.line_type})"
            if self.e164
            else f"+{self.country_code} — {self.country_name}"
        )


def _normalise(raw: str) -> str:
    """Strip formatting, keeping a leading + as a marker only."""
    text = unicodedata.normalize("NFKC", raw or "").strip()
    # Convert Arabic-Indic and Persian digits.
    translated = []
    for char in text:
        code = ord(char)
        if 0x0660 <= code <= 0x0669:
            translated.append(str(code - 0x0660))
        elif 0x06F0 <= code <= 0x06F9:
            translated.append(str(code - 0x06F0))
        else:
            translated.append(char)
    text = "".join(translated)
    return re.sub(r"[^\d+]", "", text)


def _match_country_code(digits: str) -> tuple[str, str, str] | None:
    """Longest-prefix match against the country-code table."""
    for length in (3, 2, 1):
        candidate = digits[:length]
        if candidate in COUNTRY_CODES:
            iso, name = COUNTRY_CODES[candidate]
            return candidate, iso, name
        # 1-digit codes other than 1 and 7 do not exist.
    return None


def _classify_line_type(plan: NumberingPlan, national: str) -> str:
    for prefix in sorted(plan.tollfree_prefixes, key=len, reverse=True):
        if national.startswith(prefix):
            return "toll-free"
    for prefix in sorted(plan.mobile_prefixes, key=len, reverse=True):
        if national.startswith(prefix):
            return "mobile"
    for prefix in sorted(plan.fixed_prefixes, key=len, reverse=True):
        if national.startswith(prefix):
            return "fixed"
    if plan.country_code == "1":
        area = national[:3]
        if area in NANP_SPECIAL:
            return NANP_SPECIAL[area, "fixed"]
    return "unknown"


def _format_national(plan: NumberingPlan, national: str) -> str:
    """Group the national number in readable blocks."""
    prefix = plan.national_prefix
    body = national
    if plan.country_code in {"966", "971", "20", "27", "90"} and len(body) == 9:
        grouped = f"{body[:2]} {body[2:5]} {body[5:]}"
    elif plan.country_code == "92" and len(body) == 10:
        grouped = f"{body[:3]} {body[3:]}"
    elif plan.country_code == "91" and len(body) == 10:
        grouped = f"{body[:5]} {body[5:]}"
    elif plan.country_code == "1" and len(body) == 10:
        grouped = f"({body[:3]}) {body[3:6]}-{body[6:]}"
    elif plan.country_code == "44" and len(body) == 10:
        grouped = f"{body[:4]} {body[4:]}"
    elif len(body) > 6:
        grouped = f"{body[:3]} {body[3:-4]} {body[-4:]}".replace("  ", " ")
    else:
        grouped = body
    return f"{prefix} {grouped}".strip() if prefix else grouped


def _format_international(country_code: str, national: str) -> str:
    if country_code == "1" and len(national) == 10:
        return f"+1 {national[:3]}-{national[3:6]}-{national[6:]}"
    if len(national) > 6:
        return f"+{country_code} {national[:3]} {national[3:-4]} {national[-4:]}".replace("  ", " ")
    return f"+{country_code} {national}"


def parse_number(raw: str, *, default_country_code: str | None = None) -> NumberInfo:
    """Parse and validate a phone number against its numbering plan."""
    info = NumberInfo(raw=raw or "", digits="")
    digits = _normalise(raw)

    if not digits:
        info.problems.append("no digits found")
        return info

    has_plus = digits.startswith("+")
    if has_plus:
        digits = digits[1:]

    if digits.startswith("00"):
        digits = digits[2:]
        has_plus = True

    info.digits = digits

    if not has_plus and default_country_code:
        prefix = _normalise(default_country_code)
        # A national number may carry a trunk prefix that must be dropped.
        plan = PLANS.get(prefix)
        if plan and plan.national_prefix and digits.startswith(plan.national_prefix):
            digits = digits[len(plan.national_prefix) :]
        digits = prefix + digits
        info.digits = digits

    if len(digits) < 7:
        info.problems.append(f"too short to be a phone number ({len(digits)} digits)")
        return info
    if len(digits) > 15:
        info.problems.append(
            f"{len(digits)} digits exceeds the E.164 maximum of 15"
        )
        return info

    match = _match_country_code(digits)
    if match is None:
        info.problems.append(f"no country calling code matches the start of {digits[:3]}…")
        return info

    country_code, iso, name = match
    national = digits[len(country_code) :]
    info.country_code = country_code
    info.country_iso = iso
    info.country_name = name
    info.national_number = national
    info.national_length = len(national)
    info.ok = True

    plan = PLANS.get(country_code)
    if plan is None:
        info.plan_known = False
        info.notes.append(
            f"The structure of {name}'s national plan is not in KINGDOM X's catalogue, "
            "so the length and line type were not verified."
        )
        info.e164 = "+" + digits
        info.formatted_international = _format_international(country_code, national)
        return info

    info.plan_known = True
    info.expected_lengths = plan.valid_lengths
    if len(national) not in plan.valid_lengths:
        info.problems.append(
            f"national number has {len(national)} digits; "
            f"{name} uses {', '.join(str(n) for n in plan.valid_lengths)}"
        )
        info.ok = False
    else:
        info.line_type = _classify_line_type(plan, national)
        if info.line_type == "unknown":
            info.notes.append(
                "The prefix does not match a documented mobile, fixed or toll-free range, "
                "so the line type is unknown (it may be a newer allocation)."
            )

    info.e164 = "+" + digits
    info.formatted_national = _format_national(plan, national)
    info.formatted_international = _format_international(country_code, national)
    info.rfc3966 = f"tel:{info.e164}"
    if plan.note:
        info.notes.append(plan.note)

    return info


def validate_e164(raw: str) -> tuple[bool, str]:
    """Quick validity check: ``(ok, reason)``."""
    info = parse_number(raw)
    if info.ok:
        return True, info.e164 or ""
    return False, "; ".join(info.problems) or "invalid"


def supported_countries() -> list[dict[str, Any]]:
    """Which plans have full structural support."""
    return [
        {
            "country_code": "+" + plan.country_code,
            "iso": plan.iso,
            "name": plan.name,
            "national_lengths": list(plan.valid_lengths),
            "knows_line_type": bool(
                plan.mobile_prefixes or plan.fixed_prefixes or plan.tollfree_prefixes
            ),
            "note": plan.note,
        }
        for plan in sorted(PLANS.values(), key=lambda p: p.name)
    ]


def coverage_report() -> dict[str, Any]:
    """Honest statement of what this module covers."""
    return {
        "country_codes_known": len(COUNTRY_CODES),
        "plans_with_structure": len(PLANS),
        "line_type_coverage": sorted(PLANS),
        "can_determine": [
            "country from the calling code",
            "structural validity for catalogued plans",
            "line type where the prefix ranges are documented",
            "E.164 / national / RFC 3966 formatting",
        ],
        "cannot_determine": [
            "subscriber name or identity",
            "address or registration location",
            "live device location",
            "call or message records",
            "carrier of a specific line without a licensed lookup API",
        ],
        "note": (
            "Carrier identification is only possible through a licensed numbering "
            "database (for example a commercial HLR or portability API). No such "
            "integration is bundled, so KINGDOM X does not report a carrier."
        ),
    }
