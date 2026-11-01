"""Password strength audit — entirely local.

Two things this module deliberately does **not** do:

* it never transmits, logs or stores the password being audited;
* it never calls an online checker, because those send a prefix of the hash to a
  third party and the operator may not expect that.

The strength estimate is an entropy calculation plus a pattern penalty. It is
labelled as an estimate everywhere it appears, because no local metric can know
whether a value already appears in a breach corpus.
"""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import string
from dataclasses import dataclass, field
from typing import Any

from kingdomx.cybersecurity.severity import Finding, Report, Severity

#: A short list of the most-abused passwords. Real corpora are far larger; this
#: catches the very common cases without shipping a wordlist.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password", "123456", "123456789", "qwerty", "12345678", "111111", "123123",
        "abc123", "password1", "1234567", "iloveyou", "admin", "welcome", "monkey",
        "letmein", "dragon", "football", "master", "sunshine", "ashley", "bailey",
        "passw0rd", "shadow", "superman", "qazwsx", "michael", "trustno1", "jordan",
        "hunter2", "root", "toor", "changeme", "default", "guest", "test", "test123",
        "administrator", "p@ssw0rd", "qwerty123", "1q2w3e4r", "zaq12wsx", "starwars",
        "freedom", "whatever", "hello", "charlie", "donald", "secret", "summer",
        "internet", "samsung", "google", "android", "termux", "kali", "linux",
    }
)

KEYBOARD_WALKS: tuple[str, ...] = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
    "qazwsxedc", "1qaz2wsx", "!qaz@wsx",
)

SEQUENCES: tuple[str, ...] = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
)

#: Rough guesses-per-second figures, used to express crack time.
ATTACK_RATES: dict[str, float] = {
    "online_throttled": 10.0,
    "online_unthrottled": 1_000.0,
    "offline_bcrypt": 10_000.0,
    "offline_sha256_gpu": 1e11,
}


@dataclass
class PasswordAnalysis:
    """The result of auditing one password. The password itself is not retained."""

    length: int
    entropy_bits: float
    score: int
    label: str
    character_classes: dict[str, bool] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    crack_times: dict[str, str] = field(default_factory=dict)
    hashed_prefix: str | None = None
    """First 8 hex chars of SHA-256, so a report can reference a value without
    revealing it. Still sensitive — only include on explicit request."""

    def to_dict(self, *, include_hash_prefix: bool = False) -> dict[str, Any]:
        payload = {
            "length": self.length,
            "entropy_bits": round(self.entropy_bits, 1),
            "score": self.score,
            "label": self.label,
            "character_classes": dict(self.character_classes),
            "problems": list(self.problems),
            "suggestions": list(self.suggestions),
            "crack_times": dict(self.crack_times),
            "note": "Entropy is an estimate. It cannot tell whether this value already "
            "appears in a breach corpus.",
        }
        if include_hash_prefix and self.hashed_prefix:
            payload["sha256_prefix"] = self.hashed_prefix
        return payload


def _classes(password: str) -> dict[str, bool]:
    return {
        "lowercase": any(ch.islower() for ch in password),
        "uppercase": any(ch.isupper() for ch in password),
        "digits": any(ch.isdigit() for ch in password),
        "symbols": any(not ch.isalnum() for ch in password),
        "non_ascii": any(ord(ch) > 127 for ch in password),
    }


def _pool_size(classes: dict[str, bool]) -> int:
    pool = 0
    if classes["lowercase"]:
        pool += 26
    if classes["uppercase"]:
        pool += 26
    if classes["digits"]:
        pool += 10
    if classes["symbols"]:
        pool += 33
    if classes["non_ascii"]:
        pool += 100
    return max(pool, 1)


def _find_walks(password: str) -> list[str]:
    """Detect keyboard runs and alphabetic/numeric sequences."""
    low = password.lower()
    found: list[str] = []
    for walk in KEYBOARD_WALKS:
        for size in range(4, len(walk) + 1):
            for start in range(0, len(walk) - size + 1):
                fragment = walk[start : start + size]
                if fragment in low or fragment[::-1] in low:
                    found.append(f"keyboard run '{fragment}'")
                    break
    for sequence in SEQUENCES:
        for size in range(4, min(len(sequence), len(low)) + 1):
            for start in range(0, len(sequence) - size + 1):
                fragment = sequence[start : start + size]
                if fragment in low or fragment[::-1] in low:
                    found.append(f"sequential run '{fragment}'")
                    break
    return found


def _repeats(password: str) -> list[str]:
    out: list[str] = []
    if re.search(r"(.)\1{2,}", password):
        out.append("three or more identical characters in a row")
    if re.fullmatch(r".{0,3}(\w+)\1.{0,3}", password) and len(password) >= 6:
        out.append("the whole value looks like a repeated chunk")
    return out


def crack_time(entropy_bits: float, rate: float) -> str:
    """Convert entropy to a human crack-time estimate at ``rate`` guesses/second."""
    if entropy_bits <= 0:
        return "immediate"
    combinations = 2 ** min(entropy_bits, 1024)
    seconds = combinations / 2 / rate  # average case
    return humanise_seconds(seconds)


def humanise_seconds(seconds: float) -> str:
    if seconds < 1:
        return "under a second"
    units = (
        ("century", 86400 * 365 * 100),
        ("year", 86400 * 365),
        ("month", 86400 * 30),
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    )
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if value > 1e6:
                return f"about {value:.3g} {name}s"
            return f"about {value:.0f} {name}{'' if round(value) == 1 else 's'}"
    return "under a second"


def analyse(password: str, *, include_hash_prefix: bool = False) -> PasswordAnalysis:
    """Audit one password. The value is used in-memory only."""
    value = password or ""
    classes = _classes(value)
    pool = _pool_size(classes)
    raw_entropy = len(value) * math.log2(pool) if value else 0.0

    problems: list[str] = []
    suggestions: list[str] = []
    penalty = 0.0

    if not value:
        problems.append("password is empty")
        penalty = 999.0

    lowered = value.lower()
    if lowered in COMMON_PASSWORDS:
        problems.append("appears in the common-password list")
        penalty += 30

    for walk in _find_walks(value):
        problems.append(walk)
        penalty += 6

    for repeat in _repeats(value):
        problems.append(repeat)
        penalty += 5

    if len(value) < 8:
        problems.append("shorter than 8 characters")
        penalty += 12
    elif len(value) < 12:
        problems.append("shorter than 12 characters")
        penalty += 4

    missing = [name for name, present in classes.items() if not present and name != "non_ascii"]
    if len(missing) >= 3:
        problems.append("uses only one or two character classes")
        penalty += 6
    elif missing:
        suggestions.append("add a " + " or ".join(missing))

    if re.match(r"^[A-Z][a-z]+[0-9]{1,4}!?$", value):
        problems.append("matches the very common 'Word + digits' pattern")
        penalty += 8

    if any(year in value for year in ("2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026")):
        problems.append("contains a recent year")
        penalty += 3

    entropy = max(0.0, raw_entropy - penalty)

    # Score bands are deliberately conservative.
    if entropy >= 90:
        score, label = 4, "excellent"
    elif entropy >= 70:
        score, label = 3, "strong"
    elif entropy >= 50:
        score, label = 2, "fair"
    elif entropy >= 30:
        score, label = 1, "weak"
    else:
        score, label = 0, "very weak"

    if score < 4:
        suggestions.append("use a long passphrase of 4-6 unrelated words")
        suggestions.append("or generate a random 20+ character value with a password manager")
    if "reuse" not in problems:
        suggestions.append("never reuse this value across services")

    crack_times = {
        name: crack_time(entropy, rate) for name, rate in ATTACK_RATES.items()
    }

    return PasswordAnalysis(
        length=len(value),
        entropy_bits=entropy,
        score=score,
        label=label,
        character_classes=classes,
        problems=problems,
        suggestions=suggestions,
        crack_times=crack_times,
        hashed_prefix=(
            hashlib.sha256(value.encode("utf-8")).hexdigest()[:8] if include_hash_prefix and value else None
        ),
    )


def password_report(password: str) -> Report:
    """Wrap the analysis in the standard report shape."""
    import time

    report = Report(module="passwords", target="(local, not transmitted)", started_at=time.time())
    analysis = analyse(password)
    severity = {
        4: Severity.INFO,
        3: Severity.INFO,
        2: Severity.MEDIUM,
        1: Severity.HIGH,
        0: Severity.CRITICAL,
    }[analysis.score]

    if analysis.score >= 3:
        report.passed(
            f"Password strength: {analysis.label}",
            "password",
            detail=f"{analysis.entropy_bits:.1f} estimated entropy bits over {analysis.length} characters.",
            evidence="; ".join(analysis.problems) or "no pattern problems detected",
        )
    else:
        report.issue(
            title=f"Password strength: {analysis.label}",
            severity=severity,
            category="password",
            detail="; ".join(analysis.problems) or "low estimated entropy",
            evidence=f"{analysis.entropy_bits:.1f} estimated bits, {analysis.length} characters",
            remediation="; ".join(analysis.suggestions),
        )

    if analysis.score < 4:
        report.issue(
            title=f"Offline attack time ({'bcrypt' if analysis.score else 'fast hash'})",
            severity=severity if analysis.score <= 2 else Severity.LOW,
            category="password",
            detail=(
                "If the password database leaks and the hash is fast (MD5/SHA-1), this is "
                "the time to crack it. Storing passwords with Argon2id makes the realistic "
                "figure far higher than the 'offline fast hash' row."
            ),
            evidence="; ".join(f"{k}: {v}" for k, v in analysis.crack_times.items()),
        )

    report.meta = analysis.to_dict()
    report.finished_at = time.time()
    return report


def generate_password(length: int = 24, *, symbols: bool = True) -> str:
    """A cryptographically strong password using ``secrets``."""
    if length < 12:
        raise ValueError("refusing to generate fewer than 12 characters")
    if length > 256:
        raise ValueError("maximum length is 256")
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{}<>?"
    # Guarantee at least one of each class, then fill and shuffle.
    required = [secrets.choice(string.ascii_lowercase), secrets.choice(string.ascii_uppercase), secrets.choice(string.digits)]
    if symbols:
        required.append(secrets.choice("!@#$%^&*()-_=+[]{}<>?"))
    rest = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + rest
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words: int = 5, separator: str = "-") -> str:
    """A passphrase from a small built-in wordlist.

    The list is short on purpose — this is a demonstration of the 5-word
    passphrase pattern, not a replacement for a real diceware list.
    """
    wordlist = (
        "anchor", "beacon", "cipher", "delta", "ember", "falcon", "granite", "harbor",
        "ivory", "jungle", "kernel", "lantern", "meridian", "nectar", "orbit", "pilot",
        "quartz", "raven", "summit", "tundra", "umbra", "vector", "willow", "xenon",
        "yonder", "zephyr", "amber", "basalt", "cobalt", "dune", "echo", "flint",
        "glacier", "hollow", "ingot", "jasper", "kestrel", "lumen", "mosaic", "nomad",
        "onyx", "prism", "quiver", "rocket", "saffron", "tempo", "ultra", "violet",
        "warden", "xylem", "yarrow", "zenith", "arc", "bridge", "crest", "drift",
        "eagle", "forge", "grove", "haven", "isle", "jetty", "knoll", "ledge",
    )
    if words < 4:
        raise ValueError("refusing to generate fewer than 4 words")
    if words > 12:
        raise ValueError("maximum is 12 words")
    return separator.join(secrets.choice(wordlist) for _ in range(words))


def policy_check(password: str, policy: dict[str, Any]) -> dict[str, Any]:
    """Check a password against a password policy dict."""
    value = password or ""
    failures: list[str] = []

    min_length = int(policy.get("min_length", 12))
    if len(value) < min_length:
        failures.append(f"shorter than {min_length} characters")

    max_length = int(policy.get("max_length", 256))
    if len(value) > max_length:
        failures.append(f"longer than {max_length} characters")

    classes = _classes(value)
    if policy.get("require_upper") and not classes["uppercase"]:
        failures.append("no uppercase letter")
    if policy.get("require_lower") and not classes["lowercase"]:
        failures.append("no lowercase letter")
    if policy.get("require_digit") and not classes["digits"]:
        failures.append("no digit")
    if policy.get("require_symbol") and not classes["symbols"]:
        failures.append("no symbol")

    for banned in policy.get("banned_substrings", []) or []:
        if banned and str(banned).lower() in value.lower():
            failures.append(f"contains forbidden substring: {banned}")

    if policy.get("forbid_common") and value.lower() in COMMON_PASSWORDS:
        failures.append("appears in the common-password list")

    return {"ok": not failures, "failures": failures, "length": len(value)}
