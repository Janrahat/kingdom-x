"""The shared finding model.

Every security module emits :class:`Finding` objects so the terminal, the API and
the report exporter all speak the same language. A finding always says *what was
observed*, not what we assume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable


class Severity(IntEnum):
    """Ordered so sorting puts the worst first."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def weight(self) -> int:
        return int(self)

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(max(0, min(int(value), 4)))
        text = (value or "").strip().lower()
        mapping = {
            "info": cls.INFO,
            "informational": cls.INFO,
            "pass": cls.INFO,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return mapping.get(text, cls.INFO)

    @classmethod
    def coerce(cls, value: str | int | "Severity") -> "Severity":
        return cls.parse(value)


@dataclass
class Finding:
    """One observation, with the evidence that produced it."""

    title: str
    severity: Severity
    category: str
    detail: str = ""
    reference: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    passed: bool = False
    """True for a check that ran and found nothing wrong (a positive result)."""
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)

    @property
    def is_issue(self) -> bool:
        return not self.passed and self.severity >= Severity.LOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "severity_weight": self.severity.weight,
            "category": self.category,
            "detail": self.detail,
            "reference": self.reference,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "passed": self.passed,
            "extra": dict(self.extra),
        }

    def line(self) -> str:
        marker = "PASS" if self.passed else self.severity.label.upper()
        return f"[{marker:<8}] {self.title}"


@dataclass
class Report:
    """A collection of findings from one check run."""

    module: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    errors: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def issue(self, **kwargs: Any) -> Finding:
        return self.add(Finding(**kwargs))

    def passed(self, title: str, category: str, detail: str = "", **kwargs: Any) -> Finding:
        return self.add(
            Finding(
                title=title,
                severity=Severity.INFO,
                category=category,
                detail=detail,
                passed=True,
                **kwargs,
            )
        )

    @property
    def issues(self) -> list[Finding]:
        return [f for f in self.findings if f.is_issue]

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def verdict(self) -> str:
        worst = self.worst
        if worst >= Severity.CRITICAL:
            return "CRITICAL"
        if worst >= Severity.HIGH:
            return "AT RISK"
        if worst >= Severity.MEDIUM:
            return "NEEDS ATTENTION"
        if worst >= Severity.LOW:
            return "MINOR ISSUES"
        return "CLEAN"

    def counts(self) -> dict[str, int]:
        counts = {level.label: 0 for level in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        counts["total"] = len(self.findings)
        counts["issues"] = len(self.issues)
        counts["passed"] = sum(1 for f in self.findings if f.passed)
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "verdict": self.verdict,
            "counts": self.counts(),
            "duration_ms": round((self.finished_at - self.started_at) * 1000, 1)
            if self.finished_at and self.started_at
            else None,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": list(self.errors),
            "meta": dict(self.meta),
        }

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (f.passed, -f.severity.weight, f.category, f.title),
        )

    def by_category(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category, []).append(finding)
        return grouped


def summarise_findings(findings: Iterable[Finding]) -> dict[str, Any]:
    """Aggregate a loose collection of findings."""
    materialised = list(findings)
    counts = {level.label: 0 for level in Severity}
    for finding in materialised:
        counts[finding.severity.label] += 1
    return {
        "total": len(materialised),
        "issues": sum(1 for f in materialised if f.is_issue),
        "passed": sum(1 for f in materialised if f.passed),
        "counts": counts,
        "worst": max((f.severity for f in materialised), default=Severity.INFO).label,
    }


#: A quick lookup for CVSS-style bands, used when interpreting external data.
CVSS_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)


def from_cvss(score: float) -> Severity:
    """Map a CVSS base score to a severity band."""
    for threshold, severity in CVSS_BANDS:
        if score >= threshold:
            return severity
    return Severity.INFO
