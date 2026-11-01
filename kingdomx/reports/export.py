"""Report bundling and export to JSON, CSV, Markdown and plain text."""

from __future__ import annotations

import csv
import io
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from kingdomx.core.redaction import redact_text
from kingdomx.cybersecurity.severity import Report, Severity


@dataclass
class ReportBundle:
    """One or more reports plus the run metadata."""

    reports: list[Report] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)
    platform_label: str = ""
    operator: str = "operator"
    notes: list[str] = field(default_factory=list)

    def add(self, report: Report) -> Report:
        self.reports.append(report)
        return report

    @property
    def findings(self) -> list[Any]:
        return [finding for report in self.reports for finding in report.findings]

    def counts(self) -> dict[str, int]:
        counts = {level.label: 0 for level in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        counts["total"] = len(self.findings)
        counts["issues"] = sum(1 for f in self.findings if f.is_issue)
        counts["passed"] = sum(1 for f in self.findings if f.passed)
        return counts

    @property
    def verdict(self) -> str:
        if not self.reports:
            return "NO DATA"
        return max((report.worst for report in self.reports), default=Severity.INFO).label and max(
            (report.verdict for report in self.reports),
            key=lambda label: {"CLEAN": 0, "MINOR ISSUES": 1, "NEEDS ATTENTION": 2,
                               "AT RISK": 3, "CRITICAL": 4}.get(label, 0),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "KINGDOM X",
            "tagline": "ONE PLATFORM. ALL TECHNOLOGIES. UNLIMITED INTELLIGENCE.",
            "generated_at": self.generated_at,
            "generated_at_iso": datetime.fromtimestamp(
                self.generated_at, tz=timezone.utc
            ).isoformat(),
            "platform": self.platform_label,
            "operator": self.operator,
            "verdict": self.verdict,
            "counts": self.counts(),
            "notes": [redact_text(note) for note in self.notes],
            "reports": [
                json.loads(redact_text(json.dumps(report.to_dict(), default=str)))
                for report in self.reports
            ],
            "disclaimer": (
                "Findings describe what this run observed at this moment. Absence of a "
                "finding is not proof of security. Active checks required recorded "
                "authorization and were run only against authorized targets."
            ),
        }


def render_json(bundle: ReportBundle, *, indent: int = 2) -> str:
    return json.dumps(bundle.to_dict(), indent=indent, ensure_ascii=False, default=str)


def render_csv(bundle: ReportBundle) -> str:
    """One row per finding, with provenance columns."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "module", "target", "severity", "passed", "category",
            "title", "detail", "evidence", "remediation", "reference",
        ]
    )
    for report in bundle.reports:
        for finding in report.sorted_findings():
            writer.writerow(
                [
                    report.module,
                    report.target,
                    finding.severity.label,
                    "yes" if finding.passed else "no",
                    finding.category,
                    finding.title,
                    redact_text(finding.detail or ""),
                    redact_text(finding.evidence or ""),
                    redact_text(finding.remediation or ""),
                    finding.reference or "",
                ]
            )
    return buffer.getvalue()


def render_markdown(bundle: ReportBundle) -> str:
    stamp = datetime.fromtimestamp(bundle.generated_at, tz=timezone.utc)
    lines = [
        "# KINGDOM X — Report",
        "",
        "**ONE PLATFORM. ALL TECHNOLOGIES. UNLIMITED INTELLIGENCE.**",
        "",
        f"- Generated: {stamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"- Platform: {bundle.platform_label or 'unknown'}",
        f"- Verdict: **{bundle.verdict}**",
        "",
        "## Summary",
        "",
    ]
    counts = bundle.counts()
    lines.append("| Metric | Count |")
    lines.append("| --- | ---: |")
    for key in ("total", "issues", "passed", "critical", "high", "medium", "low", "info"):
        lines.append(f"| {key} | {counts.get(key, 0)} |")

    for report in bundle.reports:
        lines.extend(["", f"## {report.module} — `{report.target}`", ""])
        lines.append(f"Verdict: **{report.verdict}**")
        if report.errors:
            lines.append("")
            lines.append("Errors:")
            for error in report.errors:
                lines.append(f"- {redact_text(str(error))}")
        lines.append("")
        for finding in report.sorted_findings():
            marker = "PASS" if finding.passed else finding.severity.label.upper()
            lines.append(f"### [{marker}] {finding.title}")
            if finding.detail:
                lines.append("")
                lines.append(redact_text(finding.detail))
            if finding.evidence:
                lines.append("")
                lines.append(f"```\n{redact_text(finding.evidence)}\n```")
            if finding.remediation:
                lines.append("")
                lines.append(f"**Remediation:** {redact_text(finding.remediation)}")
            if finding.reference:
                lines.append("")
                lines.append(f"Reference: {finding.reference}")
            lines.append("")

    if bundle.notes:
        lines.extend(["", "## Notes", ""])
        for note in bundle.notes:
            lines.append(f"- {redact_text(note)}")

    lines.extend(
        [
            "",
            "---",
            "",
            "Findings describe what this run observed. Absence of a finding is not proof "
            "of security. Active checks ran only against authorized targets.",
            "",
        ]
    )
    return "\n".join(lines)


def render_text(bundle: ReportBundle) -> str:
    stamp = datetime.fromtimestamp(bundle.generated_at, tz=timezone.utc)
    lines = [
        "KINGDOM X — REPORT",
        "=" * 60,
        f"Generated : {stamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Platform  : {bundle.platform_label or 'unknown'}",
        f"Verdict   : {bundle.verdict}",
        "",
        "SUMMARY",
        "-" * 60,
    ]
    counts = bundle.counts()
    for key in ("total", "issues", "passed", "critical", "high", "medium", "low"):
        lines.append(f"  {key:<14} {counts.get(key, 0)}")

    for report in bundle.reports:
        lines.extend(["", f"MODULE: {report.module}  TARGET: {report.target}", "-" * 60])
        for finding in report.sorted_findings():
            marker = "PASS" if finding.passed else finding.severity.label.upper()
            lines.append(f"  [{marker:<8}] {finding.title}")
            if finding.evidence:
                lines.append(f"             {redact_text(finding.evidence)[:160]}")
        if report.errors:
            for error in report.errors:
                lines.append(f"  ! {redact_text(str(error))[:160]}")

    lines.extend(
        [
            "",
            "=" * 60,
            "Absence of a finding is not proof of security.",
        ]
    )
    return "\n".join(lines)


RENDERERS = {
    "json": render_json,
    "csv": render_csv,
    "markdown": render_markdown,
    "md": render_markdown,
    "text": render_text,
    "txt": render_text,
}


def save_report(bundle: ReportBundle, path: str | Path, *, fmt: str | None = None) -> Path:
    """Write a bundle to ``path``. The format defaults to the file suffix."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    chosen = (fmt or target.suffix.lstrip(".") or "json").lower()
    renderer = RENDERERS.get(chosen)
    if renderer is None:
        raise ValueError(f"unsupported format: {chosen}. Use one of {', '.join(sorted(RENDERERS))}")
    target.write_text(renderer(bundle), encoding="utf-8")
    return target


def bundle_from_reports(reports: Iterable[Report], *, platform_label: str = "") -> ReportBundle:
    bundle = ReportBundle(platform_label=platform_label)
    for report in reports:
        bundle.add(report)
    return bundle
