"""Allow-listed action execution.

There is no ``shell=True`` anywhere in this package and no path by which a
scheduled task can name an arbitrary command. Each action maps to a Python
function in this module.
"""

from __future__ import annotations

from typing import Any, Callable

from kingdomx.core.logging_setup import get_logger
from kingdomx.core.storage import Database

log = get_logger("automation.executor")


class ActionError(Exception):
    def __init__(self, message: str, *, code: str = "kingdomx.action") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def _host_audit(db: Database, params: dict[str, Any]) -> dict[str, Any]:
    from kingdomx.cybersecurity.audit import run_audit

    report = run_audit(keys=params.get("keys"))
    return {
        "summary": f"host audit: {report.verdict}, {len(report.issues)} issue(s)",
        "verdict": report.verdict,
        "issues": len(report.issues),
    }


def _dependency_scan(db: Database, params: dict[str, Any]) -> dict[str, Any]:
    from kingdomx.cybersecurity.dependencies import scan_directory

    path = params.get("path") or "."
    scan = scan_directory(path, network=bool(params.get("network")))
    issues = [f for f in scan.findings if f.is_issue]
    return {
        "summary": f"dependency scan of {path}: {len(scan.packages)} package(s), {len(issues)} finding(s)",
        "packages": len(scan.packages),
        "findings": len(issues),
    }


def _integrity_baseline(db: Database, params: dict[str, Any]) -> dict[str, Any]:
    from kingdomx.cybersecurity.integrity import integrity_report

    path = params.get("path") or "."
    report = integrity_report(path, baseline_path=params.get("baseline"))
    return {
        "summary": f"integrity of {path}: {report.verdict}",
        "verdict": report.verdict,
        "issues": len(report.issues),
    }


def _log_analysis(db: Database, params: dict[str, Any]) -> dict[str, Any]:
    from kingdomx.cybersecurity.logs import analyse_path, common_log_paths

    target = params.get("path")
    if not target:
        found = common_log_paths()
        if not found:
            raise ActionError("no standard log files found on this platform")
        target = str(found[0])
    report = analyse_path(target)
    return {
        "summary": f"log analysis of {target}: {len(report.issues)} issue(s) across {report.meta.get('total_lines', 0)} line(s)",
        "issues": len(report.issues),
    }


def _system_health(db: Database, params: dict[str, Any]) -> dict[str, Any]:
    from kingdomx.computers.system import health_report

    health = health_report()
    return {
        "summary": f"system health: {health['verdict']} ({len(health['issues'])} issue(s))",
        "verdict": health["verdict"],
        "issues": len(health["issues"]),
    }


def _tools_inventory(db: Database, params: dict[str, Any]) -> dict[str, Any]:
    from kingdomx.cybersecurity.tools import inventory_summary

    summary = inventory_summary()
    return {
        "summary": f"{summary['present']}/{summary['total_catalogued']} catalogued tools installed",
        "present": summary["present"],
    }


def _dns_diagnose(db: Database, params: dict[str, Any]) -> dict[str, Any]:
    from kingdomx.dns.lookup import diagnose

    domain = str(params.get("domain") or "").strip()
    if not domain:
        raise ActionError("dns_diagnose needs a 'domain' parameter")
    result = diagnose(domain)
    return {
        "summary": f"DNS {domain}: {result['passed']}/{result['total']} checks passed",
        "passed": result["passed"],
        "total": result["total"],
    }


def _report_export(db: Database, params: dict[str, Any]) -> dict[str, Any]:
    from kingdomx.computers.system import health_report
    from kingdomx.cybersecurity.audit import run_audit
    from kingdomx.reports.export import ReportBundle, save_report

    bundle = ReportBundle()
    bundle.add(run_audit())
    path = params.get("path") or "kingdomx-report.json"
    saved = save_report(bundle, path)
    return {"summary": f"report exported to {saved}", "path": str(saved)}


#: The complete action table. This dict *is* the allow-list.
ACTIONS: dict[str, Callable[[Database, dict[str, Any]], dict[str, Any]]] = {
    "host_audit": _host_audit,
    "dependency_scan": _dependency_scan,
    "integrity_baseline": _integrity_baseline,
    "log_analysis": _log_analysis,
    "system_health": _system_health,
    "tools_inventory": _tools_inventory,
    "dns_diagnose": _dns_diagnose,
    "report_export": _report_export,
}


def run_action(db: Database, action: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run one allow-listed action."""
    handler = ACTIONS.get(action)
    if handler is None:
        raise ActionError(
            f"action '{action}' is not allowed. Allowed: {', '.join(sorted(ACTIONS))}",
            code="kingdomx.action.unknown",
        )
    safe_params = params if isinstance(params, dict) else {}
    log.info("running action %s", action)
    try:
        outcome = handler(db, safe_params)
    except ActionError:
        raise
    except Exception as exc:  # noqa: BLE001 - convert to one error type
        raise ActionError(f"{action} failed: {type(exc).__name__}: {exc}") from exc
    return {"action": action, **outcome}


def action_list() -> list[dict[str, str]]:
    from kingdomx.automation.scheduler import ALLOWED_ACTIONS

    return [
        {"name": name, "description": ALLOWED_ACTIONS.get(name, "")}
        for name in sorted(ACTIONS)
    ]
