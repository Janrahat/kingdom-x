"""Persisted scheduled tasks.

No background daemon: a task fires when the operator runs ``kingdomx run-due``,
which makes the behaviour predictable and testable. Run history is kept so an
operator can see what actually happened rather than trusting a silent timer.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any

from kingdomx.core.logging_setup import get_logger
from kingdomx.core.storage import Database

log = get_logger("automation.scheduler")

#: Actions an automation may invoke. Anything else is rejected.
ALLOWED_ACTIONS: dict[str, str] = {
    "host_audit": "Read-only Linux host configuration audit.",
    "dependency_scan": "Scan local manifests for vulnerable dependencies.",
    "integrity_baseline": "Hash a directory and store/compare a baseline.",
    "log_analysis": "Analyse local log files for problem patterns.",
    "system_health": "Collect CPU, memory and disk health.",
    "tools_inventory": "Detect installed security tooling.",
    "dns_diagnose": "Run the DNS diagnostic for a domain.",
    "report_export": "Export a report bundle to a file.",
}

MIN_INTERVAL_SECONDS = 300


@dataclass
class ScheduledTask:
    id: int
    name: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    interval_seconds: int = 3600
    enabled: bool = True
    last_run: float | None = None
    next_run: float | None = None
    created_at: float = field(default_factory=time.time)
    last_status: str | None = None
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "action": self.action,
            "params": dict(self.params),
            "interval_seconds": self.interval_seconds,
            "enabled": self.enabled,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "created_at": self.created_at,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "due": self.is_due(),
        }

    def is_due(self, now: float | None = None) -> bool:
        if not self.enabled:
            return False
        if self.next_run is None:
            return True
        return self.next_run <= (now if now is not None else time.time())


SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL UNIQUE,
    action           TEXT NOT NULL,
    params_json      TEXT NOT NULL DEFAULT '{}',
    interval_seconds INTEGER NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    last_run         REAL,
    next_run         REAL,
    created_at       REAL NOT NULL,
    last_status      TEXT,
    last_error       TEXT
);
CREATE TABLE IF NOT EXISTS task_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     INTEGER NOT NULL,
    started_at  REAL NOT NULL,
    finished_at REAL,
    status      TEXT NOT NULL,
    summary     TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_task_runs_task ON task_runs(task_id, started_at DESC);
"""


def ensure_schema(db: Database) -> None:
    db.executescript(SCHEMA)


def _row_to_task(row: sqlite3.Row) -> ScheduledTask:
    try:
        params = json.loads(row["params_json"] or "{}")
    except json.JSONDecodeError:
        params = {}
    return ScheduledTask(
        id=int(row["id"]),
        name=row["name"],
        action=row["action"],
        params=params if isinstance(params, dict) else {},
        interval_seconds=int(row["interval_seconds"]),
        enabled=bool(row["enabled"]),
        last_run=row["last_run"],
        next_run=row["next_run"],
        created_at=row["created_at"],
        last_status=row["last_status"],
        last_error=row["last_error"],
    )


def create_task(
    db: Database,
    name: str,
    action: str,
    *,
    params: dict[str, Any] | None = None,
    interval_seconds: int = 3600,
    enabled: bool = True,
) -> ScheduledTask:
    """Register a scheduled task."""
    ensure_schema(db)
    clean_name = (name or "").strip()
    if not clean_name or len(clean_name) > 64:
        raise ValueError("task name must be 1-64 characters")
    if action not in ALLOWED_ACTIONS:
        raise ValueError(
            f"action '{action}' is not allowed. Use one of: {', '.join(sorted(ALLOWED_ACTIONS))}"
        )
    if interval_seconds < MIN_INTERVAL_SECONDS:
        raise ValueError(f"interval must be at least {MIN_INTERVAL_SECONDS} seconds")

    now = time.time()
    try:
        cursor = db.execute(
            """
            INSERT INTO scheduled_tasks
                (name, action, params_json, interval_seconds, enabled, next_run, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                clean_name,
                action,
                json.dumps(params or {}),
                interval_seconds,
                1 if enabled else 0,
                now + interval_seconds,
                now,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"a task named '{clean_name}' already exists") from exc

    row = db.query_one("SELECT * FROM scheduled_tasks WHERE id = ?", (cursor.lastrowid,))
    db.audit("operator", "automation.create", target=clean_name, detail=action)
    return _row_to_task(row)


def list_tasks(db: Database, *, only_enabled: bool = False) -> list[ScheduledTask]:
    ensure_schema(db)
    sql = "SELECT * FROM scheduled_tasks"
    if only_enabled:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY name"
    return [_row_to_task(row) for row in db.query(sql)]


def delete_task(db: Database, name_or_id: str | int) -> bool:
    ensure_schema(db)
    if isinstance(name_or_id, int) or str(name_or_id).isdigit():
        cursor = db.execute("DELETE FROM scheduled_tasks WHERE id = ?", (int(name_or_id),))
    else:
        cursor = db.execute("DELETE FROM scheduled_tasks WHERE name = ?", (str(name_or_id),))
    deleted = cursor.rowcount > 0
    if deleted:
        db.audit("operator", "automation.delete", target=str(name_or_id))
    return deleted


def due_tasks(db: Database, *, now: float | None = None) -> list[ScheduledTask]:
    moment = now if now is not None else time.time()
    return [task for task in list_tasks(db, only_enabled=True) if task.is_due(moment)]


def record_run(
    db: Database,
    task: ScheduledTask,
    *,
    status: str,
    summary: str = "",
    error: str | None = None,
) -> None:
    """Write a run row and advance the schedule."""
    ensure_schema(db)
    now = time.time()
    db.execute(
        """
        INSERT INTO task_runs (task_id, started_at, finished_at, status, summary, error)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (task.id, task.last_run or now, now, status, summary[:500], error),
    )
    db.execute(
        """
        UPDATE scheduled_tasks
        SET last_run = ?, next_run = ?, last_status = ?, last_error = ?
        WHERE id = ?
        """,
        (now, now + task.interval_seconds, status, error, task.id),
    )


def run_due(db: Database, *, now: float | None = None) -> list[dict[str, Any]]:
    """Execute every due task and report each real outcome."""
    from kingdomx.automation.executor import ActionError, run_action

    results: list[dict[str, Any]] = []
    for task in due_tasks(db, now=now):
        started = time.time()
        task.last_run = started
        try:
            outcome = run_action(db, task.action, task.params)
            record_run(
                db,
                task,
                status="success",
                summary=str(outcome.get("summary") or ""),
            )
            results.append(
                {
                    "task": task.name,
                    "status": "success",
                    "duration_ms": round((time.time() - started) * 1000, 1),
                    "summary": outcome.get("summary"),
                }
            )
        except ActionError as exc:
            record_run(db, task, status="failed", error=exc.message)
            results.append(
                {"task": task.name, "status": "failed", "error": exc.message}
            )
        except Exception as exc:  # noqa: BLE001 - one bad task must not stop the rest
            record_run(db, task, status="failed", error=f"{type(exc).__name__}: {exc}")
            results.append(
                {
                    "task": task.name,
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
    return results


def run_history(db: Database, *, limit: int = 50) -> list[dict[str, Any]]:
    ensure_schema(db)
    rows = db.query(
        """
        SELECT r.*, t.name AS task_name
        FROM task_runs r JOIN scheduled_tasks t ON t.id = r.task_id
        ORDER BY r.started_at DESC LIMIT ?
        """,
        (limit,),
    )
    return [dict(row) for row in rows]
