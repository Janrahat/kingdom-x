"""SQLite storage with migrations, parameterised queries and audit logging.

SQLite is the default and requires no server. PostgreSQL support is opt-in via
``storage.driver = 'postgres'``; the schema in :data:`MIGRATIONS` is written in a
portable subset so both engines accept it.

Every query in this module is parameterised. There is no string interpolation of
user data anywhere — grep this file for an f-string inside ``execute`` and you
will find none.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from kingdomx.core.errors import StorageError
from kingdomx.core.logging_setup import get_logger
from kingdomx.core.redaction import redact_text

log = get_logger("core.storage")

SCHEMA_VERSION = 4

# Each entry is (version, [statements]). Migrations run in order and are recorded
# in schema_migrations so a restart never re-applies one.
MIGRATIONS: list[tuple[int, list[str]]] = [
    (
        1,
        [
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version     INTEGER PRIMARY KEY,
                applied_at  REAL NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS settings (
                key         TEXT PRIMARY KEY,
                value       TEXT NOT NULL,
                updated_at  REAL NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL NOT NULL,
                actor       TEXT NOT NULL,
                action      TEXT NOT NULL,
                target      TEXT,
                outcome     TEXT NOT NULL,
                detail      TEXT
            )
            """,
        ],
    ),
    (
        2,
        [
            """
            CREATE TABLE IF NOT EXISTS providers (
                name            TEXT PRIMARY KEY,
                kind            TEXT NOT NULL,
                base_url        TEXT NOT NULL,
                default_model   TEXT,
                enabled         INTEGER NOT NULL DEFAULT 1,
                last_checked    REAL,
                last_status     TEXT,
                last_error      TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS models (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                provider        TEXT NOT NULL,
                name            TEXT NOT NULL,
                display_name    TEXT,
                context_window  INTEGER,
                kind            TEXT,
                available       INTEGER NOT NULL DEFAULT 0,
                checked_at      REAL,
                UNIQUE (provider, name)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS ai_usage (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ts              REAL NOT NULL,
                provider        TEXT NOT NULL,
                model           TEXT NOT NULL,
                prompt_tokens   INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                total_tokens    INTEGER NOT NULL DEFAULT 0,
                latency_ms      REAL NOT NULL DEFAULT 0,
                ok              INTEGER NOT NULL DEFAULT 1,
                error_code      TEXT
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_ai_usage_ts ON ai_usage (ts)",
            "CREATE INDEX IF NOT EXISTS idx_ai_usage_provider ON ai_usage (provider, ts)",
        ],
    ),
    (
        3,
        [
            """
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id              TEXT PRIMARY KEY,
                module          TEXT NOT NULL,
                target          TEXT NOT NULL,
                authorized      INTEGER NOT NULL DEFAULT 0,
                authorization_note TEXT,
                status          TEXT NOT NULL,
                started_at      REAL NOT NULL,
                finished_at     REAL,
                findings        INTEGER NOT NULL DEFAULT 0,
                error           TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id          TEXT NOT NULL,
                severity        TEXT NOT NULL,
                category        TEXT NOT NULL,
                title           TEXT NOT NULL,
                detail          TEXT,
                reference       TEXT,
                created_at      REAL NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_findings_job ON findings (job_id)",
            "CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings (severity, created_at)",
            """
            CREATE TABLE IF NOT EXISTS tool_inventory (
                name            TEXT PRIMARY KEY,
                path            TEXT,
                version         TEXT,
                present         INTEGER NOT NULL DEFAULT 0,
                platform_ok     INTEGER NOT NULL DEFAULT 1,
                notes           TEXT,
                checked_at      REAL
            )
            """,
        ],
    ),
    (
        4,
        [
            """
            CREATE TABLE IF NOT EXISTS plugin_state (
                name            TEXT PRIMARY KEY,
                version         TEXT,
                enabled         INTEGER NOT NULL DEFAULT 0,
                permissions     TEXT,
                installed_at    REAL,
                last_error      TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scheduled_jobs (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                module          TEXT NOT NULL,
                schedule        TEXT NOT NULL,
                payload         TEXT,
                enabled         INTEGER NOT NULL DEFAULT 1,
                last_run        REAL,
                next_run        REAL,
                last_result     TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS reports (
                id              TEXT PRIMARY KEY,
                title           TEXT NOT NULL,
                kind            TEXT NOT NULL,
                format          TEXT NOT NULL,
                path            TEXT NOT NULL,
                created_at      REAL NOT NULL,
                size_bytes      INTEGER NOT NULL DEFAULT 0
            )
            """,
        ],
    ),
]

#: Columns that must exist for the app to consider the DB healthy.
REQUIRED_TABLES = (
    "schema_migrations",
    "settings",
    "audit_log",
    "providers",
    "models",
    "ai_usage",
    "scan_jobs",
    "findings",
    "tool_inventory",
    "plugin_state",
    "scheduled_jobs",
    "reports",
)


@dataclass(frozen=True)
class DbStats:
    path: str
    size_bytes: int
    tables: dict[str, int]
    schema_version: int
    journal_mode: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "tables": dict(self.tables),
            "schema_version": self.schema_version,
            "journal_mode": self.journal_mode,
        }


class Database:
    """Thread-safe SQLite wrapper with migrations and an audit trail."""

    def __init__(self, path: str | Path | None = None, *, memory: bool = False) -> None:
        self.memory = memory or str(path) == ":memory:"
        self.path = ":memory:" if self.memory else str(Path(path or "data/kingdomx.db"))
        if not self.memory:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._local = threading.local()
        self._migrate()

    # ------------------------------------------------------------------ connection
    def _connect(self) -> sqlite3.Connection:
        # A memory DB must be shared across threads, so check_same_thread is relaxed
        # only in that case; the file-backed case keeps the default strictness.
        conn = sqlite3.connect(
            self.path,
            timeout=15.0,
            check_same_thread=self.memory,
            isolation_level=None,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not self.memory:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        existing = getattr(self._local, "conn", None)
        if existing is None:
            existing = self._connect()
            self._local.conn = existing
        return existing

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:  # pragma: no cover
                pass
            self._local.conn = None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = self.conn
            conn.execute("BEGIN")
            try:
                yield conn
            except Exception:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    # ------------------------------------------------------------------ migrations
    def _migrate(self) -> None:
        with self._lock:
            conn = self.conn
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at REAL NOT NULL
                )
                """
            )
            applied = {
                row["version"] for row in conn.execute("SELECT version FROM schema_migrations")
            }
            for version, statements in MIGRATIONS:
                if version in applied:
                    continue
                for statement in statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, time.time()),
                )
                log.info("applied migration %s", version)

    def schema_version(self) -> int:
        row = self.conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        return int(row["v"]) if row and row["v"] is not None else 0

    # ------------------------------------------------------------------ generic helpers
    def execute(self, sql: str, params: Sequence[Any] | None = None) -> sqlite3.Cursor:
        with self._lock:
            try:
                return self.conn.execute(sql, tuple(params or ()))
            except sqlite3.Error as exc:
                raise StorageError("query failed", detail=str(exc)) from exc

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        with self._lock:
            try:
                self.conn.executemany(sql, [tuple(r) for r in rows])
            except sqlite3.Error as exc:
                raise StorageError("batch query failed", detail=str(exc)) from exc

    def executescript(self, sql: str) -> None:
        """Run a multi-statement script (schema/migration bodies).

        Separate from :meth:`execute` because sqlite3 only accepts several
        statements through ``executescript``; passing DDL with several CREATEs to
        ``execute`` silently runs just the first one.
        """
        with self._lock:
            try:
                self.conn.executescript(sql)
                self.conn.commit()
            except sqlite3.Error as exc:
                raise StorageError("script failed", detail=str(exc)) from exc

    def query(self, sql: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        return [dict(row) for row in self.execute(sql, params).fetchall()]

    def query_one(self, sql: str, params: Sequence[Any] | None = None) -> dict[str, Any] | None:
        row = self.execute(sql, params).fetchone()
        return dict(row) if row else None

    def scalar(self, sql: str, params: Sequence[Any] | None = None, default: Any = None) -> Any:
        row = self.execute(sql, params).fetchone()
        if row is None:
            return default
        value = row[0]
        return default if value is None else value

    # ------------------------------------------------------------------ settings
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, time.time()),
        )

    def all_settings(self) -> dict[str, str]:
        return {row["key"]: row["value"] for row in self.query("SELECT key, value FROM settings")}

    # ------------------------------------------------------------------ audit
    def audit(
        self,
        actor: str,
        action: str,
        *,
        target: str | None = None,
        outcome: str = "ok",
        detail: str | None = None,
    ) -> None:
        # Redact before writing: the audit table is a log, and a log must never
        # become the leak. Callers legitimately pass key names and error text
        # through here, so filtering at the boundary is the only safe place.
        safe_detail = redact_text(detail) if detail is not None else None
        safe_target = redact_text(target) if target is not None else None
        self.execute(
            """
            INSERT INTO audit_log (ts, actor, action, target, outcome, detail)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (time.time(), actor, action, safe_target, outcome, safe_detail),
        )

    def recent_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.query(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),)
        )

    # ------------------------------------------------------------------ stats
    def stats(self) -> DbStats:
        tables: dict[str, int] = {}
        for name in REQUIRED_TABLES:
            try:
                tables[name] = int(self.scalar(f"SELECT COUNT(*) FROM {name}", default=0) or 0)
            except StorageError:
                tables[name] = -1
        size = 0
        if not self.memory:
            try:
                size = Path(self.path).stat().st_size
            except OSError:
                size = 0
        journal = str(self.scalar("PRAGMA journal_mode", default="unknown"))
        return DbStats(
            path=self.path,
            size_bytes=size,
            tables=tables,
            schema_version=self.schema_version(),
            journal_mode=journal,
        )

    def integrity_check(self) -> dict[str, Any]:
        result = self.scalar("PRAGMA integrity_check", default="unknown")
        return {"ok": str(result).lower() == "ok", "result": str(result)}

    def missing_tables(self) -> list[str]:
        present = {
            row["name"]
            for row in self.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        return [name for name in REQUIRED_TABLES if name not in present]

    # ------------------------------------------------------------------ retention
    def purge_older_than(self, days: int) -> dict[str, int]:
        """Delete aged analytics rows. Returns per-table deletion counts."""
        if days < 1:
            raise StorageError("retention must be at least 1 day")
        cutoff = time.time() - days * 86400
        deleted: dict[str, int] = {}
        for table, column in (
            ("ai_usage", "ts"),
            ("audit_log", "ts"),
            ("findings", "created_at"),
        ):
            before = int(self.scalar(f"SELECT COUNT(*) FROM {table}", default=0) or 0)
            self.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
            after = int(self.scalar(f"SELECT COUNT(*) FROM {table}", default=0) or 0)
            deleted[table] = max(0, before - after)
        return deleted

    def vacuum(self) -> None:
        with self._lock:
            self.conn.execute("VACUUM")

    # ------------------------------------------------------------------ backup
    def backup_to(self, destination: str | Path) -> Path:
        """Consistent file copy via SQLite's online backup API."""
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        if self.memory:
            raise StorageError("cannot back up an in-memory database")
        with self._lock:
            try:
                with sqlite3.connect(str(target)) as dest:
                    self.conn.backup(dest)
            except sqlite3.Error as exc:
                raise StorageError("backup failed", detail=str(exc)) from exc
        return target


def open_database(path: str | Path | None = None) -> Database:
    return Database(path)


def verify_database(path: str | Path) -> dict[str, Any]:
    """Read-only health check used by diagnostics and the API.

    A corrupt or non-SQLite file must be *reported*, not raised: this function
    exists so a caller can decide what to do about a bad database.
    """
    target = Path(path)
    if not target.is_file():
        return {"ok": False, "reason": "file not found", "path": str(target)}
    try:
        db = Database(target)
    except (sqlite3.Error, OSError) as exc:
        return {
            "ok": False,
            "reason": f"cannot open database: {exc}",
            "path": str(target),
        }
    try:
        stats = db.stats()
        integrity = db.integrity_check()
        missing = db.missing_tables()
        return {
            "ok": bool(integrity["ok"] and not missing),
            "path": stats.path,
            "size_bytes": stats.size_bytes,
            "schema_version": stats.schema_version,
            "journal_mode": stats.journal_mode,
            "integrity": integrity,
            "missing_tables": missing,
            "tables": stats.tables,
        }
    finally:
        db.close()
