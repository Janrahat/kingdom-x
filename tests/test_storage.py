"""SQLite storage: schema, settings, audit log, retention, backup, SQL safety."""

from __future__ import annotations

import sqlite3

import pytest

from kingdomx.core.storage import Database, open_database, verify_database


class TestSchema:
    def test_migrates_cleanly(self, db):
        assert db.schema_version() >= 1

    def test_integrity_check_passes(self, db):
        result = db.integrity_check()
        assert result["ok"] is True

    def test_no_missing_tables(self, db):
        assert db.missing_tables() == []

    def test_expected_tables_exist(self, db):
        names = {
            row["name"]
            for row in db.query("SELECT name FROM sqlite_master WHERE type='table'")
        }
        for table in (
            "schema_migrations", "settings", "audit_log", "providers",
            "models", "ai_usage", "scan_jobs", "findings", "tool_inventory",
            "plugin_state", "scheduled_jobs", "reports",
        ):
            assert table in names, f"missing table {table}"

    def test_reopening_is_idempotent(self, tmp_path):
        path = tmp_path / "kx.db"
        first = Database(path)
        version = first.schema_version()
        first.close()
        second = Database(path)
        assert second.schema_version() == version
        second.close()


class TestSettings:
    def test_set_and_get(self, db):
        db.set_setting("theme", "royal")
        assert db.get_setting("theme") == "royal"

    def test_get_missing_returns_default(self, db):
        assert db.get_setting("absent", "fallback") == "fallback"

    def test_overwrite(self, db):
        db.set_setting("k", "one")
        db.set_setting("k", "two")
        assert db.get_setting("k") == "two"

    def test_all_settings(self, db):
        db.set_setting("a", "1")
        db.set_setting("b", "2")
        settings = db.all_settings()
        assert settings["a"] == "1" and settings["b"] == "2"


class TestQueries:
    def test_parameterised_query_is_safe(self, db):
        db.set_setting("safe", "value")
        # A classic injection payload must be treated as a literal string.
        rows = db.query("SELECT * FROM settings WHERE key = ?", ("safe' OR '1'='1",))
        assert rows == []

    def test_execute_returns_cursor(self, db):
        cursor = db.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            ("x", "y", 0.0),
        )
        assert cursor.rowcount == 1

    def test_scalar(self, db):
        db.set_setting("count", "42")
        assert db.scalar("SELECT COUNT(*) FROM settings") == 1

    def test_transaction_rolls_back_on_error(self, db):
        before = db.scalar("SELECT COUNT(*) FROM settings")
        with pytest.raises(RuntimeError):
            with db.transaction() as conn:
                conn.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                    ("tx", "1", 0.0),
                )
                raise RuntimeError("boom")
        assert db.scalar("SELECT COUNT(*) FROM settings") == before

    def test_transaction_commits(self, db):
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                ("ok", "1", 0.0),
            )
        assert db.get_setting("ok") == "1"


class TestAudit:
    def test_audit_writes_a_row(self, db):
        db.audit("operator", "test.action", target="127.0.0.1", detail="unit test")
        rows = db.recent_audit()
        assert any(row["action"] == "test.action" for row in rows)

    def test_audit_never_stores_a_secret(self, db):
        db.audit("operator", "key.set", detail="sk-abcdefghijklmnopqrstuvwxyz0123456789")
        rows = db.recent_audit()
        assert not any("abcdefghijklmnopqrstuvwxyz" in str(row["detail"]) for row in rows if row.get("detail"))

    def test_audit_limit(self, db):
        for index in range(5):
            db.audit("op", f"action.{index}")
        assert len(db.recent_audit(limit=2)) == 2


class TestStatsAndRetention:
    def test_stats_shape(self, db):
        stats = db.stats().to_dict()
        assert "path" in stats or "tables" in stats

    def test_purge_requires_a_sane_retention(self, db):
        from kingdomx.core.errors import StorageError

        # Guardrail: purging with a sub-day window is refused.
        with pytest.raises(StorageError):
            db.purge_older_than(days=0)

    def test_purge_returns_counts(self, db):
        db.audit("op", "old.action")
        result = db.purge_older_than(days=30)
        assert isinstance(result, dict)

    def test_vacuum_runs(self, db):
        db.set_setting("a", "b")
        db.vacuum()  # must not raise

    def test_backup_refuses_in_memory(self, db):
        from kingdomx.core.errors import StorageError

        with pytest.raises(StorageError):
            db.backup_to("/tmp/should-not-exist.db")

    def test_backup_creates_a_readable_copy(self, tmp_path):
        source = Database(tmp_path / "source.db")
        source.set_setting("backup_key", "backup_value")
        destination = tmp_path / "backup.db"
        written = source.backup_to(destination)
        assert written.exists()
        copy = Database(written)
        assert copy.get_setting("backup_key") == "backup_value"
        copy.close()
        source.close()


class TestHelpers:
    def test_open_database(self, tmp_path):
        database = open_database(tmp_path / "opened.db")
        assert database.schema_version() >= 1
        database.close()

    def test_verify_database(self, tmp_path):
        path = tmp_path / "verified.db"
        Database(path).close()
        result = verify_database(path)
        assert result["ok"] is True

    def test_verify_database_flags_a_broken_file(self, tmp_path):
        broken = tmp_path / "broken.db"
        broken.write_bytes(b"this is not a sqlite file at all")
        result = verify_database(broken)
        assert result["ok"] is False
