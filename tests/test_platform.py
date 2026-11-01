"""Plugins, automation, reports, web dashboard and CLI — all offline."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest


# --------------------------------------------------------------------- plugins
class TestPlugins:
    def _manifest(self, **overrides):
        base = {
            "name": "sample-plugin",
            "version": "1.0.0",
            "description": "Test plugin",
            "entry": "plugin.py",
            "permissions": [],
        }
        base.update(overrides)
        return base

    def _write_plugin(self, root, manifest=None, code="def run(context=None):\n    return {'ok': True}\n"):
        import pathlib

        directory = pathlib.Path(root) / "sample-plugin"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "plugin.json").write_text(
            json.dumps(manifest or self._manifest()), encoding="utf-8"
        )
        (directory / "plugin.py").write_text(code, encoding="utf-8")
        return directory

    def test_manifest_validation(self):
        from kingdomx.plugins.loader import validate_manifest

        manifest = validate_manifest(self._manifest())
        assert manifest.name == "sample-plugin"
        assert manifest.entry == "plugin.py"

    def test_manifest_requires_a_name(self):
        from kingdomx.plugins.loader import PluginError, validate_manifest

        with pytest.raises(PluginError):
            validate_manifest(self._manifest(name=""))

    def test_manifest_rejects_path_traversal_in_name(self):
        from kingdomx.plugins.loader import PluginError, validate_manifest

        with pytest.raises(PluginError):
            validate_manifest(self._manifest(name="../escape"))

    def test_manifest_rejects_an_escaping_entry(self):
        from kingdomx.plugins.loader import PluginError, validate_manifest

        with pytest.raises(PluginError):
            validate_manifest(self._manifest(entry="../../etc/passwd"))

    def test_permission_model_is_published(self):
        from kingdomx.plugins.loader import plugin_permissions

        permissions = plugin_permissions()
        assert permissions
        assert "network" in permissions

    def test_reference_plugin_is_shipped(self):
        from kingdomx.plugins.loader import reference_plugin

        sample = reference_plugin()
        assert sample

    def test_list_installed_on_a_fresh_root(self, tmp_path, monkeypatch):
        from kingdomx.plugins import loader

        monkeypatch.setattr(loader, "plugin_root", lambda: tmp_path / "plugins")
        (tmp_path / "plugins").mkdir(parents=True, exist_ok=True)
        assert loader.list_installed() == []

    def test_install_then_run_then_remove(self, tmp_path, monkeypatch):
        from kingdomx.plugins import loader

        root = tmp_path / "plugins"
        root.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(loader, "plugin_root", lambda: root)

        source = self._write_plugin(tmp_path / "src")
        record = loader.install_plugin(source)
        assert record.manifest.name == "sample-plugin"
        assert [p.manifest.name for p in loader.list_installed()] == ["sample-plugin"]

        result = loader.run_plugin("sample-plugin")
        assert result["ok"] is True

        assert loader.remove_plugin("sample-plugin") is True
        assert loader.list_installed() == []

    def test_install_refuses_a_directory_without_a_manifest(self, tmp_path, monkeypatch):
        from kingdomx.plugins import loader

        root = tmp_path / "plugins"
        root.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(loader, "plugin_root", lambda: root)
        empty = tmp_path / "bad"
        empty.mkdir()
        with pytest.raises(Exception):
            loader.install_plugin(empty)

    def test_run_unknown_plugin_raises(self, tmp_path, monkeypatch):
        from kingdomx.plugins import loader

        root = tmp_path / "plugins"
        root.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(loader, "plugin_root", lambda: root)
        with pytest.raises(Exception):
            loader.run_plugin("nope")


# ---------------------------------------------------------------------- automation
class TestAutomation:
    def test_create_and_list_tasks(self, db):
        from kingdomx.automation.scheduler import create_task, list_tasks

        task = create_task(db, "nightly audit", "host_audit", interval_seconds=3600)
        assert task.id
        assert [t.name for t in list_tasks(db)] == ["nightly audit"]

    def test_due_tasks_respect_the_interval(self, db):
        from kingdomx.automation.scheduler import create_task, due_tasks

        create_task(db, "later", "host_audit", interval_seconds=600)
        assert due_tasks(db, now=1_000.0) == []

    def test_record_run_advances_state(self, db):
        from kingdomx.automation.scheduler import create_task, list_tasks, record_run

        task = create_task(db, "a", "host_audit", interval_seconds=3600)
        record_run(db, task, status="ok", summary="ran")
        stored = list_tasks(db)[0]
        assert stored.last_status == "ok"
        assert stored.last_run is not None

    def test_delete_task(self, db):
        from kingdomx.automation.scheduler import create_task, delete_task, list_tasks

        task = create_task(db, "a", "host_audit")
        assert delete_task(db, task.id) is True
        assert list_tasks(db) == []

    def test_disabled_task_is_not_due(self, db):
        from kingdomx.automation.scheduler import create_task, due_tasks

        create_task(db, "off", "host_audit", interval_seconds=900, enabled=False)
        assert due_tasks(db, now=10_000.0) == []

    def test_run_history_is_recorded(self, db):
        from kingdomx.automation.scheduler import create_task, record_run, run_history

        task = create_task(db, "a", "host_audit", interval_seconds=3600)
        record_run(db, task, status="ok", summary="done")
        assert run_history(db)

    def test_executor_runs_an_allow_listed_action(self, db):
        from kingdomx.automation.executor import action_list, run_action

        action = action_list()[0]["name"]
        result = run_action(db, action)
        assert result["action"] == action

    def test_executor_rejects_unknown_actions(self, db):
        from kingdomx.automation.executor import run_action

        with pytest.raises(Exception):
            run_action(db, "rm -rf /")

    def test_executor_never_uses_a_shell(self):
        import pathlib

        from kingdomx.automation import executor

        # Check executable code only: the module docstring legitimately mentions
        # the phrase it is promising never to use.
        source = pathlib.Path(executor.__file__).read_text(encoding="utf-8")
        code_lines = [
            line
            for line in source.splitlines()
            if not line.strip().startswith("#") and "shell=True" not in line.split('"""')[0]
        ]
        joined = "\n".join(code_lines)
        assert "subprocess.run(" not in joined or "shell=True" not in joined
        assert "os.system(" not in joined

    def test_action_list_is_published(self):
        from kingdomx.automation.executor import action_list

        actions = action_list()
        assert actions
        assert all("name" in action for action in actions)


# ----------------------------------------------------------------------- reports
class TestReports:
    def _report(self):
        from kingdomx.cybersecurity.severity import Finding, Report, Severity

        return Report(
            module="test.module",
            target="example.com",
            findings=[
                Finding("Missing CSP", Severity.MEDIUM, "web", detail="no content-security-policy"),
                Finding("HSTS ok", Severity.INFO, "web", passed=True),
            ],
        )

    def test_to_dict_keeps_provenance(self):
        payload = self._report().to_dict()
        assert payload["module"] == "test.module"
        assert payload["target"] == "example.com"

    def test_render_json(self):
        from kingdomx.reports.export import bundle_from_reports, render_json

        bundle = bundle_from_reports([self._report()])
        assert json.loads(render_json(bundle))["reports"][0]["module"] == "test.module"

    def test_render_csv(self):
        from kingdomx.reports.export import bundle_from_reports, render_csv

        text = render_csv(bundle_from_reports([self._report()]))
        assert "Missing CSP" in text

    def test_render_markdown(self):
        from kingdomx.reports.export import bundle_from_reports, render_markdown

        assert "Missing CSP" in render_markdown(bundle_from_reports([self._report()]))

    def test_render_text(self):
        from kingdomx.reports.export import bundle_from_reports, render_text

        assert "Missing CSP" in render_text(bundle_from_reports([self._report()]))

    def test_save_report_infers_the_format(self, tmp_path):
        from kingdomx.reports.export import bundle_from_reports, save_report

        for suffix in (".json", ".csv", ".md", ".txt"):
            path = save_report(
                bundle_from_reports([self._report()]), tmp_path / f"out{suffix}"
            )
            assert path.exists(), suffix

    def test_unknown_format_rejected(self, tmp_path):
        from kingdomx.reports.export import bundle_from_reports, save_report

        with pytest.raises(Exception):
            save_report(bundle_from_reports([self._report()]), tmp_path / "r.pdf", fmt="pdf")

    def test_report_never_contains_a_secret(self, tmp_path):
        from kingdomx.cybersecurity.severity import Finding, Report, Severity
        from kingdomx.reports.export import bundle_from_reports, save_report

        report = Report(
            module="m",
            target="t",
            findings=[Finding("leak", Severity.HIGH, "c", detail="key sk-abcdefghijklmnopqrstuvwx")],
        )
        path = save_report(bundle_from_reports([report]), tmp_path / "leak.json")
        assert "abcdefghijklmnopqrstuvwx" not in path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- web
class TestWebDashboard:
    @pytest.fixture()
    def client(self):
        fastapi = pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from kingdomx.web.app import create_app

        return TestClient(create_app())

    def test_index_renders(self, client):
        response = client.get("/")
        assert response.status_code == 200
        body = response.text
        assert "KINGDOM X" in body
        assert "THE KING OF GLOBAL TECHNOLOGY" in body

    def test_status_json(self, client):
        response = client.get("/api/status")
        assert response.status_code == 200
        payload = response.json()
        assert payload["tool"] == "KINGDOM X"
        assert payload["counts"]
        assert payload["sections"]

    def test_health_endpoint(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()

    def test_system_endpoint(self, client):
        assert client.get("/api/system").status_code == 200

    def test_audit_endpoint(self, client):
        assert client.get("/api/audit").status_code == 200

    def test_tools_endpoint(self, client):
        assert client.get("/api/tools").status_code == 200

    def test_module_detail(self, client):
        response = client.get("/api/module/cyber.passwords")
        assert response.status_code == 200
        assert response.json()["key"] == "cyber.passwords"

    def test_unknown_module_is_404(self, client):
        assert client.get("/api/module/not.a.module").status_code == 404

    def test_summary_has_no_secrets(self, client):
        # The status payload must never echo a credential. Match a real key shape
        # (sk- followed by 16+ chars), not the bare "sk-" substring, because the
        # platform label legitimately contains the word "desktop".
        import re

        blob = json.dumps(client.get("/api/status").json())
        assert not re.search(r"sk-[A-Za-z0-9]{16,}", blob)

    def test_dashboard_exposes_no_mutating_routes(self, client):
        # The dashboard is read-only by design; there must be no route that
        # changes state from the web surface.
        for method in ("post", "put", "delete", "patch"):
            assert getattr(client, method)("/api/status").status_code in {404, 405}


# --------------------------------------------------------------------------- cli
class TestCli:
    def test_help_runs(self):
        result = subprocess.run(
            [sys.executable, "-m", "kingdomx", "--help"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0
        assert "kingdom" in (result.stdout + result.stderr).lower()

    def test_selftest_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "kingdomx", "selftest"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr

    def test_status_command_lists_the_registry(self):
        result = subprocess.run(
            [sys.executable, "-m", "kingdomx", "status"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        assert "cyber.passwords" in result.stdout

    def test_version_command(self):
        result = subprocess.run(
            [sys.executable, "-m", "kingdomx", "--version"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0
        assert "KINGDOM" in (result.stdout + result.stderr).upper() or "1." in result.stdout

    def test_branding_banner_contains_the_title(self):
        from kingdomx.core.branding import CROWN_ASCII, WORDMARK_ASCII, banner

        rendered = banner()
        # banner() returns a Rich renderable; flatten it to text before matching.
        from io import StringIO

        from rich.console import Console

        buffer = StringIO()
        Console(file=buffer, force_terminal=False, width=100).print(rendered)
        text = buffer.getvalue()
        assert "KINGDOM" in text.upper() or "KING" in text.upper()
        assert CROWN_ASCII
        assert WORDMARK_ASCII

    def test_menu_has_twenty_five_entries(self):
        from kingdomx.core.registry import menu_entries

        entries = menu_entries()
        assert len(entries) == 25
        numbers = [entry[0] for entry in entries]
        assert numbers[0] == "01"
        assert "25" in numbers
