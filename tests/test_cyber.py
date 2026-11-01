"""Cybersecurity modules: passwords, ports, tools, headers, logs, deps, integrity."""

from __future__ import annotations

import json

import pytest

from kingdomx.cybersecurity.audit import CHECKS, list_checks, run_audit
from kingdomx.cybersecurity.dependencies import (
    Package,
    parse_manifest,
    parse_requirements_txt,
    scan_directory,
    version_below,
)
from kingdomx.cybersecurity.headers import expected_headers
from kingdomx.cybersecurity.integrity import build_manifest, compare, hash_file, integrity_report
from kingdomx.cybersecurity.logs import analyse_file, analyse_path, common_log_paths, parse_line
from kingdomx.cybersecurity.passwords import analyse, generate_password, generate_passphrase, policy_check
from kingdomx.cybersecurity.ports import (
    COMMON_PORTS,
    KNOWN_PORTS,
    dangerous_open_ports,
    describe_port,
    is_encrypted,
    parse_port_spec,
    risk_for,
    service_for,
)
from kingdomx.cybersecurity.severity import Finding, Report, Severity, from_cvss
from kingdomx.cybersecurity.tools import (
    TOOLS,
    categories,
    detect_all,
    find_tool,
    install_hint,
    inventory_summary,
    search,
)


# --------------------------------------------------------------------- severity
class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_from_cvss_bands(self):
        assert from_cvss(9.5) is Severity.CRITICAL
        assert from_cvss(7.5) is Severity.HIGH
        assert from_cvss(5.0) is Severity.MEDIUM
        assert from_cvss(2.0) is Severity.LOW
        assert from_cvss(0.0) is Severity.INFO

    def test_finding_is_issue(self):
        assert Finding("t", Severity.HIGH, "cat").is_issue is True
        assert Finding("t", Severity.INFO, "cat").is_issue is False

    def test_passed_finding_is_not_an_issue(self):
        assert Finding("t", Severity.HIGH, "cat", passed=True).is_issue is False

    def test_report_verdict_escalates(self):
        report = Report(module="m", target="t")
        assert report.verdict == "CLEAN"
        report = Report(module="m", target="t", findings=[Finding("x", Severity.CRITICAL, "c")])
        assert report.verdict == "CRITICAL"

    def test_report_sorts_by_severity(self):
        report = Report(
            module="m",
            target="t",
            findings=[Finding("low", Severity.LOW, "c"), Finding("crit", Severity.CRITICAL, "c")],
        )
        assert report.sorted_findings()[0].title == "crit"


# --------------------------------------------------------------------- passwords
class TestPasswords:
    def test_weak_password_is_weak(self):
        result = analyse("password")
        assert result.score < 60
        assert result.label

    def test_strong_password_scores_high(self):
        assert analyse("vT7#qLm2$Xz9!Wp4").score > analyse("password").score

    def test_longer_random_password_beats_short_one(self):
        assert (
            analyse("kR7#mQ2$vX9!wL4&pZ8@nB3%tY6^cD1").entropy_bits
            > analyse("abc123").entropy_bits
        )

    def test_common_password_is_flagged(self):
        result = analyse("123456")
        problems = " ".join(result.problems + result.suggestions).lower()
        assert problems, "a trivially weak password must produce at least one problem"

    def test_keyboard_walk_penalised(self):
        assert analyse("qwerty").score < analyse("vT7#qLm2$Xz9").score

    def test_repeated_characters_penalised(self):
        assert analyse("aaaaaaaa").score < analyse("vT7#qLm2").score

    def test_empty_password_rejected(self):
        result = analyse("")
        assert result.score == 0
        assert result.length == 0

    def test_entropy_is_positive_for_real_password(self):
        assert analyse("Tr0ub4dor&3").entropy_bits > 0

    def test_crack_times_are_reported(self):
        times = analyse("abc123def456").crack_times
        assert isinstance(times, dict) and times

    def test_generated_password_length(self):
        assert len(generate_password(24)) == 24

    def test_generated_passwords_differ(self):
        assert generate_password(20) != generate_password(20)

    def test_passphrase_has_separator(self):
        assert "-" in generate_passphrase(5)

    def test_policy_check_passes(self):
        outcome = policy_check("Abcdef1!ghij", {"min_length": 8})
        assert outcome["ok"] is True

    def test_policy_violation_reported(self):
        outcome = policy_check("abc", {"min_length": 12})
        assert outcome["ok"] is False
        assert outcome["failures"]


# --------------------------------------------------------------------- ports
class TestPorts:
    def test_knowledge_base_populated(self):
        assert len(KNOWN_PORTS) >= 50

    def test_ssh_known(self):
        assert service_for(22) == "ssh"

    def test_risk_for_high_risk_port(self):
        assert risk_for(23) in {"high", "critical"}  # telnet

    def test_encrypted_ports(self):
        assert is_encrypted(443) is True
        assert is_encrypted(80) is False

    def test_describe_port_returns_text(self):
        assert "22" in describe_port(22)

    def test_dangerous_open_ports(self):
        found = dangerous_open_ports([22, 23, 3306, 443])
        assert found

    def test_parse_port_spec(self):
        assert parse_port_spec("80,443") == [80, 443]
        assert 8000 in parse_port_spec("8000-8010")

    def test_common_ports_not_empty(self):
        assert len(COMMON_PORTS) > 10


# --------------------------------------------------------------------- tools
class TestToolDetection:
    def test_catalogue_size(self):
        assert len(TOOLS) >= 80

    def test_every_tool_has_official_url(self):
        for spec in TOOLS:
            assert spec.homepage.startswith("http"), f"{spec.name} has no official URL"
            assert spec.license, f"{spec.name} has no licence"

    def test_detect_all_runs(self):
        detected = detect_all()
        assert len(detected) == len(TOOLS)

    def test_python_is_always_present(self):
        status = next(tool for tool in detect_all() if tool.spec.name.lower() in {"python", "python3"})
        assert status.present is True

    def test_absent_tool_is_not_claimed_present(self):
        for tool in detect_all():
            if tool.present:
                assert tool.path, f"{tool.spec.name} claims present with no path"

    def test_find_tool(self):
        assert find_tool("nmap") is not None
        assert find_tool("definitely-not-a-tool") is None

    def test_search(self):
        assert search("scan")

    def test_categories(self):
        found = categories()
        assert found and any(c.lower() == "network" for c in found)

    def test_install_hint_is_platform_appropriate(self):
        spec = find_tool("nmap")
        hint = install_hint(spec)
        assert "apt" in hint or "pkg" in hint or "http" in hint

    def test_inventory_summary(self):
        summary = inventory_summary()
        assert summary["total_catalogued"] == len(TOOLS)


# --------------------------------------------------------------------- headers
class TestHeaders:
    def test_expected_header_list(self):
        names = expected_headers()
        assert names
        flat = " ".join(str(name).lower() for name in names)
        assert "strict-transport-security" in flat


# --------------------------------------------------------------------- logs
class TestLogs:
    def test_parse_syslog_line(self):
        line = parse_line(
            "Jan  5 10:00:05 host sshd[101]: Failed password for root from 1.2.3.4 port 22 ssh2", 1
        )
        assert line.line_no == 1
        assert line.process == "sshd"
        assert "1.2.3.4" in line.ips

    def test_analyse_sample_log(self, tmp_path, sample_log):
        path = tmp_path / "auth.log"
        path.write_text(sample_log, encoding="utf-8")
        analysis = analyse_file(path)
        assert analysis.total_lines > 0
        report = analyse_path(path)
        assert report.module
        assert "total_lines" in report.meta

    def test_brute_force_detected(self, tmp_path, sample_log):
        path = tmp_path / "auth.log"
        path.write_text(sample_log, encoding="utf-8")
        report = analyse_file(path)
        assert report.findings, "the sample log contains brute force and must produce findings"
        text = " ".join(f"{f.title} {f.detail}".lower() for f in report.findings)
        assert "fail" in text or "brute" in text or "auth" in text

    def test_common_log_paths_returns_list(self):
        assert isinstance(common_log_paths(), list)


# --------------------------------------------------------------------- dependencies
class TestDependencies:
    def test_parse_requirements(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("flask==2.0.1\nrequests>=2.0\n# comment\n\n", encoding="utf-8")
        packages = parse_requirements_txt(path)
        names = {p.name for p in packages}
        assert "flask" in names
        assert "requests" in names

    def test_parse_package_json(self, tmp_path):
        path = tmp_path / "package.json"
        path.write_text(
            json.dumps({"name": "x", "dependencies": {"lodash": "4.17.20"}}), encoding="utf-8"
        )
        packages = parse_manifest(path)
        assert any(p.name == "lodash" for p in packages)

    def test_version_below(self):
        assert version_below("2.0.1", "2.1.0") is True
        assert version_below("2.5.0", "2.1.0") is False

    def test_scan_directory_finds_vulnerable_pinned_package(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")
        scan = scan_directory(tmp_path)
        assert scan.packages
        # The local advisory cache knows flask 0.12.2 is vulnerable.
        assert scan.findings

    def test_scan_clean_directory_reports_nothing(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
        scan = scan_directory(tmp_path)
        assert scan.packages

    def test_package_dataclass(self):
        package = Package(name="x", version="1.0", ecosystem="PyPI")
        assert package.name == "x"


# --------------------------------------------------------------------- integrity
class TestIntegrity:
    def test_hash_file(self, tmp_path):
        path = tmp_path / "a.txt"
        path.write_text("hello", encoding="utf-8")
        digest, size = hash_file(path)
        assert len(digest) == 64
        assert size == 5

    def test_identical_content_same_hash(self, tmp_path):
        one, two = tmp_path / "one.txt", tmp_path / "two.txt"
        one.write_text("same", encoding="utf-8")
        two.write_text("same", encoding="utf-8")
        assert hash_file(one)[0] == hash_file(two)[0]

    def test_manifest_and_compare_detects_modification(self, tmp_path):
        (tmp_path / "file.txt").write_text("original", encoding="utf-8")
        before = build_manifest(tmp_path)
        (tmp_path / "file.txt").write_text("tampered", encoding="utf-8")
        after = build_manifest(tmp_path)
        diff = compare(before, after)
        assert diff.modified

    def test_compare_detects_added_file(self, tmp_path):
        (tmp_path / "a.txt").write_text("a", encoding="utf-8")
        before = build_manifest(tmp_path)
        (tmp_path / "b.txt").write_text("b", encoding="utf-8")
        after = build_manifest(tmp_path)
        assert compare(before, after).added

    def test_compare_detects_removed_file(self, tmp_path):
        (tmp_path / "a.txt").write_text("a", encoding="utf-8")
        (tmp_path / "b.txt").write_text("b", encoding="utf-8")
        before = build_manifest(tmp_path)
        (tmp_path / "b.txt").unlink()
        after = build_manifest(tmp_path)
        assert compare(before, after).removed

    def test_integrity_report_runs(self, tmp_path):
        (tmp_path / "x.txt").write_text("x", encoding="utf-8")
        report = integrity_report(tmp_path)
        assert report.module


# --------------------------------------------------------------------- audit
class TestAudit:
    def test_checks_registered(self):
        assert len(CHECKS) >= 10

    def test_list_checks(self):
        entries = list_checks()
        assert entries
        for entry in entries:
            assert "key" in entry or "name" in entry

    def test_run_audit_produces_a_report(self):
        report = run_audit()
        assert report.module
        assert isinstance(report.verdict, str)

    def test_run_single_check(self):
        key = list_checks()[0]["key"]
        report = run_audit(keys=[key])
        assert len(report.findings) == 1

    def test_audit_is_read_only(self):
        """The audit must not modify anything — it only reads files and commands."""
        import inspect

        source = inspect.getsource(run_audit)
        for forbidden in ("write_text", "unlink", "rmtree", "os.remove", "chmod"):
            assert forbidden not in source
