"""CLI smoke tests.

These exist because three real bugs shipped that the unit suite could not see:
``doctor`` raised ``KeyError: 'arch'``, ``dns`` raised ``AttributeError`` on
``DnsResult.records``, and ``--json`` only worked *before* the subcommand. All
three were in the argument-parsing / rendering layer, which the module tests
never exercised.

Every test here runs the real parser and the real command function. Network
commands are only asserted to produce valid JSON, never to succeed, so the suite
stays offline-safe.
"""

from __future__ import annotations

import argparse
import json

import pytest

from kingdomx.cli.main import App, build_parser, main
from kingdomx.core.config import Config
from kingdomx.core.storage import Database
from kingdomx.core.ui import Ui


@pytest.fixture()
def app(tmp_path):
    config = Config.load()
    db = Database(tmp_path / "smoke.db")
    yield App(ui=Ui.create(plain=True), config=config, db=db)
    db.close()


# --------------------------------------------------------------------------- parser
def test_json_flag_accepted_before_subcommand():
    args = build_parser().parse_args(["--json", "status"])
    assert args.json is True
    assert args.command == "status"


@pytest.mark.parametrize(
    "argv",
    [
        ["status", "--json"],
        ["selftest", "--json"],
        ["doctor", "--json"],
        ["audit", "--json"],
        ["tools", "--json"],
        ["dns", "example.com", "--json"],
        ["ip", "8.8.8.8", "--json"],
        ["phone", "+966501234567", "--json"],
        ["tools", "--search", "nmap", "--json"],
        ["dns", "example.com", "--diagnose", "--json"],
    ],
)
def test_json_flag_accepted_after_subcommand(argv):
    """Regression: the subparsers used to reject ``--json`` entirely."""
    args = build_parser().parse_args(argv)
    assert args.json is True


def test_global_json_survives_subparser_default():
    """Regression: a subparser default must not clobber the global flag.

    ``default=argparse.SUPPRESS`` is what makes this work; with a plain
    ``store_true`` the subparser would reset ``json`` to False.
    """
    assert build_parser().parse_args(["--json", "status"]).json is True
    assert build_parser().parse_args(["status"]).json is False


def test_plain_flag_accepted_after_subcommand():
    assert build_parser().parse_args(["status", "--plain"]).plain is True


# --------------------------------------------------------------------------- doctor
def test_doctor_renders_without_keyerror(app, capsys):
    """Regression: ``snap["os"]["arch"]`` raised KeyError; the key is ``architecture``."""
    from kingdomx.cli.main import cmd_doctor

    code = cmd_doctor(app, argparse.Namespace(json=False))
    out = capsys.readouterr().out
    assert "Arch" in out
    assert "KeyError" not in out
    assert code in (0, 1)


def test_doctor_json_has_architecture_key(app, capsys):
    from kingdomx.cli.main import cmd_doctor

    cmd_doctor(app, argparse.Namespace(json=True))
    payload = json.loads(capsys.readouterr().out)
    assert "architecture" in payload["health"]["snapshot"]["os"]
    assert "arch" not in payload["health"]["snapshot"]["os"]


# --------------------------------------------------------------------------- dns
def test_dns_result_has_no_records_attribute():
    """Regression guard: the CLI must use ``answers``/``record_type``."""
    from kingdomx.dns.lookup import DnsResult

    result = DnsResult(name="example.com", record_type="A")
    assert hasattr(result, "answers")
    assert hasattr(result, "record_type")
    assert not hasattr(result, "records")
    assert not hasattr(result, "query_type")


def test_dns_renders_answers_without_attributeerror(app, capsys):
    """Regression: ``records.records`` / ``rec.type`` / ``records.query_type``."""
    from kingdomx.cli.main import cmd_dns

    code = cmd_dns(app, argparse.Namespace(target="example.com", type="A", diagnose=False, json=False))
    out = capsys.readouterr().out
    assert "AttributeError" not in out
    assert code == 0


def test_dns_json_shape(app, capsys):
    from kingdomx.cli.main import cmd_dns

    cmd_dns(app, argparse.Namespace(target="example.com", type="A", diagnose=False, json=True))
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "example.com"
    assert payload["type"] == "A"
    assert "answers" in payload


def test_dns_diagnose_uses_check_and_ok_keys(app, capsys):
    """Regression: the renderer read ``c["name"]``/``c["passed"]``; diagnose emits
    ``check``/``ok``, so every row raised KeyError."""
    from kingdomx.cli.main import cmd_dns

    code = cmd_dns(app, argparse.Namespace(target="example.com", diagnose=True, json=False))
    out = capsys.readouterr().out
    assert "KeyError" not in out
    assert code == 0


def test_mx_host_extraction():
    """Regression: MX values were rewritten to ``priority=<host>``, which broke
    every caller that split the value to recover the host."""
    from kingdomx.dns.lookup import _mx_host

    assert _mx_host("10 mail.example.com.") == "mail.example.com"
    assert _mx_host("0 .") == ""
    assert _mx_host("10 priority=mail.example.com") == "mail.example.com"
    assert _mx_host("") == ""


# --------------------------------------------------------------------------- entry
def test_main_returns_int_for_status(capsys):
    assert main(["--json", "status"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "KINGDOM X"


def test_main_handles_unknown_command_gracefully():
    with pytest.raises(SystemExit):
        main(["definitely-not-a-command"])
