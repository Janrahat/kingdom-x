from __future__ import annotations

from kingdomx.dns.lookup import parse_resolv_conf


def test_parse_resolv_conf_reads_valid_nameservers(tmp_path):
    config = tmp_path / "resolv.conf"
    config.write_text(
        "# resolver config\n"
        "search example.test\n"
        "nameserver 8.8.8.8\n"
        "nameserver 8.8.4.4\n"
        "nameserver not-an-ip\n",
        encoding="utf-8",
    )

    assert parse_resolv_conf(str(config)) == ["8.8.8.8", "8.8.4.4"]


def test_parse_resolv_conf_returns_empty_for_missing_file(tmp_path):
    assert parse_resolv_conf(str(tmp_path / "missing-resolv.conf")) == []
