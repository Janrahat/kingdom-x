"""Shared fixtures.

Every test in this suite runs **offline**. Anything that would touch the network
is either skipped with an explicit marker or exercised through a fixture that
reads a canned payload. That keeps the suite deterministic and means a green run
proves something about the code, not about the weather at the other end of a
socket.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Point every path KINGDOM X derives at a throwaway directory."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("KINGDOMX_HOME", str(home / ".kingdomx"))
    monkeypatch.setenv("KINGDOMX_OFFLINE", "1")
    # Make sure no ambient provider keys leak into a test.
    for name in list(os.environ):
        if name.endswith("_API_KEY") or name in {"OPENAI_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY"}:
            monkeypatch.delenv(name, raising=False)
    yield home


@pytest.fixture
def workdir(tmp_path):
    directory = tmp_path / "work"
    directory.mkdir()
    return directory


@pytest.fixture
def db():
    from kingdomx.core.storage import Database

    database = Database(memory=True)
    yield database
    database.close()


@pytest.fixture
def sample_log():
    """A small, realistic auth log containing several detectable patterns."""
    return "\n".join(
        [
            "Jan  5 10:00:01 host sshd[100]: Accepted password for alice from 203.0.113.5 port 51234 ssh2",
            "Jan  5 10:00:05 host sshd[101]: Failed password for root from 198.51.100.7 port 40001 ssh2",
            "Jan  5 10:00:06 host sshd[101]: Failed password for root from 198.51.100.7 port 40002 ssh2",
            "Jan  5 10:00:07 host sshd[101]: Failed password for root from 198.51.100.7 port 40003 ssh2",
            "Jan  5 10:00:08 host sshd[101]: Failed password for root from 198.51.100.7 port 40004 ssh2",
            "Jan  5 10:00:09 host sshd[101]: Failed password for root from 198.51.100.7 port 40005 ssh2",
            "Jan  5 10:00:10 host sshd[101]: Failed password for root from 198.51.100.7 port 40006 ssh2",
            "Jan  5 10:00:11 host sshd[102]: Invalid user oracle from 192.0.2.44 port 33333",
            "Jan  5 10:01:00 host sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
            "Jan  5 10:02:00 host kernel: Out of memory: Killed process 4242 (python3)",
            "Jan  5 10:03:00 host kernel: python3[4243]: segfault at 0 ip 00007f sp 00007ff error 4",
            "Jan  5 10:04:00 host systemd[1]: No space left on device",
        ]
    )


@pytest.fixture
def sample_nmap_xml():
    """Real-shaped nmap XML, trimmed to what the parser actually reads."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -Pn --top-ports 100 -oX - 127.0.0.1">
  <host starttime="1700000000" endtime="1700000010">
    <status state="up" reason="user-set"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="631">
        <state state="open" reason="syn-ack"/>
        <service name="ipp"/>
      </port>
      <port protocol="tcp" portid="5432">
        <state state="closed" reason="conn-refused"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000010" elapsed="2.41"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""


@pytest.fixture
def sample_http_headers():
    """Headers as the audit sees them, with real weaknesses present."""
    return {
        "server": "nginx/1.18.0",
        "content-type": "text/html; charset=UTF-8",
        "x-powered-by": "PHP/7.4.3",
        "set-cookie": "session=abc123; Path=/",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
    }
