#!/usr/bin/env python3
"""KINGDOM X launcher.

Works without installing the package (``python kingdomx.py``) and without a
virtual environment active, as long as the dependencies are importable.

    python kingdomx.py              interactive terminal UI
    python kingdomx.py status       module status report
    python kingdomx.py selftest     verify the install
    python kingdomx.py web          web dashboard on 127.0.0.1:8000
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the checkout importable without `pip install -e .`
sys.path.insert(0, str(Path(__file__).resolve().parent))

MIN_PYTHON = (3, 10)


def main() -> int:
    if sys.version_info < MIN_PYTHON:
        sys.stderr.write(
            f"KINGDOM X needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer; "
            f"this is {sys.version.split()[0]}.\n"
        )
        return 1

    try:
        from kingdomx.cli.main import main as cli_main
    except ImportError as exc:
        missing = getattr(exc, "name", None) or str(exc)
        sys.stderr.write(
            "KINGDOM X could not start: a dependency is missing "
            f"({missing}).\n\n"
            "  Debian/Kali : sudo apt install -y python3-venv python3-pip\n"
            "                python3 -m venv .venv && source .venv/bin/activate\n"
            "                pip install -r requirements.txt\n"
            "  Termux      : pkg install -y python && pip install -r requirements.txt\n\n"
            "Or run the bundled installer: ./install-kali.sh | ./install-termux.sh\n"
        )
        return 1

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
