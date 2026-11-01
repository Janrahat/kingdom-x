#!/usr/bin/env bash
# KINGDOM X — Kali Linux / Debian-family installer.
# Idempotent: safe to re-run. Never needs root for normal features.
set -euo pipefail

BOLD=$'\033[1m'; GOLD=$'\033[38;5;178m'; GREEN=$'\033[32m'
YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'

say()  { printf '%s[KINGDOM X]%s %s\n' "$GOLD" "$RESET" "$*"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
die()  { printf '%s✗ %s%s\n' "$RED" "$*" "$RESET" >&2; exit 1; }

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

printf '%s\n' "$BOLD$GOLD"
printf '  ▄▄ KINGDOM X ▄▄  THE KING OF GLOBAL TECHNOLOGY\n'
printf '  ONE PLATFORM. ALL TECHNOLOGIES. UNLIMITED INTELLIGENCE.%s\n\n' "$RESET"

# ---------------------------------------------------------------- platform check
say "detecting platform"
if [[ -n "${PREFIX:-}" && "${PREFIX:-}" == *com.termux* ]]; then
  die "This is Termux. Run ./install-termux.sh instead."
fi

DISTRO="unknown"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO="${ID:-unknown}"
fi
ok "distribution: $DISTRO"

# ------------------------------------------------------------------- python check
say "checking python"
PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
done
[[ -n "$PY" ]] || die "python3 not found. Install it: sudo apt install -y python3 python3-venv python3-pip"

if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
  die "$($PY --version) is too old. Python 3.9 or newer is required."
fi
ok "$($PY --version)"

# ------------------------------------------------------------------ system packages
if command -v apt-get >/dev/null 2>&1; then
  say "checking Debian packages (venv + pip)"
  MISSING=""
  dpkg -s python3-venv >/dev/null 2>&1 || MISSING="$MISSING python3-venv"
  dpkg -s python3-pip  >/dev/null 2>&1 || MISSING="$MISSING python3-pip"
  if [[ -n "$MISSING" ]]; then
    if [[ $EUID -eq 0 ]]; then
      apt-get update -qq && apt-get install -y $MISSING
    else
      warn "missing:$MISSING"
      warn "re-run with sudo for these, or install them manually:"
      warn "  sudo apt-get install -y$MISSING"
    fi
  else
    ok "python3-venv, python3-pip present"
  fi
fi

# ------------------------------------------------------------------- virtualenv
say "creating the virtual environment (.venv)"
if [[ ! -d .venv ]]; then
  "$PY" -m venv .venv || die "venv creation failed. On Debian install python3-venv."
  ok "created .venv"
else
  ok ".venv already present"
fi

# shellcheck disable=SC1091
source .venv/bin/activate

say "upgrading pip"
python -m pip install --quiet --upgrade pip wheel

say "installing dependencies"
if [[ -f requirements.txt ]]; then
  python -m pip install --quiet -r requirements.txt || die "dependency install failed"
  ok "core requirements installed"
else
  warn "requirements.txt missing — skipping"
fi

# dnspython is genuinely optional: the resolver falls back to libc getaddrinfo.
if python -c 'import dns.resolver' >/dev/null 2>&1; then
  ok "dnspython available (full record-type support)"
else
  warn "dnspython not importable — A/AAAA/CNAME still work via the OS resolver,"
  warn "MX/TXT/NS/SOA will report as unavailable. Install with:"
  warn "  python -m pip install dnspython"
fi

# ------------------------------------------------------------------- database
say "initialising the database"
python - <<'PY'
from kingdomx.core.config import Config
from kingdomx.core.storage import Database

config = Config.load()
db = Database(config.db_path)
db.audit("installer", "install.initialise", outcome="ok", detail="kali")
print(f"  ok database ready at {config.db_path}")
db.close()
PY

say "checking the install"
python - <<'PY'
from kingdomx.core.registry import REGISTRY
counts = REGISTRY.counts()
working = counts.get("WORKING", 0)
total = sum(counts.values())
print(f"  ok {total} modules registered, {working} working without extra input")
PY

cat <<EOF

${BOLD}${GOLD}Installation complete.${RESET}

  Activate the environment : source .venv/bin/activate
  Launch the terminal UI   : python kingdomx.py
  Module status report     : python kingdomx.py status
  Self test                : python kingdomx.py selftest
  Web dashboard            : python kingdomx.py web
  Run the test suite       : python -m pytest tests/ -q

  The dashboard listens on http://127.0.0.1:8000 by default.
  A local server cannot receive internet visitors — see docs/DEPLOYMENT.md.

EOF
