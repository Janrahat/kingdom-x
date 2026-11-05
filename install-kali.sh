#!/usr/bin/env bash
# KINGDOM X — Kali / Debian / Ubuntu installer.
set -euo pipefail

GOLD=$'\033[38;5;178m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
RED=$'\033[31m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

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
if [[ "$(id -u)" -eq 0 ]]; then
  warn "running as root — KINGDOM X does not need root and will not use it"
fi

if command -v apt-get >/dev/null 2>&1; then
  ok "apt-based system detected"
else
  warn "apt-get not found — install python3 and pip manually, then re-run"
fi

# ------------------------------------------------------------------- packages
say "installing system packages"
if command -v apt-get >/dev/null 2>&1; then
  SUDO=""
  [[ "$(id -u)" -ne 0 ]] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
  # shellcheck disable=SC2086
  $SUDO apt-get update -qq || warn "apt-get update failed — continuing with the existing index"
  # shellcheck disable=SC2086
  $SUDO apt-get install -y -qq python3 python3-pip python3-venv \
    || die "could not install python3 — install it manually and re-run"
  ok "python3 and pip installed"
fi

PYTHON_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,9) else 0)')
[[ "$PYTHON_OK" == "1" ]] || die "Python 3.9+ required, found $(python3 --version)"
ok "$(python3 --version)"

# ------------------------------------------------------------------- install
say "installing Python dependencies"
if [[ -f requirements.txt ]]; then
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    if python3 -m pip install --quiet --break-system-packages "$line" 2>/dev/null \
       || python3 -m pip install --quiet "$line"; then
      ok "$line"
    else
      warn "could not install '$line' — the matching feature will report UNAVAILABLE"
    fi
  done < requirements.txt
fi

# ------------------------------------------------------------------- database
say "initialising the database"
python3 - <<'PY'
from kingdomx.core.config import Config
from kingdomx.core.storage import Database

config = Config.load()
db = Database(config.db_path)
db.audit("installer", "install.initialise", outcome="ok", detail="kali")
print(f"  ok database ready at {config.db_path}")
db.close()
PY

say "checking the install"
python3 - <<'PY'
from kingdomx.core.platform_detect import detect_platform
from kingdomx.core.registry import REGISTRY

plat = detect_platform()
counts = REGISTRY.counts()
print(f"  ok platform: {plat.label} ({plat.arch})")
print(f"  ok {sum(counts.values())} modules registered, {counts.get('WORKING', 0)} working")
PY

cat <<EOF

${BOLD}${GOLD}Installation complete.${RESET}

  Launch the terminal UI   : python3 kingdomx.py
  Module status report     : python3 kingdomx.py status
  Self test                : python3 kingdomx.py selftest
  Web dashboard            : python3 kingdomx.py web
  Run the test suite       : python3 -m pytest tests/ -q

  The dashboard listens on http://127.0.0.1:8000 and is bound to localhost only.

EOF
