#!/usr/bin/env bash
# KINGDOM X — generic Linux installer (Debian/Ubuntu/Kali, Fedora, Arch, openSUSE).
# Uses the system package manager only to satisfy python3-venv; everything else
# goes into a local .venv.
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
printf '  ▄▄ KINGDOM X ▄▄  THE KING OF GLOBAL TECHNOLOGY%s\n\n' "$RESET"

command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.9+ first."
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,9) else 1)' \
  || die "Python 3.9+ required, found $(python3 --version)"
ok "$(python3 --version)"

# Try to make venv available without assuming root.
if ! python3 -c 'import venv' >/dev/null 2>&1; then
  warn "the venv module is missing. Attempting to install it:"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y python3-venv 2>/dev/null || warn "run: sudo apt-get install -y python3-venv"
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3 2>/dev/null || warn "run: sudo dnf install -y python3"
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm python 2>/dev/null || warn "run: sudo pacman -S python"
  elif command -v zypper >/dev/null 2>&1; then
    sudo zypper install -y python3 2>/dev/null || warn "run: sudo zypper install -y python3"
  fi
fi

say "creating the virtual environment"
[[ -d .venv ]] || python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip wheel

say "installing dependencies"
if [[ -f requirements.txt ]]; then
  python -m pip install --quiet -r requirements.txt || die "dependency install failed"
  ok "dependencies installed"
fi

say "initialising the database"
python - <<'PY'
from kingdomx.core.config import Config
from kingdomx.core.storage import Database

config = Config.load()
db = Database(config.db_path)
db.audit("installer", "install.initialise", outcome="ok", detail="linux")
print(f"  ok database ready at {config.db_path}")
db.close()
PY

python -m pytest tests/ -q >/dev/null 2>&1 && ok "test suite passes" || warn "test suite reported failures — run: python -m pytest tests/ -q"

cat <<EOF

${BOLD}${GOLD}Installation complete.${RESET}

  source .venv/bin/activate
  python kingdomx.py            # terminal UI
  python kingdomx.py status     # module status
  python kingdomx.py web        # dashboard on http://127.0.0.1:8000

EOF
