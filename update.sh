#!/usr/bin/env bash
# KINGDOM X — update the checkout and re-sync dependencies.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; cd "$ROOT"

GOLD=$'\033[38;5;178m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
say() { printf '%s[KINGDOM X]%s %s\n' "$GOLD" "$RESET" "$*"; }
ok()  { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn(){ printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*"; }

if [[ -d .git ]] && git rev-parse --git-dir >/dev/null 2>&1; then
  say "pulling the latest commits"
  BRANCH="$(git rev-parse --abbrev-ref HEAD)"
  if git pull --ff-only origin "$BRANCH"; then ok "updated ($BRANCH)"; else warn "pull skipped (local changes or no remote)"; fi
else
  warn "not a git checkout — skipping the pull"
fi

if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
  say "refreshing dependencies"
  python -m pip install --quiet --upgrade pip wheel
  [[ -f requirements.txt ]] && python -m pip install --quiet -U -r requirements.txt && ok "dependencies refreshed"
else
  warn "no .venv found — run an installer first"
fi

say "applying migrations"
python - <<'PY'
from kingdomx.core.config import Config
from kingdomx.core.storage import Database
config = Config.load()
db = Database(config.db_path)
print(f"  ok schema at version {db.schema_version()}")
db.close()
PY

say "running the test suite"
if python -m pytest tests/ -q; then ok "tests pass"; else warn "tests reported failures (see output above)"; fi
