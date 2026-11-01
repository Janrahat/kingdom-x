#!/usr/bin/env bash
# KINGDOM X — diagnostics.
#
# Prints what is actually installed and working on THIS machine. Every line is a
# measurement, not an assumption. Run this first when a feature looks broken.
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; cd "$ROOT"

GOLD=$'\033[38;5;178m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
RED=$'\033[31m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
hdr()  { printf '\n%s%s── %s ──%s\n' "$BOLD" "$GOLD" "$1" "$RESET"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$RESET" "$*"; }

printf '%s\n' "$BOLD$GOLD"
printf '  ▄▄ KINGDOM X ▄▄  DIAGNOSTICS\n%s' "$RESET"

hdr "host"
printf '  uname   : %s\n' "$(uname -srm)"
printf '  distro  : %s\n' "$( ( . /etc/os-release 2>/dev/null && printf '%s %s' "$NAME" "$VERSION_ID" ) || echo unknown )"
printf '  python  : %s\n' "$(python3 --version 2>&1)"

hdr "environment"
if [[ "${PREFIX:-}" == *com.termux* ]]; then ok "Termux detected (${PREFIX})"
elif [[ -d .venv ]]; then ok "virtual environment present (.venv)"
else warn "no .venv — dependencies install into the system interpreter"
fi

hdr "interpreter + packages"
if python3 -c 'import kingdomx' >/dev/null 2>&1; then ok "kingdomx importable"
else bad "kingdomx not importable from $(pwd)"; fi

for pkg in rich psutil dns.resolver fastapi uvicorn pytest; do
  if python3 -c "import $pkg" >/dev/null 2>&1; then ok "$pkg"
  else warn "$pkg missing — the matching feature reports UNAVAILABLE"; fi
done

hdr "database"
python3 - <<'PY' 2>/dev/null || bad "database check failed"
from kingdomx.core.config import Config
from kingdomx.core.storage import Database, verify_database
try:
    config = Config.load()
    health = verify_database(config.db_path)
    if health.get("ok"):
        print(f"  ✓ {config.db_path} (schema v{health.get('schema_version', '?')})")
    else:
        print(f"  ✗ {health.get('reason')}")
except Exception as exc:  # noqa: BLE001
    print(f"  ✗ {exc}")
PY

hdr "modules"
python3 - <<'PY' 2>/dev/null || bad "registry check failed"
from kingdomx.core.registry import REGISTRY
counts = REGISTRY.counts()
for state in ("WORKING", "NEEDS_NETWORK", "NEEDS_KEY", "PLANNED"):
    if counts.get(state):
        print(f"  {state:<14} {counts[state]}")
print(f"  {'TOTAL':<14} {sum(counts.values())}")
PY

hdr "security tooling"
python3 - <<'PY' 2>/dev/null || warn "tool detection failed"
from kingdomx.cybersecurity.tools import detect_all
present = [t for t in detect_all() if t.present]
print(f"  {len(present)} detected:")
print("  " + ", ".join(sorted(t.spec.name for t in present)) if present else "  none")
PY

hdr "network (optional, may fail offline)"
if python3 - <<'PY' >/dev/null 2>&1
import socket
socket.setdefaulttimeout(3)
socket.create_connection(("1.1.1.1", 443)).close()
PY
then ok "outbound TCP to 1.1.1.1:443 works"
else warn "no outbound connectivity — every network module will report an error"
fi

hdr "secrets"
for f in .env .ruk_secret; do
  if [[ -e "$f" ]]; then
    PERMS="$(stat -c '%a' "$f" 2>/dev/null || echo '?')"
    if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then ok "$f present, mode $PERMS"
    else bad "$f present with mode $PERMS — run: chmod 600 $f"; fi
  fi
done
if [[ -d .git ]]; then
  if git ls-files --error-unmatch .env >/dev/null 2>&1; then bad ".env is TRACKED BY GIT — remove it"
  else ok ".env is not tracked"; fi
fi

hdr "test suite"
if [[ -d tests ]]; then
  if python3 -m pytest tests/ -q >/tmp/kingdomx-tests.log 2>&1; then
    ok "$(tail -1 /tmp/kingdomx-tests.log)"
  else
    bad "tests failed — see /tmp/kingdomx-tests.log"
    tail -5 /tmp/kingdomx-tests.log
  fi
else
  warn "no tests/ directory"
fi

printf '\n%sDone.%s\n' "$BOLD" "$RESET"
