#!/usr/bin/env bash
# KINGDOM X — uninstall.
# Removes the virtual environment and, with --purge, the local database and state.
# Source code is NOT deleted unless you pass --all.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; cd "$ROOT"

GOLD=$'\033[38;5;178m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
say() { printf '%s[KINGDOM X]%s %s\n' "$GOLD" "$RESET" "$*"; }
ok()  { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }

PURGE=0; ALL=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --all)   ALL=1; PURGE=1 ;;
    -h|--help)
      cat <<'EOF'
Usage: ./uninstall.sh [--purge] [--all]

  (no flags)  remove .venv only
  --purge     also delete the local database, logs and the generated secret
  --all       also delete the source tree (irreversible)
EOF
      exit 0 ;;
  esac
done

if [[ -d .venv ]]; then say "removing .venv"; rm -rf .venv; ok ".venv removed"
else say ".venv not present — nothing to do"; fi

if [[ $PURGE -eq 1 ]]; then
  say "removing local state"
  for path in data kingdomx.db kingdomx.db-wal kingdomx.db-shm logs .ruk_secret; do
    [[ -e "$path" ]] && { rm -rf "$path"; ok "removed $path"; }
  done
  find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  ok "state cleared"
fi

if [[ $ALL -eq 1 ]]; then
  say "removing the source tree"
  PARENT="$(dirname "$ROOT")"
  cd "$PARENT"
  rm -rf "$ROOT"
  printf '  %s✓%s removed %s\n' "$GREEN" "$RESET" "$ROOT"
  exit 0
fi

printf '\n%sDone.%s Pass --purge to also clear the database, --all for the source tree.\n' "$GOLD" "$RESET"
