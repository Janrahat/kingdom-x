#!/usr/bin/env bash
# KINGDOM X — Termux (Android) installer.
#
# Termux is not Kali: there is no apt python3-venv, most security tools are absent,
# and several PyPI wheels need a C toolchain. This script installs the Termux
# packages that actually exist and degrades honestly when a wheel is unavailable.
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
if [[ "${PREFIX:-}" != *com.termux* ]]; then
  warn "PREFIX does not look like Termux (${PREFIX:-unset})."
  warn "This may be a plain Linux box — ./install-kali.sh is usually the better script."
fi
[[ -n "${PREFIX:-}" ]] && ok "prefix: $PREFIX"

command -v pkg >/dev/null 2>&1 || die "the 'pkg' command is missing. This is not a Termux environment."

# ------------------------------------------------------------------- packages
say "installing Termux packages"
# python + pip exist; rust is needed only if a wheel has no prebuilt for your ABI.
PKGS="python"
for extra in clang make openssl libffi rust binutils; do
  if pkg show "$extra" >/dev/null 2>&1; then
    PKGS="$PKGS $extra"
  else
    warn "package '$extra' not available in this Termux repo — skipping"
  fi
done
# shellcheck disable=SC2086
pkg install -y $PKGS || die "pkg install failed"
ok "packages installed"

PYTHON_OK=$(python -c 'import sys; print(1 if sys.version_info >= (3,9) else 0)')
[[ "$PYTHON_OK" == "1" ]] || die "Python 3.9+ required, found $(python --version)"
ok "$(python --version)"

# ------------------------------------------------------------------- install
say "installing dependencies"
python -m pip install --upgrade pip setuptools wheel >/dev/null
if [[ -f requirements.txt ]]; then
  # One at a time so a single unavailable wheel does not abort the whole install.
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    if python -m pip install --quiet "$line"; then
      ok "$line"
    else
      warn "could not install '$line' — the matching feature will report UNAVAILABLE"
    fi
  done < requirements.txt
fi

# psutil is the one dependency that commonly needs compilation on Android.
if python -c 'import psutil' >/dev/null 2>&1; then
  ok "psutil available (full system metrics)"
else
  warn "psutil unavailable — /proc fallbacks will be used instead"
fi

if python -c 'import dns.resolver' >/dev/null 2>&1; then
  ok "dnspython available"
else
  warn "dnspython unavailable — A/AAAA still resolve via the OS resolver"
fi

# ------------------------------------------------------------------- database
say "initialising the database"
python - <<'PY'
from kingdomx.core.config import Config
from kingdomx.core.storage import Database

config = Config.load()
db = Database(config.db_path)
db.audit("installer", "install.initialise", outcome="ok", detail="termux")
print(f"  ok database ready at {config.db_path}")
db.close()
PY

say "checking the install"
python - <<'PY'
from kingdomx.core.platform_detect import detect_platform
from kingdomx.core.registry import REGISTRY

plat = detect_platform()
counts = REGISTRY.counts()
print(f"  ok platform: {plat.label} ({plat.arch})")
print(f"  ok {sum(counts.values())} modules registered, {counts.get('WORKING', 0)} working")
print("  note: most Kali security tools are not packaged for Termux; KINGDOM X")
print("        detects them by binary and reports them as absent rather than guessing.")
PY

cat <<EOF

${BOLD}${GOLD}Installation complete.${RESET}

  Launch the terminal UI   : python kingdomx.py
  Module status report     : python kingdomx.py status
  Self test                : python kingdomx.py selftest
  Web dashboard            : python kingdomx.py web
  Run the test suite       : python -m pytest tests/ -q

  The dashboard listens on http://127.0.0.1:8000. Termux runs it inside Android,
  so it is reachable from the device (and from a browser on the same device);
  it is NOT reachable from the internet without a tunnel or a real server.

  Termux-specific limits:
    - no root by default: /etc/shadow and iptables checks report UNAVAILABLE
    - no systemd: service checks read /proc instead
    - some security binaries do not exist in the Termux repo — reported, not assumed

EOF
