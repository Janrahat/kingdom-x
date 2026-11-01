# Installation

Three installers, one application. Each is idempotent — safe to re-run.

---

## Kali Linux (and Debian / Ubuntu / Parrot)

```bash
git clone https://github.com/Janrahat/kingdom-x.git
cd kingdom-x
chmod +x install-kali.sh
./install-kali.sh
source .venv/bin/activate
```

**What the script does**

1. Detects the distribution from `/etc/os-release`.
2. Requires Python ≥ 3.9.
3. Installs `python3-venv` and `python3-pip` via `apt` **only if missing** — and prompts you to run `sudo` yourself if you are not root.
4. Creates `.venv`, upgrades pip, installs `requirements.txt`.
5. Initialises the SQLite database.
6. Prints the module count so you know the install is real.

Kali already ships much of the security tooling KINGDOM X detects. After install:

```bash
python kingdomx.py tools      # what it found
python kingdomx.py doctor     # environment report
```

---

## Termux (Android)

```bash
pkg install -y git
git clone https://github.com/Janrahat/kingdom-x.git
cd kingdom-x
chmod +x install-termux.sh
./install-termux.sh
```

**What is different on Termux**

| Area | Reality |
|---|---|
| venv | Termux has no `python3-venv` package. The script installs into the Termux Python directly. |
| `psutil` | Usually has no prebuilt wheel. Installs one dependency at a time so one failure does not abort the rest; the app falls back to `/proc`. |
| Security tools | Most of `nmap`, `tshark`, `lynis`, `trivy` etc. are **not** in the Termux repo. They are reported as absent, not assumed present. |
| Root | No root by default. `/etc/shadow` and `iptables` checks report `UNAVAILABLE`. |
| systemd | Absent. Service checks read `/proc` instead. |
| Dashboard | Reachable from the device. **Not** reachable from the internet without a tunnel. |

Termux-specific bounds are also printed at the end of `install-termux.sh`.

---

## Other Linux (Fedora, Arch, openSUSE)

```bash
./install-linux.sh
```

Detects `dnf`, `pacman` or `zypper` when a package is needed, but installs nothing outside `.venv` otherwise.

---

## Manual install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python kingdomx.py selftest
```

If `venv` is unavailable on your distro, install the OS package first:

| Distro | Command |
|---|---|
| Debian/Ubuntu/Kali | `sudo apt install -y python3-venv python3-pip` |
| Fedora | `sudo dnf install -y python3 python3-pip` |
| Arch | `sudo pacman -S python python-pip` |
| openSUSE | `sudo zypper install -y python3 python3-pip` |
| Termux | `pkg install -y python` |

---

## Configuration

```bash
cp .env.example .env
chmod 600 .env
```

Then edit `.env`. Leave a provider key blank and that provider stays `UNKNOWN` — which is the honest state until a real health check succeeds.

**Never commit `.env`.** It is in `.gitignore`, and CI fails if it ever becomes tracked.

---

## Verification

```bash
python kingdomx.py selftest     # does the install resolve?
python kingdomx.py doctor       # what is this machine?
python -m pytest tests/ -q      # 332 tests
./diagnostics.sh                # everything above, plus secrets and connectivity
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No module named 'rich'` | venv not active | `source .venv/bin/activate` |
| `No module named 'venv'` | Debian splits venv out | `sudo apt install -y python3-venv` |
| `ensurepip is not available` | Same as above | Same as above |
| `✗ python3 too old` | < 3.9 | Install a newer Python |
| DNS `MX`/`TXT` report `UNAVAILABLE` | `dnspython` missing | `pip install dnspython` (A/AAAA still work) |
| `psutil` failed to build on Termux | No prebuilt wheel | `pkg install -y clang make rust` then retry, or ignore — `/proc` fallback works |
| Dashboard port busy | 8000 in use | `python kingdomx.py web --port 8080` |
| All network modules error | Offline / firewall | Expected; they say so rather than inventing data |
| `permission denied` on a script | Not executable | `chmod +x install-kali.sh` |
| Termux: `pkg: command not found` | Not Termux | Use `install-kali.sh` |

Still stuck? Run `./diagnostics.sh` — it checks every one of the above and prints what it measured.
