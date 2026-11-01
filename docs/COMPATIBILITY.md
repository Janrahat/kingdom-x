# Compatibility report

**What was tested, on what, and what remains unverified.**

Last hardware verification: Debian 12 container, x86_64, Python 3.11.

---

## Verified

| Platform | Python | Result | Notes |
|---|---|---|---|
| Debian 12 (container, x86_64) | 3.11 | **Full suite passes (332 tests)** | Reference environment for everything below |
| Debian 12 | 3.11 | CLI boots, `selftest` OK, dashboard serves | |
| Debian 12 | 3.11 | `--host 127.0.0.1` dashboard, all routes 200 | |

## Verified by construction (not on hardware)

| Platform | Status | Reasoning |
|---|---|---|
| Kali Linux | **Expected to work** | Kali is Debian-based; `install-kali.sh` uses the same `apt`/`venv` path that passed on Debian 12. Difference is Kali's larger preinstalled tool set, which only means more tools detected. |
| Ubuntu 22.04 / 24.04 | Expected to work | Same Debian family, same package names. |
| Parrot OS | Expected to work | Debian-based. |
| Fedora / Arch / openSUSE | **Untested** | `install-linux.sh` branches on the detected package manager; that branch has not been executed. |
| macOS | Untested, partial | Pure-Python modules should work; `cybersecurity/audit.py` reads Linux-specific paths and will report most checks `UNAVAILABLE`. |
| Windows | **Not supported** | `/proc`, POSIX permissions and the audit path assume a Unix host. WSL2 under Ubuntu is the supported route. |

## Termux — honest limits

**Not executed on a real Android device.** The installer handles the known differences (no `python3-venv`, no most-security-tools, no root, no systemd), but this claim is untested on hardware.

| Feature | Termux | Why |
|---|---|---|
| Terminal UI | Works | Pure Python + Rich |
| AI providers | Works | HTTPS via requests |
| Password audit | Works | Local computation |
| File integrity | Works | Files the app can read |
| DNS A/AAAA | Works | OS resolver |
| DNS MX/TXT/NS | Works if `dnspython` installs | Pure Python wheel, usually fine |
| Host audit | **Partial** | No root: `/etc/shadow` and `iptables` unreadable |
| Security tool detection | **Mostly absent** | The Termux repo has almost none of nmap/lynis/trivy |
| Port scan | Loopback/lab only | Needs an authorization record for anything else |
| Web dashboard | Device-local | Not reachable from the internet without a tunnel |
| `psutil` metrics | May need `clang`/`rust` | Falls back to `/proc` when absent |

## Dependency behaviour when missing

| Package | If absent |
|---|---|
| `rich` | **Required** — the CLI cannot start; the launcher prints a clear install message |
| `psutil` | Falls back to `/proc`; memory/CPU detail reduced |
| `dnspython` | A/AAAA/CNAME via OS resolver; MX/TXT/NS/SOA report `UNAVAILABLE` |
| `fastapi` / `uvicorn` | `python kingdomx.py web` explains what to install; terminal UI unaffected |
| `pytest` | Tests cannot run; the app is unaffected |

No dependency is silently faked. Each absence is reported where it matters.

## Network-backed modules

These require outbound connectivity and are **not exercised by the test suite** (which runs fully offline):

| Module | Service | Behaviour offline |
|---|---|---|
| `ip.lookup` | ip-api | Reports the network error |
| `ip.rdap` | Regional RDAP | Reports the network error |
| `domain.rdap` | IANA bootstrap → registry | Reports the network error |
| `dns.*` | Resolver | Reports the network error |
| `web.headers` / `web.tls` / `web.fingerprint` | Target host | Reports the network error |
| `ai.health` | Provider `/models` | Provider stays `UNKNOWN` |
| `dns.axfr` | Nameserver | Reports the refusal (which is the expected answer) |

The parser and formatting half of every one of these **is** unit-tested; only the transport is not, because the suite must not depend on a third party being reachable.

## Known limitations

1. **No real TLS test against a live certificate** — `cybersecurity/tls.py` parses certificates via `ssl.getpeercert()`; the parsing logic is unit-tested, the transport is not.
2. **No real `.mmdb` GeoIP database** — geolocation goes through the ip-api HTTP endpoint, not a local MaxMind file.
3. **Browser rendering of the dashboard was not visually verified** — routes return 200 and the HTML contains the expected content, but no headless-browser screenshot check was run.
4. **`dependency_scan` uses a bundled advisory subset**, not a live OSV/NVD feed. It catches known-common CVEs; it is not a substitute for `trivy`/`grype`.
5. **Plugin sandbox is path-validated, not process-isolated.** A malicious plugin runs in-process. Only install plugins you trust — the manifest check stops traversal, not malice.
6. **No Windows support.**

## Reporting a compatibility problem

Include:

```bash
uname -srm
python3 --version
python kingdomx.py doctor
python kingdomx.py selftest
./diagnostics.sh
```

Those four outputs identify almost every environment problem.
