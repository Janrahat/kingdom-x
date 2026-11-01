# User guide

Every command and every menu entry, with what it actually does.

---

## Command line

```
python kingdomx.py [--plain] [--json] <command> [args]
```

`--plain` disables the crown banner and box drawing (useful in logs / narrow terminals).
`--json` emits machine-readable output where the command supports it.

### `status`

Prints every registered module grouped by section, with its state.

```bash
python kingdomx.py status
python kingdomx.py status --section cyber
```

### `selftest`

Verifies the install: imports every module, confirms each `WORKING` entry resolves to a real callable, then checks database integrity.

```
modules  working 39  network 11  key 1  authz 1  planned 25  total 77
✔ all 52 implemented modules resolve
✔ database integrity OK
```

### `doctor`

Platform, Python, dependency availability, database path, connectivity, and which security binaries were found.

### `audit`

Read-only Linux configuration audit. Checks SSH config, world-writable files, SUID binaries, firewall state, password policy, and more — each with severity and remediation.

```bash
python kingdomx.py audit --json > audit.json
```

### `tools`

Detects installed security tooling by binary, reports version and path, and flags what is missing.

```bash
python kingdomx.py tools
python kingdomx.py tools --search nmap
```

### `dns`

Real DNS queries. Uses `dnspython` for the full record set, or the OS resolver for A/AAAA/CNAME when `dnspython` is absent.

```bash
python kingdomx.py dns example.com --type MX
python kingdomx.py dns example.com --all
python kingdomx.py dns example.com --diagnose
```

### `ip`

Classification, ASN and geolocation for a public address.

```bash
python kingdomx.py ip 8.8.8.8
```

### `phone`

Numbering-plan analysis. Country, structural validity, line type where documented, and formatting.

```bash
python kingdomx.py phone +966501234567
python kingdomx.py phone 0501234567 --country 966
```

### `web`

Starts the dashboard.

```bash
python kingdomx.py web
python kingdomx.py web --port 8080 --host 127.0.0.1
```

### `report`

Builds a report bundle from what you ask for and writes it out.

```bash
python kingdomx.py report --format json --out reports/
python kingdomx.py report --format md
```

---

## The interactive menu

`python kingdomx.py` (or `python kingdomx.py menu`) opens the command center.

Each entry maps to a registry section. **If every module in a section is `PLANNED`, the menu says so instead of opening an empty screen.**

### 01 AI Intelligence Center

- Configure a provider (key or local endpoint)
- Run a health check — the only way a model becomes `AVAILABLE`
- Chat with the selected model
- Compare models on the same prompt
- Inspect token usage

### 02 Cybersecurity Center

- Password audit (local, nothing transmitted)
- File integrity: build a baseline, then compare
- Security headers for a URL
- TLS certificate inspection
- Dependency scan for a manifest
- Auth-log analysis
- Host audit

### 03–10 Intelligence

Device catalogue, phone numbering, system diagnostics, website audit, domain/RDAP, IP/ASN, DNS, network state.

### 11–13 Cloud / API / Forensics

Cloud and API entries are reference data plus health checks. Forensics is a `PLANNED` roadmap item — the menu says so.

### 17 Global Tool Directory

Curated tool catalogue with official links, licence, platform support and install hints.

### 21 Automation Center

Scheduled tasks (minimum interval 5 minutes) and an allow-listed action executor. There is no arbitrary command execution — actions map to Python functions.

### 22 Plugin Marketplace

Install, list, run and remove plugins. Manifests are validated before anything touches disk.

### 24 System Diagnostics

CPU, memory, disk, uptime, processes, services — from `psutil`, or `/proc` when it is absent.

### 25 Settings

Provider defaults, timeouts, retention policy, export paths.

---

## Reading the status column

| Marker | Meaning |
|---|---|
| `WORKING` | Runs now, no network, no key |
| `NEEDS_NETWORK` | Runs now if you are online |
| `NEEDS_KEY` | Runs once a provider key or local model is configured |
| `NEEDS_AUTHORIZATION` | Refuses until you record authorization for the target |
| `PLANNED` | **Not implemented** — roadmap only |

If something says `PLANNED`, it does nothing. That is deliberate: an entry that silently no-ops is worse than an entry that admits it is unbuilt.

---

## Keyboard

| Key | Action |
|---|---|
| `1`–`25` | Jump to a menu section |
| `00` | Exit |
| `b` | Back one level |
| `h` | Help for the current screen |
| `q` | Quit from any screen |
| `Ctrl-C` | Exit immediately |

---

## Common tasks

**Check whether a provider actually works**

```bash
python kingdomx.py status --section ai     # what is registered
python kingdomx.py                        # menu → 01 → health check
```

A provider whose key is set but whose endpoint is unreachable reports `UNREACHABLE`, not `AVAILABLE`.

**Audit this machine**

```bash
python kingdomx.py audit --json > audit.json
```

**Inspect a domain**

```bash
python kingdomx.py dns example.com --all
python kingdomx.py ip $(dig +short example.com | head -1)
```

**Export evidence**

```bash
python kingdomx.py report --format json --out reports/
```
