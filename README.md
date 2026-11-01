# KINGDOM X

**THE KING OF GLOBAL TECHNOLOGY**
*ONE PLATFORM. ALL TECHNOLOGIES. UNLIMITED INTELLIGENCE.*

[![CI](https://github.com/Janrahat/kingdom-x/actions/workflows/ci.yml/badge.svg)](https://github.com/Janrahat/kingdom-x/actions/workflows/ci.yml)

A modular technology and cybersecurity intelligence platform for **Kali Linux**, **Termux (Android)** and generic Linux. Premium terminal command center, read-only web dashboard, real AI provider integrations, and defensive-first security modules.

---

## What this actually is

KINGDOM X is a **working tool**, and it is honest about what it can and cannot do.

Every module declares its own state in the registry, and the interface shows that state:

| State | Meaning |
|---|---|
| `WORKING` | Implemented, runs with no external input, covered by tests |
| `NEEDS_NETWORK` | Implemented; requires outbound connectivity to a real service |
| `NEEDS_KEY` | Implemented; requires an API key or a running local model |
| `NEEDS_AUTHORIZATION` | Implemented; refuses to run until you record authorization |
| `PLANNED` | **Not built.** A roadmap note, not a feature |

You can see the current split at any time:

```bash
python kingdomx.py selftest
# modules  working 39  network 11  key 1  authz 1  planned 25  total 77
```

**39 modules work with no credentials and no network. 25 are explicitly `PLANNED` and do nothing yet.** Nothing in this project is a mockup dressed up as a feature.

### What KINGDOM X is not

It cannot reveal anyone's passwords, private messages, photos, contacts, exact GPS location, files, IMEI, or full phone identity. A web link — or a CLI — cannot do that. `kingdomx/phone/numbering.py` reports numbering-plan facts only, and the consent model is documented in `docs/SECURITY.md`.

---

## Install

### Kali Linux / Debian / Ubuntu

```bash
git clone https://github.com/Janrahat/kingdom-x.git
cd kingdom-x
chmod +x install-kali.sh
./install-kali.sh
source .venv/bin/activate
python kingdomx.py
```

### Termux (Android)

```bash
pkg install -y git
git clone https://github.com/Janrahat/kingdom-x.git
cd kingdom-x
chmod +x install-termux.sh
./install-termux.sh
python kingdomx.py
```

### Any other Linux

```bash
./install-linux.sh
```

### Manual

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python kingdomx.py selftest
```

---

## Run

| Command | What it does |
|---|---|
| `python kingdomx.py` | Interactive terminal UI (25-item menu) |
| `python kingdomx.py status` | Module status table |
| `python kingdomx.py selftest` | Verify the install |
| `python kingdomx.py doctor` | Environment diagnostics |
| `python kingdomx.py audit` | Local host configuration audit |
| `python kingdomx.py tools` | Installed security tooling |
| `python kingdomx.py dns <domain>` | Real DNS lookup |
| `python kingdomx.py ip <address>` | IP classification |
| `python kingdomx.py phone <number>` | Numbering-plan analysis |
| `python kingdomx.py web` | Dashboard on `http://127.0.0.1:8000` |
| `python kingdomx.py report` | Export a report bundle |

Stop the web dashboard with `Ctrl-C`. Nothing runs as a background daemon.

---

## The 25-item menu

```
[01] AI INTELLIGENCE CENTER          [14] MALWARE ANALYSIS
[02] CYBERSECURITY CENTER            [15] VULNERABILITY INTELLIGENCE
[03] GLOBAL DEVICE INTELLIGENCE      [16] OSINT CENTER
[04] MOBILE INTELLIGENCE             [17] GLOBAL TOOL DIRECTORY
[05] PHONE NUMBER INTELLIGENCE       [18] AI MODEL MANAGER
[06] COMPUTER INTELLIGENCE           [19] PROGRAMMING CENTER
[07] WEBSITE INTELLIGENCE            [20] DATABASE CENTER
[08] DOMAIN INTELLIGENCE             [21] AUTOMATION CENTER
[09] IP & NETWORK INTELLIGENCE       [22] PLUGIN MARKETPLACE
[10] DNS INTELLIGENCE                [23] REPORTS & ANALYTICS
[11] CLOUD & SERVER CENTER           [24] SYSTEM DIAGNOSTICS
[12] API INTELLIGENCE CENTER         [25] SETTINGS & CONFIGURATION
[13] DIGITAL FORENSICS               [00] EXIT
```

Each entry opens only what exists. Entries backed by `PLANNED` modules say so on screen instead of pretending.

---

## Working modules

**Core** — config, redaction, platform detection (Kali/Termux/WSL detection), SQLite storage with migrations, SSRF-guarded HTTP client, audit log.

**AI** — 10 providers (OpenAI, Anthropic, Gemini, DeepSeek, Mistral, Groq, OpenRouter, Qwen, Hugging Face, Ollama) plus custom OpenAI-compatible endpoints. Real request builders, real response parsers for all four wire shapes, live health checks, token accounting. **A model is never shown as available until its provider has actually answered.**

**Cybersecurity** — installed-tool detection, password strength audit (entropy + crack-time estimates, entirely local), file integrity monitoring, security-header audit, TLS certificate inspection, dependency vulnerability scanning, auth-log analysis, Linux configuration audit. All findings carry severity, evidence and remediation.

**Intelligence** — DNS (real queries, two backends), IP classification and ASN, domain RDAP + homograph detection (skeleton/keyboard-mapping analysis), website fingerprinting (54 signatures), phone numbering plans (19 countries with structure, 110 calling codes), public device catalogue, local system diagnostics, local network state, authorization-gated port scanning.

**Platform** — plugin registry with manifest validation and sandboxed execution, report export (JSON/CSV/Markdown/text), scheduled tasks, allow-listed action executor, read-only web dashboard, CI.

---

## Safety model

- Active scans are **refused** until `AuthorizationRecord` is populated for the target.
- Passwords are never transmitted; the auditor works entirely in memory.
- Secrets are redacted at every boundary — logs, audit table, reports, API responses.
- `.env` and `.ruk_secret` are gitignored and the CI fails if either is ever committed.
- The dashboard is read-only: no route mutates state.
- No `shell=True`, no `os.system()` in the executor path.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Per-platform install, dependencies, troubleshooting |
| [docs/USER-GUIDE.md](docs/USER-GUIDE.md) | Every menu, every command |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module layout, data flow, extension points |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, authorization gate, data handling |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Local vs public, HTTPS, reverse proxy |
| [docs/ROADMAP.md](docs/ROADMAP.md) | What is planned and what it will need |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | Tested platforms and known limits |
| [docs/DEVELOPER.md](docs/DEVELOPER.md) | Adding a module, tests, release process |

---

## Tests

```bash
python -m pytest tests/ -q
# 332 passed
```

The suite runs **fully offline** — no network, no API keys, no fixtures downloaded. Coverage spans core primitives, storage, the registry's honesty rules, AI request/response shapes, cybersecurity logic, intelligence parsers, plugins, automation, reports, the web API and the CLI.

---

## Legal

KINGDOM X is for systems you own or have **written permission** to test. The active-scan path requires you to record authorization before it will run, and it records that authorization in the audit log. Using it against systems you do not control may be illegal in your jurisdiction.

Collecting personal data may also be regulated (GDPR, CCPA and equivalents). KINGDOM X performs passive lookups of public registry data only, and never bypasses authentication, consent or platform sandboxing.

---

## Licence

MIT — see [LICENSE](LICENSE).
