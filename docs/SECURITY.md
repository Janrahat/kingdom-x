# Security model

## Scope

KINGDOM X performs **passive analysis of public data** and **local, read-only inspection** of the machine it runs on. It has one active capability — TCP port checking — and that one is gated.

It does **not** and **will not**:

- bypass authentication, consent, DRM or platform sandboxing
- read another person's messages, photos, contacts, files or credentials
- intercept traffic, TLS-strip, or downgrade a connection
- deploy, install or build malware
- collect data covertly, or fingerprint a visitor without disclosure

## What a web link or a CLI cannot determine

This is stated plainly because products in this space routinely imply otherwise:

| Claim | Reality |
|---|---|
| "Find a phone's owner" | A numbering plan gives you **country, and maybe line type**. No name. |
| "Locate the device by IP" | IP geolocation resolves to a **city or region** at best, often just the ISP. |
| "Get the visitor's exact GPS" | Requires an explicit browser permission prompt. Passive analytics cannot. |
| "Reveal IMEI / SIM / contacts" | Requires OS-level privileges that no website has. |

`kingdomx/phone/numbering.py` returns `cannot_determine` in its own output so the boundary travels with the data.

## Authorization gate

`kingdomx/core/authorization.py` requires an `AuthorizationRecord` before any active operation:

```python
AuthorizationRecord(
    target="10.0.0.5",
    scope="single host, services 1-1024",
    authorized_by="Jane Doe (CISO)",
    reference="TICKET-4412",
    granted_at=...,
    expires_at=...,
)
```

Missing, expired, or out-of-scope records are refused **and the refusal is audited**. The record's reference lands in the audit log, so there is a trail of who authorized what.

Lab targets (`127.0.0.1`, `::1`) are permitted without a record — that is the safe-by-default path for learning.

## Secret handling

| Where | Control |
|---|---|
| Logs | `RedactingFilter` strips key-shaped strings before any handler |
| Audit table | `Database.audit()` redacts `detail` and `target` on write |
| Reports | `ReportBundle.to_dict()` re-serialises through `redact_text()` |
| Web API | status payload uses registry metadata only — never a key |
| Health checks | the key goes in a header; errors are truncated and redacted |

Patterns covered: `sk-…`, `sk-ant-…`, `AIza…`, `ghp_…`, `gho_…`, `hf_…`, `Bearer …`, AWS access keys, PEM private-key blocks, and `password=`/`token=` query parameters.

`.env` and `.ruk_secret` are gitignored. CI fails the build if either becomes tracked.

## Network safety

`SafeHttpClient` blocks SSRF before connecting:

- resolves the hostname first, then checks **every** resolved address
- refuses loopback, private, link-local, multicast, reserved and CGNAT ranges
- refuses `.local`, `.internal`, `.localhost`, and bare `localhost`
- caps redirects (5) and re-validates each hop
- caps response size (2 MB) and time (10 s default)
- opt-in `allow_hosts` for a deliberate private target (e.g. Ollama on `127.0.0.1`)

## Web dashboard

- **Read-only.** There is no POST/PUT/DELETE route. `tests/test_platform.py` asserts this.
- Binds to `127.0.0.1` by default. Bind elsewhere only behind a TLS reverse proxy.
- Renders registry metadata only — no findings detail, no keys.
- No session, no cookie, no login — because there is nothing to protect beyond public module metadata. If you extend it with authenticated features, add real session handling first (see `docs/DEPLOYMENT.md`).

## Plugin sandbox

A plugin must ship `plugin.json`. The loader validates:

- `name` matches `^[A-Za-z0-9._-]{1,48}$` — no path separators, no traversal
- `entry` is a **plain filename** inside the plugin directory
- declared permissions are from a known set (`network`, `filesystem_read`, …)
- imports happen from the plugin directory only

Plugins get a `context` dict and nothing else: no database handle unless granted, no ambient credentials.

## Data retention

`Database.purge_older_than(days=…)` refuses anything under one day, so a mistyped `0` cannot wipe the audit trail. `vacuum()` reclaims space afterwards. Backups use SQLite's own backup API rather than a file copy, so a live database produces a consistent snapshot.

## Threat model summary

| Threat | Mitigation |
|---|---|
| SSRF to cloud metadata (`169.254.169.254`) | address-range guard, pre-connect DNS re-validation |
| SQL injection | parameterised queries everywhere; `execute()` refuses multi-statement input |
| Secret leakage via logs/reports | redaction at every egress boundary |
| Path traversal in plugins | strict name + entry validation |
| Command injection | no `shell=True`, no `os.system`, allow-listed actions only |
| Unauthorized scanning | authorization record required, audited on refusal and on use |
| XSS in dashboard | registry metadata is escaped by the template layer; no user-supplied HTML |
| Accidental git commit of keys | `.gitignore` + CI gate |

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue.
