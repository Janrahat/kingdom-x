# Roadmap

The 25 `PLANNED` registry entries are roadmap items, not features. This document says what each would need — so you can judge the effort before relying on it.

---

## What is built

| Area | Modules | State |
|---|---|---|
| Core | 11 | WORKING |
| AI | 5 | WORKING / NEEDS_KEY |
| Cybersecurity | 10 | WORKING |
| Intelligence (DNS/IP/domain/web/phone/device) | 15 | WORKING / NEEDS_NETWORK |
| Platform (reports/plugins/automation/web) | 8 | WORKING |
| Network active scanning | 1 | NEEDS_AUTHORIZATION |

---

## Planned — with prerequisites

### Cloud Security
**Needs:** cloud provider SDKs (boto3 / azure-identity / google-cloud), scoped read-only credentials, an IAM policy template.
**Scope:** CIS benchmark checks against your own account — public buckets, root account MFA, unused access keys, security-group ingress.
**Blocker:** cannot be done without real credentials, and must never run against an account you do not own.

### Container Security
**Needs:** Docker/Podman socket access (or `trivy`/`grype` installed).
**Scope:** image scan aggregation, privileged-container detection, rootless verification.
**Note:** `cybersecurity/dependencies.py` already parses manifests; wiring a scanner is the missing piece.

### API Security
**Needs:** an OpenAPI/Postman spec parser.
**Scope:** auth-scheme detection, rate-limit header inspection, secret-in-URL detection, schema diffing between versions.
**Partial overlap:** `cybersecurity/headers.py` covers the transport half already.

### Threat Intelligence
**Needs:** at least one feed (AbuseIPDB, AlienVault OTX, or a local MISP instance) and an API key.
**Scope:** IP/domain reputation lookup with attribution to the feed and its timestamp.

### Digital Forensics
**Needs:** nothing external for basic triage.
**Scope:** file-carving hints, timestamp timeline from `stat`, memory of modified files, evidence manifest with hashes.
**Why planned:** the honest version is a large surface; shipping a half-built evidence tool would be worse than shipping none.

### Malware Analysis
**Needs:** YARA (binary), an isolated environment.
**Scope:** static-only — hashes, strings, PE/ELF header parse, YARA match. **Never execution.**
**Blocker:** dynamic analysis must not be in this tool, full stop.

### Incident Response
**Needs:** a case/evidence schema (partially present in `scan_jobs`).
**Scope:** case creation, evidence attachment, timeline, export.

### Compliance
**Needs:** a control-mapping dataset (CIS Controls, ISO 27001 Annex A).
**Scope:** map the existing `cybersecurity/audit.py` checks onto control IDs so an audit produces a compliance view.

### Knowledge Center
**Needs:** none — it is a content problem, not a code problem.
**Scope:** searchable explainers for the concepts the modules reference.

### Monitoring
**Needs:** a daemon story. KINGDOM X has no background process by design.
**Scope:** host metric collection, threshold alerts, a local ring buffer.

### Supply Chain
**Needs:** SBOM generation (CycloneDX) and signature verification (`cosign`/`sigstore`).
**Scope:** SBOM export, provenance check for downloaded artifacts.

### Phishing Awareness
**Needs:** URL heuristics (partly present) and a training-content library.
**Scope:** suspicious-URL explanation using the existing homograph + fingerprint logic, plus a teaching corpus.

### Android / Mobile-specific
**Needs:** Termux:API for device info; nothing for the rest.
**Scope:** Android version, security patch level, app permission inspection for APK files the user selects.
**Blocker:** a web page or CLI cannot read another app's data — that is the Android sandbox, not a gap here.

### Server Security / Database Security
**Needs:** SSH access model (or local-only operation).
**Scope:** local is feasible (config files, listeners, DB auth policy); remote requires credentials and a threat-model discussion.

### Programming Center
**Needs:** optional tool availability (`ruff`, `mypy`, `gofmt`, `clippy`).
**Scope:** run whatever is installed, report what is not — same pattern as `cybersecurity/tools.py`.

### OSINT Center
**Needs:** per-source API keys; each source has its own terms of service.
**Scope:** only public-registry sources already integrated (RDAP, DNS, certificate transparency). Anything beyond that is a legal question before it is a code question.

---

## Not on the roadmap

These are out of scope permanently, not "planned":

- subscriber identity lookup for phone numbers
- exact GPS location of a visitor
- reading another person's messages, contacts, files or credentials
- credential harvesting, phishing pages, or malware deployment
- stealth tracking or fingerprinting without disclosure
- bypassing any authentication or platform sandbox

---

## How to contribute a planned module

1. Write the module so it degrades honestly when its dependency is missing.
2. Register it with the real status — `NEEDS_KEY`, `NEEDS_NETWORK`, or `WORKING`.
3. Add tests to `tests/`.
4. `test_registry.py` will reject a `WORKING` claim with no test.
5. Update this file: move the entry from "Planned" to "Built" with its verified state.

That last step is what keeps this document from drifting into marketing.
