# Architecture

## Principles

1. **The registry is the source of truth.** A feature exists if `kingdomx/core/registry.py` says `WORKING` and a test proves it resolves. Everything the UI shows comes from the registry.
2. **Offline first.** Every module that needs the network degrades with an explicit message rather than hanging or inventing data.
3. **Redact at the boundary.** Secrets are filtered on the way *out* (logs, audit table, reports, HTTP) so a caller cannot leak by accident.
4. **No privilege escalation.** KINGDOM X never asks for root, never writes outside its own directory, never runs a shell.

---

## Layout

```
kingdom-x/
├── kingdomx/
│   ├── core/            config, storage, http (SSRF), redaction, registry,
│   │                    platform detection, validation, authorization, ui, branding
│   ├── ai/              catalog, client (4 wire shapes), health, manager, assistant
│   ├── cybersecurity/   severity, ports, tools, headers, tls, passwords,
│   │                    integrity, dependencies, logs, audit
│   ├── dns/  ip/  domains/  websites/  network/
│   ├── phone/  devices/  globaltech/  computers/
│   ├── reports/  plugins/  automation/
│   ├── cli/             main.py — argument parsing + interactive menu
│   └── web/             app.py (FastAPI) + templates/
├── tests/               conftest + 6 test modules, all offline
├── docs/                this directory
├── install-*.sh  update.sh  uninstall.sh  diagnostics.sh
└── kingdomx.py          launcher (works without `pip install`)
```

---

## Request flow (a lookup)

```
CLI / Web
   ↓
Registry lookup ──→ state == PLANNED?  ──→ say so, stop
   ↓ WORKING / NEEDS_*
Module function
   ↓
SafeHttpClient (SSRF guard, size cap, redirect cap, timeout)
   ↓
External service
   ↓
Finding / Report  ← every finding carries severity + evidence
   ↓
redact_text() ──→ ReportBundle ──→ JSON / CSV / Markdown
```

Active operations add one gate before the network call:

```
AuthorizationRecord present for target? ──no──→ refuse, log the refusal
                                        └─yes─→ proceed, log authorization
```

---

## The registry

```python
register(
    key="cyber.passwords",          # dotted, stable, used by the CLI and API
    title="Password strength audit",
    section="cyber",                # groups modules into the 25 menu entries
    status=Status.WORKING,
    summary="Entropy, character-class and crack-time estimate, computed locally.",
    module_path="kingdomx.cybersecurity.passwords",
    entry="audit_password",
    verified_by="tests/test_cyber.py::TestPasswords",
)
```

`Status.WORKING` and friends require `verified_by` — the registry refuses a `WORKING` claim with no test attached. This is enforced by `tests/test_registry.py`, so honesty is not a convention you have to remember.

---

## The AI layer

Four wire shapes are supported, chosen by `ProviderSpec.kind`:

| kind | Wire format | Example |
|---|---|---|
| `openai` | `{choices:[{message:{content}}]}` | OpenAI, DeepSeek, Mistral, Groq, Qwen |
| `openai_compatible` | same, custom `base_url` | OpenRouter, Hugging Face, local gateways |
| `anthropic` | `{content:[{type:text,text}]}` + `x-api-key` | Claude |
| `google` | `{contents:[{parts:[{text}]}]}` + `generateContent` | Gemini |
| `ollama` | OpenAI shim **and** native `{message:{content}}` | local Ollama |

`health.check_provider()` performs a real `GET /models` (or `/api/tags`); a provider with no successful check stays `UNKNOWN`. `parse_response()` accepts both the OpenAI shim shape and Ollama's native shape, so a local model that answers correctly is not reported as broken.

---

## Storage

SQLite, one file, WAL disabled for portability. Migrations are numbered and applied in order; `Database.schema_version()` reports what is applied.

Tables: `schema_migrations`, `settings`, `audit_log`, `providers`, `models`, `ai_usage`, `scan_jobs`, `findings`, `tool_inventory`, `plugin_state`, `scheduled_jobs`, `reports`.

All access is parameterised. `executescript()` exists separately from `execute()` because sqlite3 only runs multi-statement DDL through the former.

---

## Adding a module

1. Create the module under the right package with a plain function.
2. Return `Report`/`Finding` objects (security) or a `dict` (intelligence).
3. Register it in `core/registry.py` with a truthful `Status`.
4. Add tests to the matching `tests/test_*.py`.
5. Run `python -m pytest tests/ -q` — `test_registry.py` will fail if the status claim is unsupported.

That last step is the point: you cannot claim a module works without a test that proves it.
