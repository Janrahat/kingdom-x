# Developer guide

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ -q
```

---

## Adding a module

### 1. Write the function

Put it in the right package. Prefer plain functions with explicit parameters over classes with hidden state.

**Security module** — return a `Report` of `Finding` objects:

```python
from kingdomx.cybersecurity.severity import Finding, Report, Severity

def check_something(target: str) -> Report:
    report = Report(module="cyber.something", target=target)
    report.add(Finding(
        title="PermitRootLogin is enabled",
        severity=Severity.HIGH,
        category="host",
        detail="sshd_config line 34 sets PermitRootLogin yes",
        remediation="Set PermitRootLogin no and reload sshd",
    ))
    return report
```

`Finding` fields that matter: `title`, `severity`, `category`, `detail` (what was observed), `remediation` (what to do), `passed` (True for checks that succeeded — they appear as evidence, not as issues).

**Intelligence module** — return a dict with a `_meta` block:

```python
return {
    "query": value,
    "records": [...],
    "_meta": {"source": "...", "as_of": "...", "confidence": "high",
              "limitations": "..."},
}
```

Provenance is not optional. If you cannot name the source, you cannot ship the dataset.

### 2. Register it

```python
# kingdomx/core/registry.py
register(
    key="cyber.something",
    title="Something check",
    section="cyber",
    status=Status.WORKING,
    summary="One sentence: what it actually does.",
    module_path="kingdomx.cybersecurity.something",
    entry="check_something",
    verified_by="tests/test_cyber.py::TestSomething",
)
```

**The registry enforces honesty.** `Status.WORKING` without `verified_by` fails `test_registry.py`. So does a `verified_by` pointing at a path that does not exist. Use `NEEDS_NETWORK`, `NEEDS_KEY` or `NEEDS_AUTHORIZATION` when that is the truth, and `PLANNED` when it is not built.

### 3. Test it

Add to the matching `tests/test_*.py`. Tests must pass **offline**:

```python
class TestSomething:
    def test_detects_the_problem(self, tmp_path):
        config = tmp_path / "sshd_config"
        config.write_text("PermitRootLogin yes\n", encoding="utf-8")
        report = check_something(str(config))
        assert any("root" in f.title.lower() for f in report.findings)
```

Never `skip` a test to make the suite green. If something genuinely cannot be tested offline, say so in `docs/COMPATIBILITY.md` instead.

---

## Testing conventions

| Rule | Why |
|---|---|
| No network in tests | CI must not depend on a third party |
| No real API keys | An accidental commit is the failure mode |
| Use `tmp_path` for files | No state leaks between tests |
| Use the `db` fixture (in-memory SQLite) | Fast, isolated |
| Assert behaviour, not implementation | A refactor should not break tests |

Run:

```bash
python -m pytest tests/ -q                    # everything
python -m pytest tests/test_cyber.py -q       # one file
python -m pytest tests/ -q -k passwords       # one area
python -m pytest tests/ -q --tb=short
```

---

## Style

- Line length 100, enforced by ruff config in `pyproject.toml`
- Type hints on public functions
- No `shell=True`, no `os.system`, no `eval`
- Docstrings explain **why**, not what — the code says what
- Comments justify non-obvious choices; they do not narrate

---

## Security checklist before a PR

- [ ] No secret, key, token or `.env` in the diff
- [ ] New outbound requests go through `SafeHttpClient` (not raw `requests`)
- [ ] New user input is validated in `core/validation.py` or locally
- [ ] New SQL is parameterised
- [ ] New file paths are resolved and checked against an allowed root
- [ ] Errors do not echo credentials (run `redact_text` on anything user-visible)
- [ ] New active capability is behind `authorization.require()`
- [ ] `python -m pytest tests/ -q` is green

---

## Release

```bash
# 1. bump the version in kingdomx/__init__.py and pyproject.toml
# 2. regenerate the status table for the README
python kingdomx.py selftest

# 3. full verification
python -m pytest tests/ -q
for s in install-kali.sh install-termux.sh install-linux.sh update.sh uninstall.sh diagnostics.sh; do bash -n "$s"; done
python -m kingdomx selftest

# 4. tag and push
git tag -a v1.0.0 -m "KINGDOM X v1.0.0"
git push origin main --tags
```

The CI workflow runs the suite on Python 3.9, 3.11 and 3.12, imports every module, boots the CLI, and fails if `.env` or a key-shaped literal is ever committed.

---

## Project conventions

| Convention | Reason |
|---|---|
| Registry is authoritative | The UI cannot claim what the registry does not |
| `_meta` on every dataset | Provenance travels with the data |
| Degrade, never fake | A missing dependency produces a message, not a plausible number |
| Redact at egress | One place to audit, not many |
| No daemons | Predictable resource use, no hidden background process |
