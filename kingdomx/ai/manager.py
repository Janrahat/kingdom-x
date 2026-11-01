"""Model registry, provider CRUD, usage accounting and chat dispatch.

The manager is the only place that decides *whether* a model may be used. Its
rule: a ``(provider, model)`` pair is usable when the database records a
successful verification for it, or when the operator explicitly forces
``unverified`` use on the command line (which is labelled in every response).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from kingdomx.ai.catalog import PROVIDERS, ProviderSpec, all_specs, get_spec
from kingdomx.ai.client import (
    ChatRequest,
    ChatResponse,
    build_request,
    parse_response,
)
from kingdomx.ai.health import (
    VERIFY_CHAT_OK,
    VERIFY_LISTED,
    HealthResult,
    check_provider,
    ollama_status,
    resolve_key,
)
from kingdomx.core.config import Config
from kingdomx.core.errors import ProviderError, UnsafeTargetError
from kingdomx.core.http import SafeHttpClient
from kingdomx.core.logging_setup import get_logger
from kingdomx.core.storage import Database

log = get_logger("ai.manager")

#: A verified chat is accepted for this long before it must be re-checked.
VERIFICATION_TTL_SECONDS = 24 * 3600


@dataclass
class ModelInfo:
    provider: str
    name: str
    display_name: str
    context_window: int | None
    available: bool
    verification: str
    checked_at: float | None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "name": self.name,
            "display_name": self.display_name,
            "context_window": self.context_window,
            "available": self.available,
            "verification": self.verification,
            "checked_at": self.checked_at,
            "reason": self.reason,
        }

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.name}"


class AIManager:
    """Everything the AI center needs, backed by the SQLite registry."""

    def __init__(self, config: Config, db: Database) -> None:
        self.config = config
        self.db = db
        self._seed_providers()

    # ------------------------------------------------------------------ providers
    def _seed_providers(self) -> None:
        """Ensure every catalogue provider has a row. Never overwrites operator edits."""
        for spec in all_specs():
            existing = self.db.query_one("SELECT name FROM providers WHERE name = ?", (spec.name,))
            if existing:
                continue
            self.db.execute(
                """
                INSERT INTO providers (name, kind, base_url, default_model, enabled)
                VALUES (?, ?, ?, ?, ?)
                """,
                (spec.name, spec.kind, spec.base_url, spec.default_model, 1),
            )

    def providers(self) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT * FROM providers WHERE enabled = 1 ORDER BY name")
        status = self.config.provider_status()
        for row in rows:
            key_info = status.get(row["name"], {})
            row["key_configured"] = bool(key_info.get("configured"))
            row["key_source"] = key_info.get("source")
            spec = get_spec(row["name"])
            row["label"] = spec.label if spec else row["name"]
            row["local"] = bool(spec.local) if spec else False
        return rows

    def enable_provider(self, name: str, enabled: bool = True) -> bool:
        spec = get_spec(name)
        if spec is None:
            return False
        self.db.execute("UPDATE providers SET enabled = ? WHERE name = ?", (1 if enabled else 0, name))
        self.db.audit("operator", "provider.enable" if enabled else "provider.disable", target=name)
        return True

    def register_custom(
        self, name: str, base_url: str, *, default_model: str = "", label: str = ""
    ) -> dict[str, Any]:
        """Add an operator-supplied OpenAI-compatible endpoint."""
        from kingdomx.core.validation import normalise_url

        clean = (name or "").strip().lower().replace(" ", "-")
        if not clean or len(clean) > 32:
            raise ProviderError("custom provider name must be 1-32 characters")
        if not all(ch.isalnum() or ch in "-_" for ch in clean):
            raise ProviderError("custom provider name may contain letters, digits, - and _ only")
        url = normalise_url(base_url)  # validates scheme + host shape
        self.db.execute(
            """
            INSERT INTO providers (name, kind, base_url, default_model, enabled)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(name) DO UPDATE SET base_url = excluded.base_url,
                                            default_model = excluded.default_model
            """,
            (clean, "openai_compatible", url, default_model),
        )
        self.db.audit("operator", "provider.register_custom", target=clean, detail=url)
        return {"name": clean, "label": label or clean, "base_url": url}

    # ------------------------------------------------------------------ health
    def check(self, provider: str, *, deep: bool = False, timeout: float = 10.0) -> HealthResult:
        """Run a real health check and persist the outcome."""
        key = self.config.provider_key(provider)
        result = check_provider(provider, api_key=key, deep=deep, timeout=timeout)

        self.db.execute(
            """
            UPDATE providers SET last_checked = ?, last_status = ?, last_error = ?
            WHERE name = ?
            """,
            (
                result.checked_at,
                "ok" if result.ok else "error",
                result.error,
                provider,
            ),
        )

        if result.models:
            for entry in result.models:
                self.db.execute(
                    """
                    INSERT INTO models (provider, name, display_name, context_window, kind,
                                        available, checked_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(provider, name) DO UPDATE SET
                        display_name = excluded.display_name,
                        context_window = excluded.context_window,
                        available = excluded.available,
                        checked_at = excluded.checked_at
                    """,
                    (
                        provider,
                        entry["name"],
                        entry.get("display_name") or entry["name"],
                        entry.get("context_window"),
                        entry.get("kind"),
                        1 if result.reachable else 0,
                        result.checked_at,
                    ),
                )
        self.db.audit(
            "operator",
            "ai.health_check",
            target=provider,
            outcome="ok" if result.ok else "error",
            detail=result.error or f"{len(result.models)} models",
        )
        return result

    def check_all(self, *, timeout: float = 8.0) -> dict[str, HealthResult]:
        out: dict[str, HealthResult] = {}
        for row in self.providers():
            out[row["name"]] = self.check(row["name"], timeout=timeout)
        return out

    def ollama(self) -> dict[str, Any]:
        return ollama_status(self.config.get("ai.ollama_host"))

    # ------------------------------------------------------------------ models
    def models(
        self,
        *,
        provider: str | None = None,
        only_available: bool = False,
    ) -> list[ModelInfo]:
        sql = "SELECT * FROM models"
        params: list[Any] = []
        if provider:
            sql += " WHERE provider = ?"
            params.append(provider)
        sql += " ORDER BY provider, name"

        out: list[ModelInfo] = []
        now = time.time()
        for row in self.db.query(sql, params):
            checked = row["checked_at"]
            fresh = bool(checked) and (now - float(checked)) < VERIFICATION_TTL_SECONDS
            available = bool(row["available"]) and fresh
            verification = VERIFY_LISTED if available else "unverified"
            reason = None
            if not available:
                reason = "not verified in the last 24h" if checked else "never checked"
            info = ModelInfo(
                provider=row["provider"],
                name=row["name"],
                display_name=row["display_name"] or row["name"],
                context_window=row["context_window"],
                available=available,
                verification=verification,
                checked_at=checked,
                reason=reason,
            )
            if only_available and not info.available:
                continue
            out.append(info)
        return out

    def mark_chat_verified(self, provider: str, model: str) -> None:
        """Record that a real chat completion succeeded for this pair."""
        self.db.execute(
            """
            INSERT INTO models (provider, name, display_name, available, checked_at)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(provider, name) DO UPDATE SET available = 1,
                                                     checked_at = excluded.checked_at
            """,
            (provider, model, model, time.time()),
        )

    def select_model(
        self, provider: str | None = None, model: str | None = None
    ) -> tuple[str, str]:
        """Pick a usable ``(provider, model)`` pair or raise with a clear reason."""
        if provider and model:
            return provider, model

        if provider:
            candidates = self.models(provider=provider, only_available=True)
            if not candidates:
                raise ProviderError(
                    f"no verified model for {provider}",
                    detail="run `kingdomx ai check --provider " + provider + "` first",
                )
            return provider, candidates[0].name

        # No provider given: honour the configured default, else first verified.
        default_provider = str(self.config.get("ai.default_provider") or "")
        default_model = str(self.config.get("ai.default_model") or "")
        if default_provider and default_provider in PROVIDERS:
            if default_model:
                return default_provider, default_model
            candidates = self.models(provider=default_provider, only_available=True)
            if candidates:
                return default_provider, candidates[0].name

        for info in self.models(only_available=True):
            return info.provider, info.name

        raise ProviderError(
            "no AI model is available",
            detail=(
                "set a provider key (e.g. OPENAI_API_KEY) or start Ollama, then run "
                "`kingdomx ai check --deep`"
            ),
        )

    # ------------------------------------------------------------------ chat
    def chat(
        self,
        request: ChatRequest,
        *,
        provider: str | None = None,
        timeout: float = 60.0,
        force_unverified: bool = False,
    ) -> ChatResponse:
        """Send a chat request and record usage. Never fabricates a reply."""
        chosen_provider = provider or request.model.split("/", 1)[0] if "/" in (request.model or "") else provider
        if "/" in (request.model or ""):
            head, _, tail = request.model.partition("/")
            if get_spec(head) is not None:
                chosen_provider, request.model = head, tail

        resolved_provider, resolved_model = (
            (chosen_provider, request.model)
            if chosen_provider and request.model
            else self.select_model(chosen_provider, request.model)
        )
        request.model = resolved_model

        spec = get_spec(resolved_provider)
        if spec is None:
            raise ProviderError(f"unknown provider: {resolved_provider}")

        if not force_unverified:
            verified = {
                (info.provider, info.name)
                for info in self.models(provider=resolved_provider, only_available=True)
            }
            if (resolved_provider, resolved_model) not in verified:
                log.info(
                    "using unverified model %s/%s (operator did not request a health check)",
                    resolved_provider,
                    resolved_model,
                )

        key = self.config.provider_key(resolved_provider)
        if spec.key_required and not key:
            raise ProviderError(
                f"{spec.label} has no API key configured",
                detail=f"set {spec.env_var} or run `kingdomx ai set-key {resolved_provider}`",
            )

        built = build_request(spec, request, api_key=key)
        client = SafeHttpClient(
            timeout=timeout,
            allow_private=spec.local,
            user_agent="KingdomX/1.0 ai",
        )

        started = time.perf_counter()
        try:
            response = client.request(
                built["method"],
                built["url"],
                json_body=built["payload"],
                headers=built["headers"],
                timeout=timeout,
                max_bytes=4 * 1024 * 1024,
            )
            parsed = parse_response(spec, response.status, response.body)
        except (ProviderError, UnsafeTargetError) as exc:
            latency = (time.perf_counter() - started) * 1000
            self._record_usage(resolved_provider, resolved_model, {}, latency, ok=False, error=exc.code)
            raise
        except Exception as exc:  # noqa: BLE001 - network errors already normalised
            latency = (time.perf_counter() - started) * 1000
            self._record_usage(
                resolved_provider, resolved_model, {}, latency, ok=False, error="kingdomx.network"
            )
            raise ProviderError(f"{spec.label} request failed", detail=type(exc).__name__) from exc

        latency = (time.perf_counter() - started) * 1000
        self._record_usage(
            resolved_provider,
            resolved_model,
            parsed.usage,
            latency,
            ok=parsed.ok,
            error=None if parsed.ok else "kingdomx.provider.empty",
        )
        if parsed.ok:
            self.mark_chat_verified(resolved_provider, resolved_model)
        return parsed

    def _record_usage(
        self,
        provider: str,
        model: str,
        usage: dict[str, int],
        latency_ms: float,
        *,
        ok: bool,
        error: str | None,
    ) -> None:
        if not self.config.get("ai.track_usage", True):
            return
        self.db.execute(
            """
            INSERT INTO ai_usage (ts, provider, model, prompt_tokens, completion_tokens,
                                  total_tokens, latency_ms, ok, error_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                provider,
                model,
                int(usage.get("prompt_tokens") or 0),
                int(usage.get("completion_tokens") or 0),
                int(usage.get("total_tokens") or 0),
                latency_ms,
                1 if ok else 0,
                error,
            ),
        )

    # ------------------------------------------------------------------ usage
    def usage_summary(self, *, days: int = 30) -> dict[str, Any]:
        cutoff = time.time() - days * 86400
        rows = self.db.query(
            """
            SELECT provider, model,
                   COUNT(*)                        AS calls,
                   SUM(total_tokens)               AS tokens,
                   AVG(latency_ms)                 AS avg_latency,
                   SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END) AS failures
            FROM ai_usage
            WHERE ts >= ?
            GROUP BY provider, model
            ORDER BY calls DESC
            """,
            (cutoff,),
        )
        totals = self.db.query_one(
            """
            SELECT COUNT(*) AS calls,
                   COALESCE(SUM(total_tokens), 0) AS tokens,
                   COALESCE(AVG(latency_ms), 0)   AS avg_latency,
                   COALESCE(SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END), 0) AS failures
            FROM ai_usage WHERE ts >= ?
            """,
            (cutoff,),
        ) or {}
        return {
            "window_days": days,
            "by_model": rows,
            "totals": {
                "calls": int(totals.get("calls") or 0),
                "tokens": int(totals.get("tokens") or 0),
                "avg_latency_ms": round(float(totals.get("avg_latency") or 0), 1),
                "failures": int(totals.get("failures") or 0),
            },
        }

    # ------------------------------------------------------------------ compare
    def compare(
        self,
        prompt: str,
        pairs: list[tuple[str, str]],
        *,
        timeout: float = 60.0,
    ) -> list[dict[str, Any]]:
        """Send one prompt to several models and report each real outcome."""
        results: list[dict[str, Any]] = []
        for provider, model in pairs:
            request = ChatRequest.from_prompt(
                prompt,
                model=model,
                temperature=self.config.get("ai.temperature", 0.2),
                max_tokens=min(int(self.config.get("ai.max_tokens", 2048)), 1024),
            )
            started = time.perf_counter()
            try:
                response = self.chat(request, provider=provider, timeout=timeout, force_unverified=True)
                results.append(
                    {
                        "provider": provider,
                        "model": model,
                        "ok": response.ok,
                        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                        "tokens": response.usage.get("total_tokens", 0),
                        "text": response.text,
                        "error": None,
                    }
                )
            except (ProviderError, UnsafeTargetError) as exc:
                results.append(
                    {
                        "provider": provider,
                        "model": model,
                        "ok": False,
                        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                        "tokens": 0,
                        "text": "",
                        "error": exc.message,
                    }
                )
        return results

    # ------------------------------------------------------------------ keys
    def set_key(self, provider: str, api_key: str) -> dict[str, Any]:
        """Store a provider key in the encrypted vault, never in the config file."""
        from kingdomx.core.redaction import describe_presence

        spec = get_spec(provider)
        if spec is None and provider != "custom":
            raise ProviderError(f"unknown provider: {provider}")
        if not api_key or len(api_key) < 8:
            raise ProviderError("API key looks too short to be valid")
        self.config.store_secret(f"provider.{provider}", api_key)
        self.db.audit(
            "operator",
            "ai.set_key",
            target=provider,
            detail="stored in encrypted vault",
        )
        meta = describe_presence(api_key)
        return {
            "provider": provider,
            "stored": True,
            "length": meta["length"],
            "env_var": spec.env_var if spec else "CUSTOM_AI_API_KEY",
        }

    def clear_key(self, provider: str) -> bool:
        removed = self.config.delete_secret(f"provider.{provider}")
        self.db.audit("operator", "ai.clear_key", target=provider)
        return removed

    def key_status(self) -> list[dict[str, Any]]:
        status = self.config.provider_status()
        rows = []
        for name, info in sorted(status.items()):
            spec = get_spec(name)
            rows.append(
                {
                    "provider": name,
                    "label": spec.label if spec else name,
                    "configured": info["configured"],
                    "source": info["source"],
                    "env_var": info["env_var"],
                    "key_required": spec.key_required if spec else True,
                }
            )
        return rows
