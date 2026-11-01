"""High-level assistant: presets, history, and an honest offline fallback.

The offline fallback is the important part. When no provider is reachable, the
assistant does **not** pretend a model answered. It either:

* raises a clear error (default), or
* returns a *deterministic local analysis* that is clearly labelled
  ``source: "local-rule-engine"`` — useful for things KINGDOM X can answer
  without any model (e.g. explaining a hash length, a port number, a header).

That distinction is surfaced in the return value so a caller can never mistake
local rules for model output.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from kingdomx.ai.catalog import TASK_PRESETS, task_preset
from kingdomx.ai.client import ChatMessage, ChatRequest, ChatResponse
from kingdomx.ai.manager import AIManager
from kingdomx.core.errors import ProviderError
from kingdomx.core.logging_setup import get_logger

log = get_logger("ai.assistant")

MAX_HISTORY_TURNS = 20


@dataclass
class AssistantReply:
    """A reply plus where it actually came from."""

    text: str
    source: str
    """``model`` or ``local-rule-engine``."""

    provider: str | None = None
    model: str | None = None
    preset: str = "general"
    usage: dict[str, int] = field(default_factory=dict)
    latency_ms: float = 0.0
    error: str | None = None
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "source": self.source,
            "provider": self.provider,
            "model": self.model,
            "preset": self.preset,
            "usage": dict(self.usage),
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
            "verified": self.verified,
        }


@dataclass
class Turn:
    role: str
    content: str
    ts: float = field(default_factory=time.time)


class Assistant:
    """Conversation state plus preset-aware dispatch."""

    def __init__(self, manager: AIManager) -> None:
        self.manager = manager
        self.history: list[Turn] = []
        self.preset = "general"
        self.provider: str | None = None
        self.model: str | None = None

    def reset(self) -> None:
        self.history.clear()

    def set_preset(self, key: str) -> str:
        if key not in TASK_PRESETS:
            raise ProviderError(
                f"unknown preset: {key}",
                detail="available: " + ", ".join(sorted(TASK_PRESETS)),
            )
        self.preset = key
        return key

    def system_prompt(self) -> str:
        base = task_preset(self.preset)["system"]
        return (
            base
            + "\n\nYou are running inside KINGDOM X on the operator's own machine. "
            "Never claim you executed a command or accessed a system unless the "
            "operator's message shows the output."
        )

    # ------------------------------------------------------------------ ask
    def ask(
        self,
        prompt: str,
        *,
        allow_local_fallback: bool = False,
        timeout: float = 60.0,
        remember: bool = True,
    ) -> AssistantReply:
        """Ask the configured model. Optionally fall back to local rules."""
        question = (prompt or "").strip()
        if not question:
            raise ProviderError("empty prompt")

        started = time.perf_counter()
        try:
            provider, model = (
                (self.provider, self.model)
                if self.provider and self.model
                else self.manager.select_model()
            )
            request = ChatRequest(
                messages=self._messages_for(question),
                model=model,
                temperature=float(self.manager.config.get("ai.temperature", 0.2)),
                max_tokens=int(self.manager.config.get("ai.max_tokens", 2048)),
                system=self.system_prompt(),
            )
            response: ChatResponse = self.manager.chat(request, provider=provider, timeout=timeout)
        except (ProviderError, Exception) as exc:  # noqa: BLE001 - normalise everything
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            message = getattr(exc, "message", str(exc))
            if allow_local_fallback:
                local = local_answer(question)
                if local is not None:
                    return AssistantReply(
                        text=local,
                        source="local-rule-engine",
                        preset=self.preset,
                        latency_ms=(time.perf_counter() - started) * 1000,
                        error=message,
                        verified=False,
                    )
            if isinstance(exc, ProviderError):
                raise
            raise ProviderError("AI request failed", detail=message) from exc

        latency = (time.perf_counter() - started) * 1000
        if remember:
            self.history.append(Turn("user", question))
            self.history.append(Turn("assistant", response.text))
            self._trim()

        return AssistantReply(
            text=response.text,
            source="model",
            provider=provider,
            model=response.model or model,
            preset=self.preset,
            usage=response.usage,
            latency_ms=latency,
            verified=response.ok,
        )

    def _messages_for(self, question: str) -> list[ChatMessage]:
        messages = [ChatMessage(turn.role, turn.content) for turn in self.history]
        messages.append(ChatMessage("user", question))
        return messages

    def _trim(self) -> None:
        limit = MAX_HISTORY_TURNS * 2
        if len(self.history) > limit:
            self.history = self.history[-limit:]


# --------------------------------------------------------------------------- local rules
_HASH_HINT = re.compile(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})\b")


def local_answer(question: str) -> str | None:
    """Answer a small set of questions deterministically, with no model.

    Returns ``None`` when the question is outside what these rules can handle —
    the caller must then report that no model was available rather than guessing.
    """
    text = (question or "").strip()
    low = text.lower()

    if "hash" in low or _HASH_HINT.search(text):
        match = _HASH_HINT.search(text)
        if match:
            digest = match.group(1)
            kind = {
                32: "MD5",
                40: "SHA-1",
                64: "SHA-256",
                128: "SHA-512",
            }.get(len(digest), "unknown")
            weak = kind in {"MD5", "SHA-1"}
            return (
                f"Local rule engine (no AI model was reachable).\n\n"
                f"Digest length {len(digest)} hex characters matches {kind}.\n"
                + (
                    f"{kind} is cryptographically broken for password storage and for "
                    "collision resistance. Use Argon2id (or scrypt) for passwords and "
                    "SHA-256/SHA-512 for integrity.\n"
                    if weak
                    else f"{kind} is acceptable for integrity checks. For passwords, prefer "
                    "Argon2id with a per-user salt.\n"
                )
                + "\nThis is a deterministic string-length classification, not a hash lookup."
            )

    if low.startswith(("what is port", "what's port")) or re.search(r"\bport\s+(\d{1,5})\b", low):
        match = re.search(r"\bport\s+(\d{1,5})\b", low)
        if match:
            from kingdomx.cybersecurity.ports import describe_port

            return "Local rule engine (no AI model was reachable).\n\n" + describe_port(
                int(match.group(1))
            )

    if "cyrillic" in low or "homograph" in low or "punycode" in low or "idn" in low:
        return (
            "Local rule engine (no AI model was reachable).\n\n"
            "Homograph attacks use characters from other scripts that render like Latin "
            "letters. Detect them by comparing the ASCII punycode form (xn--) with the "
            "displayed form, and by checking that every label of a security-relevant "
            "domain is pure ASCII. KINGDOM X's domain module flags non-ASCII labels for "
            "exactly this reason."
        )

    if low in {"help", "?", "commands"}:
        return (
            "Local rule engine (no AI model was reachable).\n\n"
            "This is the built-in help path, not a model reply. Run `kingdomx --help` for "
            "commands, or `kingdomx ai check --deep` to verify a provider."
        )

    return None
