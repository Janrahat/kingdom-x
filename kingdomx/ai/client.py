"""Provider-agnostic request building and response parsing.

Four wire shapes are covered:

* ``openai`` / ``openai_compatible`` / ``ollama`` — ``/chat/completions`` with
  ``messages[]`` and ``choices[0].message.content``.
* ``anthropic`` — ``/messages`` with a top-level ``system`` and ``content[]``
  blocks; the reply is a **list of blocks**, not a string.
* ``google`` — ``:generateContent`` with ``contents[].parts[]``; the reply nests
  under ``candidates[0].content.parts[*].text``, and ``promptFeedback`` can
  block a request before any candidate exists.

Building and parsing are pure functions with no I/O so they can be unit-tested
exhaustively without touching the network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from kingdomx.ai.catalog import ProviderSpec, get_spec
from kingdomx.core.errors import ProviderError


@dataclass
class ChatMessage:
    role: str
    content: str

    def __post_init__(self) -> None:
        role = (self.role or "").strip().lower()
        if role not in {"system", "user", "assistant"}:
            raise ProviderError(f"unsupported message role: {self.role}")
        self.role = role

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class ChatRequest:
    """A provider-neutral chat request."""

    messages: list[ChatMessage]
    model: str
    temperature: float = 0.2
    max_tokens: int = 2048
    top_p: float | None = None
    system: str | None = None
    stream: bool = False
    stop: Sequence[str] = field(default_factory=list)

    @classmethod
    def from_prompt(
        cls,
        prompt: str,
        *,
        model: str,
        system: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> "ChatRequest":
        return cls(
            messages=[ChatMessage("user", prompt)],
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            system=system,
        )

    def with_system(self, system: str) -> "ChatRequest":
        self.system = system
        return self


@dataclass
class ChatResponse:
    """A normalised reply, whatever the provider shape was."""

    text: str
    model: str
    provider: str
    usage: dict[str, int] = field(default_factory=dict)
    finish_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    block_reason: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.text.strip()) and not self.blocked

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "model": self.model,
            "provider": self.provider,
            "usage": dict(self.usage),
            "finish_reason": self.finish_reason,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
        }


# --------------------------------------------------------------------------- headers
def build_headers(spec: ProviderSpec, api_key: str | None) -> dict[str, str]:
    """Auth and content headers for ``spec``."""
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    key = (api_key or "").strip()

    if spec.auth_style == "bearer" and key:
        headers["Authorization"] = f"Bearer {key}"
    elif spec.auth_style == "x-api-key" and key:
        headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"
    elif spec.auth_style == "x-goog-api-key" and key:
        headers["x-goog-api-key"] = key
    elif spec.auth_style == "none":
        pass
    elif spec.key_required and not key:
        raise ProviderError(
            f"{spec.label} requires an API key",
            detail=f"set {spec.env_var} in your environment",
        )
    return headers


# --------------------------------------------------------------------------- build
def build_request(
    spec: ProviderSpec,
    request: ChatRequest,
    *,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Build ``(url, headers, payload)``-shaped data for one provider."""
    if not request.model:
        raise ProviderError(
            f"no model selected for {spec.label}",
            detail="run a health check first; never assume a model name",
        )

    url = spec.chat_url(request.model)
    headers = build_headers(spec, api_key)
    payload = _build_payload(spec, request)
    return {"url": url, "headers": headers, "payload": payload, "method": spec.chat_method}


def _build_payload(spec: ProviderSpec, request: ChatRequest) -> dict[str, Any]:
    if spec.kind == "google":
        return _build_google(request)
    if spec.kind == "anthropic":
        return _build_anthropic(request)
    return _build_openai(spec, request)


def _build_openai(spec: ProviderSpec, request: ChatRequest) -> dict[str, Any]:
    messages: list[dict[str, str]] = []
    if request.system:
        messages.append({"role": "system", "content": request.system})
    messages.extend(message.to_dict() for message in request.messages)

    payload: dict[str, Any] = {
        "model": request.model,
        "messages": messages,
        "temperature": request.temperature,
        "max_tokens": request.max_tokens,
    }
    if request.top_p is not None:
        payload["top_p"] = request.top_p
    if request.stop:
        payload["stop"] = list(request.stop)
    if request.stream:
        payload["stream"] = True
    return payload


def _build_anthropic(request: ChatRequest) -> dict[str, Any]:
    # Anthropic requires system as a top-level field and at least one message.
    messages = [m.to_dict() for m in request.messages if m.role != "system"]
    if not messages:
        raise ProviderError("Anthropic requires at least one user message")
    for message in messages:
        if message["role"] == "system":
            message["role"] = "user"

    payload: dict[str, Any] = {
        "model": request.model,
        "messages": messages,
        "max_tokens": max(1, request.max_tokens),
        "temperature": max(0.0, min(request.temperature, 1.0)),
    }
    system_text = request.system or next(
        (m.content for m in request.messages if m.role == "system"), None
    )
    if system_text:
        payload["system"] = system_text
    if request.stop:
        payload["stop_sequences"] = list(request.stop)
    if request.stream:
        payload["stream"] = True
    return payload


def _build_google(request: ChatRequest) -> dict[str, Any]:
    contents: list[dict[str, Any]] = []
    for message in request.messages:
        role = "model" if message.role == "assistant" else "user"
        if message.role == "system":
            role = "user"
        contents.append({"role": role, "parts": [{"text": message.content}]})
    if not contents:
        raise ProviderError("Gemini requires at least one content part")

    payload: dict[str, Any] = {
        "contents": contents,
        "generationConfig": {
            "temperature": max(0.0, min(request.temperature, 2.0)),
            "maxOutputTokens": max(1, request.max_tokens),
        },
    }
    if request.top_p is not None:
        payload["generationConfig"]["topP"] = max(0.0, min(request.top_p, 1.0))
    if request.system:
        payload["systemInstruction"] = {"parts": [{"text": request.system}]}
    if request.stop:
        payload["generationConfig"]["stopSequences"] = list(request.stop)
    return payload


# --------------------------------------------------------------------------- parse
def parse_response(spec: ProviderSpec, status: int, body: bytes | str) -> ChatResponse:
    """Turn a provider reply into a :class:`ChatResponse`, or raise."""
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
    try:
        payload = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        if status >= 400:
            raise ProviderError(
                f"{spec.label} returned HTTP {status}",
                detail=_truncate(text),
            ) from None
        raise ProviderError(
            f"{spec.label} returned a non-JSON body", detail=_truncate(text)
        ) from None

    if status >= 400 or "error" in payload and status >= 400:
        raise ProviderError(
            f"{spec.label} returned HTTP {status}",
            detail=_error_message(payload) or _truncate(text),
        )

    if spec.kind == "google":
        return _parse_google(spec, payload)
    if spec.kind == "anthropic":
        return _parse_anthropic(spec, payload)
    return _parse_openai(spec, payload)


def _parse_openai(spec: ProviderSpec, payload: dict[str, Any]) -> ChatResponse:
    if "error" in payload:
        raise ProviderError(f"{spec.label} error", detail=_error_message(payload))

    choices = payload.get("choices") or []
    if not choices:
        # Ollama's *native* /api/chat shape (and a few compatible servers) answer
        # with a top-level "message" object and no "choices" array. Rejecting that
        # would make a perfectly good local reply look like a provider failure.
        native = payload.get("message")
        if isinstance(native, dict) and (native.get("content") or "").strip():
            return ChatResponse(
                text=str(native.get("content")).strip(),
                model=payload.get("model") or "",
                provider=spec.name,
                usage=_normalise_usage(
                    {
                        "prompt_tokens": payload.get("prompt_eval_count"),
                        "completion_tokens": payload.get("eval_count"),
                    }
                ),
                finish_reason=payload.get("done_reason") or ("stop" if payload.get("done") else None),
                raw=payload,
            )
        raise ProviderError(
            f"{spec.label} returned no choices",
            detail=_truncate(json.dumps(payload)[:400]),
        )
    choice = choices[0] or {}
    message = choice.get("message") or {}
    content = message.get("content")

    # Some OpenAI-compatible servers return a list of content parts.
    if isinstance(content, list):
        content = "".join(
            part.get("text", "") if isinstance(part, dict) else str(part) for part in content
        )
    text = (content or "").strip()
    if not text:
        text = (choice.get("text") or "").strip()

    usage = _normalise_usage(payload.get("usage") or {})
    return ChatResponse(
        text=text,
        model=payload.get("model") or "",
        provider=spec.name,
        usage=usage,
        finish_reason=choice.get("finish_reason"),
        raw=payload,
    )


def _parse_anthropic(spec: ProviderSpec, payload: dict[str, Any]) -> ChatResponse:
    blocks = payload.get("content") or []
    parts: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            parts.append(str(block.get("text", "")))
        elif block.get("type") == "tool_use":
            parts.append(f"[tool_use {block.get('name')}: {block.get('input')}]")

    usage_raw = payload.get("usage") or {}
    usage = {
        "prompt_tokens": int(usage_raw.get("input_tokens") or 0),
        "completion_tokens": int(usage_raw.get("output_tokens") or 0),
    }
    usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]

    return ChatResponse(
        text="".join(parts).strip(),
        model=payload.get("model") or "",
        provider=spec.name,
        usage=usage,
        finish_reason=payload.get("stop_reason"),
        raw=payload,
    )


def _parse_google(spec: ProviderSpec, payload: dict[str, Any]) -> ChatResponse:
    feedback = payload.get("promptFeedback") or {}
    block_reason = feedback.get("blockReason")
    if block_reason:
        return ChatResponse(
            text="",
            model=payload.get("modelVersion") or "",
            provider=spec.name,
            blocked=True,
            block_reason=str(block_reason),
            raw=payload,
        )

    candidates = payload.get("candidates") or []
    if not candidates:
        raise ProviderError(
            "Gemini returned no candidates",
            detail=_truncate(json.dumps(payload)[:400]),
        )
    candidate = candidates[0] or {}
    parts = ((candidate.get("content") or {}).get("parts")) or []
    text = "".join(
        str(part.get("text", "")) for part in parts if isinstance(part, dict)
    ).strip()

    usage_raw = payload.get("usageMetadata") or {}
    usage = {
        "prompt_tokens": int(usage_raw.get("promptTokenCount") or 0),
        "completion_tokens": int(usage_raw.get("candidatesTokenCount") or 0),
        "total_tokens": int(usage_raw.get("totalTokenCount") or 0),
    }
    if not usage["total_tokens"]:
        usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]

    finish = candidate.get("finishReason")
    return ChatResponse(
        text=text,
        model=payload.get("modelVersion") or "",
        provider=spec.name,
        usage=usage,
        finish_reason=finish,
        raw=payload,
        blocked=finish == "SAFETY" and not text,
        block_reason=str(finish) if finish == "SAFETY" else None,
    )


# --------------------------------------------------------------------------- models
def parse_model_list(spec: ProviderSpec, payload: Any) -> list[dict[str, Any]]:
    """Extract ``[{name, display_name, context_window}]`` from a model-list reply."""
    items: Any
    if isinstance(payload, dict):
        items = (
            payload.get("data")
            or payload.get("models")
            or (payload.get("data") or {}).get("models")
            or []
        )
    else:
        items = payload or []

    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ident = item.get("id") or item.get("name") or item.get("model")
        if not ident:
            continue
        ident = str(ident)
        if spec.kind == "google" and ident.startswith("models/"):
            ident = ident[len("models/") :]
        out.append(
            {
                "name": ident,
                "display_name": str(item.get("display_name") or item.get("displayName") or ident),
                "context_window": _context_window(item),
                "kind": _model_kind(item),
            }
        )
    return sorted(out, key=lambda entry: entry["name"])


def _context_window(item: dict[str, Any]) -> int | None:
    for key in ("context_window", "context_length", "input_token_limit", "max_context_length"):
        value = item.get(key)
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def _model_kind(item: dict[str, Any]) -> str | None:
    for key in ("type", "object", "kind"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    methods = item.get("supportedGenerationMethods")
    if isinstance(methods, list):
        return ",".join(str(m) for m in methods)
    return None


# --------------------------------------------------------------------------- helpers
def _normalise_usage(raw: dict[str, Any]) -> dict[str, int]:
    prompt = int(raw.get("prompt_tokens") or 0)
    completion = int(raw.get("completion_tokens") or 0)
    total = int(raw.get("total_tokens") or 0) or (prompt + completion)
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
    }


def _error_message(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if isinstance(error, dict):
        message = error.get("message") or error.get("error_description")
        return str(message) if message else None
    if isinstance(error, str):
        return error
    if isinstance(payload.get("message"), str):
        return payload["message"]
    return None


def _truncate(text: str, limit: int = 300) -> str:
    clean = (text or "").strip().replace("\n", " ")
    return clean if len(clean) <= limit else clean[: limit - 1] + "…"


def estimate_tokens(text: str) -> int:
    """A rough 4-characters-per-token estimate, clearly labelled as such."""
    return max(1, len(text or "") // 4)


def messages_from_history(turns: Iterable[tuple[str, str]]) -> list[ChatMessage]:
    """Build messages from ``[(role, content), ...]`` pairs."""
    return [ChatMessage(role, content) for role, content in turns]
