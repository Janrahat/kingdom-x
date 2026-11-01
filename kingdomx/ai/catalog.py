"""Provider catalogue.

Each entry describes how to reach a provider: base URL, auth header style, the
request/response shape we must build and parse, and where its key comes from.

**No model is ever reported as available because it appears in this catalogue.**
Availability is decided by :mod:`kingdomx.ai.health`, which actually calls the
provider's model-list endpoint (or the local runtime) and records the result.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProviderSpec:
    """How to talk to one provider."""

    name: str
    label: str
    base_url: str
    kind: str
    """``openai``, ``openai_compatible``, ``anthropic``, ``google``, ``ollama``."""

    env_var: str
    docs_url: str
    key_required: bool = True
    local: bool = False
    models_path: str = "/models"
    chat_path: str = "/chat/completions"
    auth_style: str = "bearer"
    """``bearer``, ``x-api-key``, ``x-goog-api-key``, ``none``."""

    chat_method: str = "POST"
    default_model: str = ""
    notes: str = ""
    known_models: tuple[str, ...] = field(default_factory=tuple)

    @property
    def models_url(self) -> str:
        return self.base_url.rstrip("/") + self.models_path

    def chat_url(self, model: str) -> str:
        """Full URL for a chat call on ``model``."""
        base = self.base_url.rstrip("/")
        if self.kind == "google":
            return f"{base}/models/{model}:generateContent"
        return base + self.chat_path

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "label": self.label,
            "base_url": self.base_url,
            "kind": self.kind,
            "env_var": self.env_var,
            "docs_url": self.docs_url,
            "key_required": self.key_required,
            "local": self.local,
            "default_model": self.default_model,
            "notes": self.notes,
            "known_models": list(self.known_models),
        }


#: Every provider the platform knows how to speak to.
PROVIDERS: dict[str, ProviderSpec] = {
    "openai": ProviderSpec(
        name="openai",
        label="OpenAI",
        base_url="https://api.openai.com/v1",
        kind="openai",
        env_var="OPENAI_API_KEY",
        docs_url="https://platform.openai.com/docs/api-reference",
        default_model="gpt-4o-mini",
        known_models=("gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o4-mini"),
        notes=(
            "Model availability depends on the account tier. The list above is only a "
            "hint; health checks replace it with the live /v1/models response."
        ),
    ),
    "deepseek": ProviderSpec(
        name="deepseek",
        label="DeepSeek",
        base_url="https://api.deepseek.com/v1",
        kind="openai_compatible",
        env_var="DEEPSEEK_API_KEY",
        docs_url="https://api-docs.deepseek.com",
        default_model="deepseek-chat",
        known_models=("deepseek-chat", "deepseek-reasoner"),
    ),
    "mistral": ProviderSpec(
        name="mistral",
        label="Mistral AI",
        base_url="https://api.mistral.ai/v1",
        kind="openai_compatible",
        env_var="MISTRAL_API_KEY",
        docs_url="https://docs.mistral.ai",
        default_model="mistral-small-latest",
        known_models=("mistral-large-latest", "mistral-small-latest", "codestral-latest"),
    ),
    "groq": ProviderSpec(
        name="groq",
        label="Groq",
        base_url="https://api.groq.com/openai/v1",
        kind="openai_compatible",
        env_var="GROQ_API_KEY",
        docs_url="https://console.groq.com/docs",
        default_model="llama-3.3-70b-versatile",
        known_models=("llama-3.3-70b-versatile", "llama-3.1-8b-instant"),
    ),
    "openrouter": ProviderSpec(
        name="openrouter",
        label="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        kind="openai_compatible",
        env_var="OPENROUTER_API_KEY",
        docs_url="https://openrouter.ai/docs",
        default_model="",
        notes="Routes to many upstream models; the live model list is authoritative.",
    ),
    "qwen": ProviderSpec(
        name="qwen",
        label="Qwen (DashScope)",
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        kind="openai_compatible",
        env_var="DASHSCOPE_API_KEY",
        docs_url="https://help.aliyun.com/zh/dashscope/",
        default_model="qwen-plus",
        known_models=("qwen-plus", "qwen-turbo", "qwen-max"),
    ),
    "huggingface": ProviderSpec(
        name="huggingface",
        label="Hugging Face Router",
        base_url="https://router.huggingface.co/v1",
        kind="openai_compatible",
        env_var="HUGGINGFACE_API_KEY",
        docs_url="https://huggingface.co/docs/api-inference",
        default_model="",
        notes="The HF router exposes an OpenAI-shaped endpoint; models vary by account.",
    ),
    "anthropic": ProviderSpec(
        name="anthropic",
        label="Anthropic Claude",
        base_url="https://api.anthropic.com/v1",
        kind="anthropic",
        env_var="ANTHROPIC_API_KEY",
        docs_url="https://docs.anthropic.com/en/api",
        models_path="/models",
        chat_path="/messages",
        auth_style="x-api-key",
        default_model="claude-sonnet-4-20250514",
        notes="Anthropic exposes GET /v1/models, so availability is verifiable.",
    ),
    "gemini": ProviderSpec(
        name="gemini",
        label="Google Gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        kind="google",
        env_var="GEMINI_API_KEY",
        docs_url="https://ai.google.dev/api",
        models_path="/models",
        chat_path="",
        auth_style="x-goog-api-key",
        default_model="gemini-2.0-flash",
        notes=(
            "Model ids are checked live against /v1beta/models. Guessing a model name "
            "is the usual cause of 404s with this provider."
        ),
    ),
    "ollama": ProviderSpec(
        name="ollama",
        label="Ollama (local)",
        base_url="http://127.0.0.1:11434/v1",
        kind="ollama",
        env_var="OLLAMA_HOST",
        docs_url="https://github.com/ollama/ollama/blob/main/docs/api.md",
        key_required=False,
        local=True,
        models_path="/models",
        chat_path="/chat/completions",
        auth_style="none",
        default_model="",
        notes=(
            "Talks to the OpenAI-compatible shim Ollama serves on /v1. The model list "
            "contains only models actually pulled on this machine."
        ),
    ),
}

#: A slot for any operator-supplied endpoint that speaks the OpenAI protocol.
CUSTOM_PROVIDER = ProviderSpec(
    name="custom",
    label="Custom OpenAI-compatible",
    base_url="",
    kind="openai_compatible",
    env_var="CUSTOM_AI_API_KEY",
    docs_url="",
    key_required=False,
    models_path="/models",
    chat_path="/chat/completions",
    auth_style="bearer",
    notes=(
        "Registered at runtime with its own base URL. Private addresses require an "
        "explicit allowlist entry; the SSRF guard applies to custom endpoints too."
    ),
)


def get_spec(name: str) -> ProviderSpec | None:
    key = (name or "").strip().lower()
    if key == "custom":
        return CUSTOM_PROVIDER
    return PROVIDERS.get(key)


def provider_names() -> list[str]:
    return sorted(PROVIDERS)


def all_specs() -> list[ProviderSpec]:
    return list(PROVIDERS.values())


#: Task presets, each a system prompt the operator can pick from the menu.
TASK_PRESETS: dict[str, dict[str, str]] = {
    "general": {
        "label": "General AI Assistant",
        "system": (
            "You are KINGDOM X, a precise technical assistant. Answer directly, state "
            "uncertainty explicitly, and never invent facts, versions or file paths."
        ),
    },
    "security": {
        "label": "Cybersecurity Assistant",
        "system": (
            "You are a defensive security engineer. Give concrete, actionable guidance "
            "for hardening, detection and response. Refuse requests that would help "
            "attack systems the user does not own. Before suggesting any active test, "
            "ask what the authorization basis is."
        ),
    },
    "code": {
        "label": "Code Assistant",
        "system": (
            "You are a senior software engineer. Produce complete, runnable code. State "
            "the language/framework versions you assume. Never leave placeholder "
            "comments where working code belongs."
        ),
    },
    "terminal": {
        "label": "Terminal Assistant",
        "system": (
            "You explain shell commands precisely. For each command, state exactly what "
            "it changes, what it deletes, and how to reverse it. Warn before anything "
            "destructive."
        ),
    },
    "report": {
        "label": "Security Report Generator",
        "system": (
            "You write security assessment reports. Structure: Scope, Method, Findings "
            "ordered by severity, Evidence, Remediation, Residual risk. Separate what "
            "was observed from what was inferred. Never inflate severity."
        ),
    },
    "log": {
        "label": "Log Analyzer",
        "system": (
            "You analyse log excerpts. Identify the failure mode, cite the exact line "
            "that shows it, and propose the smallest correct fix. Say when the excerpt "
            "is insufficient."
        ),
    },
    "explain": {
        "label": "Vulnerability Explainer",
        "system": (
            "You explain vulnerabilities for a defender: what the flaw is, which "
            "versions are affected, how it is exploited in principle, how to detect it, "
            "and how to remediate it. Do not produce working exploit code."
        ),
    },
    "network": {
        "label": "Network Report Assistant",
        "system": (
            "You interpret network diagnostics. Distinguish local faults from upstream "
            "ones, and recommend the single next diagnostic step rather than a list."
        ),
    },
    "docs": {
        "label": "Documentation Generator",
        "system": (
            "You write developer documentation in Markdown: purpose, prerequisites, "
            "exact commands, expected output, troubleshooting. No marketing language."
        ),
    },
    "translate": {
        "label": "Translation Assistant",
        "system": (
            "You translate technical text faithfully, preserving code, identifiers and "
            "command names untranslated. Label anything ambiguous instead of guessing."
        ),
    },
}


def task_preset(key: str) -> dict[str, str]:
    return TASK_PRESETS.get((key or "").strip().lower(), TASK_PRESETS["general"])


def preset_names() -> list[str]:
    return sorted(TASK_PRESETS)
