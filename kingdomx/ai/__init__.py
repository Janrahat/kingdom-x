"""AI Intelligence Center.

Public surface:

* :mod:`kingdomx.ai.catalog` — provider and task-preset catalogue
* :mod:`kingdomx.ai.client` — request builders and response parsers
* :mod:`kingdomx.ai.health` — real availability checks
* :mod:`kingdomx.ai.manager` — model registry, usage accounting, provider CRUD
* :mod:`kingdomx.ai.assistant` — high-level chat with presets and local fallback
"""

from kingdomx.ai.catalog import (
    PROVIDERS,
    ProviderSpec,
    all_specs,
    get_spec,
    preset_names,
    provider_names,
    task_preset,
)
from kingdomx.ai.client import ChatMessage, ChatRequest, ChatResponse, build_request, parse_response
from kingdomx.ai.health import HealthResult, check_provider
from kingdomx.ai.manager import AIManager

__all__ = [
    "PROVIDERS",
    "ProviderSpec",
    "all_specs",
    "get_spec",
    "preset_names",
    "provider_names",
    "task_preset",
    "ChatMessage",
    "ChatRequest",
    "ChatResponse",
    "build_request",
    "parse_response",
    "HealthResult",
    "check_provider",
    "AIManager",
]
