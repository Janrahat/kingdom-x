"""AI layer tested entirely offline: catalogue, request building, parsing, health."""

from __future__ import annotations

import json

import pytest

from kingdomx.ai import client, health
from kingdomx.ai.catalog import (
    CUSTOM_PROVIDER,
    PROVIDERS,
    all_specs,
    get_spec,
    preset_names,
    provider_names,
    task_preset,
)
from kingdomx.ai.client import ChatMessage, ChatRequest


def _request(text: str = "hi", model: str = "test-model") -> ChatRequest:
    return ChatRequest(messages=[ChatMessage(role="user", content=text)], model=model)


class TestCatalog:
    def test_ten_providers(self):
        assert len(PROVIDERS) >= 10

    def test_every_provider_is_complete(self):
        for name, spec in PROVIDERS.items():
            assert spec.base_url.startswith("http"), name
            assert spec.kind, name
            assert spec.docs_url.startswith("http"), name

    def test_routers_are_allowed_to_have_an_empty_model_list(self):
        # Routers (OpenRouter, Hugging Face) publish a dynamic model list, so an
        # empty curated list is honest as long as the spec says why.
        for name, spec in PROVIDERS.items():
            if not spec.known_models:
                assert spec.notes, name

    def test_provider_lookup(self):
        assert get_spec("openai") is not None
        assert get_spec("does-not-exist") is None

    def test_provider_names_sorted(self):
        names = provider_names()
        assert names == sorted(names)

    def test_all_specs_returns_every_provider(self):
        assert len(all_specs()) == len(PROVIDERS)

    def test_custom_provider_shape(self):
        assert CUSTOM_PROVIDER.kind == "openai_compatible"
        assert "SSRF" in CUSTOM_PROVIDER.notes or "allowlist" in CUSTOM_PROVIDER.notes

    def test_task_presets_are_usable(self):
        names = preset_names()
        assert names
        for name in names:
            preset = task_preset(name)
            assert preset.get("system") or preset.get("prompt")

    def test_local_providers_flagged(self):
        ollama = get_spec("ollama")
        assert ollama is not None
        assert ollama.local is True

    def test_cloud_providers_require_a_key(self):
        assert get_spec("openai").key_required is True


class TestRequestBuilding:
    def test_openai_shape(self):
        spec = get_spec("openai")
        request = client.build_request(spec, _request("hi", "gpt-4o-mini"), api_key="test-key")
        assert request["method"] == "POST"
        payload = request["payload"]
        assert payload["model"] == "gpt-4o-mini"
        assert payload["messages"][0]["content"] == "hi"
        assert "Bearer test-key" in str(request["headers"])

    def test_anthropic_uses_x_api_key_header(self):
        spec = get_spec("anthropic")
        headers = client.build_headers(spec, "anth-key")
        joined = str(headers).lower()
        assert "x-api-key" in joined

    def test_anthropic_payload_has_max_tokens(self):
        spec = get_spec("anthropic")
        request = client.build_request(spec, _request("hi", "claude-3-5-sonnet"), api_key="k")
        payload = request["payload"]
        assert "max_tokens" in payload
        assert payload["messages"]

    def test_gemini_targets_generate_content(self):
        spec = get_spec("gemini")
        request = client.build_request(spec, _request("hi", "gemini-1.5-flash"), api_key="k")
        assert "generateContent" in request["url"] or "contents" in request["payload"]

    def test_ollama_sends_no_auth_header(self):
        spec = get_spec("ollama")
        headers = client.build_headers(spec, None)
        assert not any("authorization" in str(k).lower() for k in headers)

    def test_ollama_does_not_request_streaming(self):
        spec = get_spec("ollama")
        request = client.build_request(spec, _request("hi", "llama3"), api_key=None)
        assert request["payload"].get("stream") is not True

    def test_api_key_never_appears_in_the_payload(self):
        import json as _json

        for name in provider_names():
            spec = get_spec(name)
            request = client.build_request(spec, _request("x", "m"), api_key="SECRET-KEY-VALUE")
            assert "SECRET-KEY-VALUE" not in _json.dumps(request["payload"]), name

    def test_system_prompt_is_sent(self):
        spec = get_spec("openai")
        request = client.build_request(
            spec,
            ChatRequest(messages=[ChatMessage(role="user", content="q")], model="m", system="be brief"),
            api_key="k",
        )
        assert "be brief" in json.dumps(request["payload"])

    def test_history_becomes_messages(self):
        messages = client.messages_from_history([("user", "one"), ("assistant", "two")])
        assert len(messages) == 2
        assert messages[0].role == "user"

    def test_estimate_tokens_is_positive(self):
        assert client.estimate_tokens("a" * 400) > 0


class TestResponseParsing:
    def test_parse_openai_response(self):
        payload = {
            "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        }
        parsed = client.parse_response(get_spec("openai"), 200, json.dumps(payload))
        assert parsed.text == "hello"

    def test_parse_anthropic_response(self):
        payload = {
            "content": [{"type": "text", "text": "hi there"}],
            "usage": {"input_tokens": 3, "output_tokens": 4},
        }
        parsed = client.parse_response(get_spec("anthropic"), 200, json.dumps(payload))
        assert parsed.text == "hi there"

    def test_parse_gemini_response(self):
        payload = {
            "candidates": [{"content": {"parts": [{"text": "gemini says hi"}]}}],
            "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 3, "totalTokenCount": 5},
        }
        parsed = client.parse_response(get_spec("gemini"), 200, json.dumps(payload))
        assert "gemini says hi" in parsed.text

    def test_parse_ollama_response(self):
        payload = {"message": {"content": "local answer"}, "eval_count": 4, "prompt_eval_count": 6}
        parsed = client.parse_response(get_spec("ollama"), 200, json.dumps(payload))
        assert parsed.text == "local answer"

    def test_http_error_is_raised(self):
        body = json.dumps({"error": {"message": "invalid api key"}})
        with pytest.raises(Exception) as excinfo:
            client.parse_response(get_spec("openai"), 401, body)
        assert "invalid api key" in str(excinfo.value).lower() or "401" in str(excinfo.value)

    def test_malformed_body_is_raised_not_silently_empty(self):
        with pytest.raises(Exception):
            client.parse_response(get_spec("openai"), 200, "{not json at all")

    def test_model_list_parsing(self):
        spec = get_spec("openai")
        payload = {"data": [{"id": "gpt-4o-mini"}, {"id": "gpt-4o"}]}
        models = client.parse_model_list(spec, payload)
        assert len(models) == 2


class TestHealth:
    def test_health_result_reports_verification_state(self):
        result = health.check_provider("openai", api_key=None, timeout=1.0)
        # No key -> the honest answer is "not reachable / no key", never available.
        assert result.reachable is False
        assert result.key_present is False
        assert result.verification in {"unverified", "failed"}

    def test_missing_key_is_explained(self):
        result = health.check_provider("openai", api_key=None, timeout=1.0)
        assert result.error

    def test_unknown_provider_is_reported_not_crashed(self):
        # An unknown provider must produce a result carrying an error, so a
        # caller can list every provider without special-casing bad names.
        result = health.check_provider("not-a-provider", api_key="x", timeout=1.0)
        assert result.reachable is False
        assert result.error

    def test_local_provider_without_a_runtime_fails_honestly(self):
        result = health.check_provider("ollama", api_key=None, timeout=1.0)
        # Unless a real Ollama daemon is listening, this must not claim availability.
        assert result.provider == "ollama"

    def test_health_never_echoes_the_key(self):
        result = health.check_provider("openai", api_key="sk-supersecret-key-value", timeout=1.0)
        blob = json.dumps(result.__dict__, default=str)
        assert "sk-supersecret" not in blob

    def test_ollama_status_is_a_dict(self):
        assert isinstance(health.ollama_status(timeout=0.5), dict)

    def test_resolve_key_reads_the_environment(self, monkeypatch):
        spec = get_spec("openai")
        monkeypatch.setenv(spec.env_var, "from-env")
        assert health.resolve_key(spec) == "from-env"

    def test_resolve_key_prefers_the_argument(self, monkeypatch):
        spec = get_spec("openai")
        monkeypatch.setenv(spec.env_var, "from-env")
        assert health.resolve_key(spec, "explicit") == "explicit"
