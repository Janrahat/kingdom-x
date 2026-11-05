"""Regression tests for the public AI CLI surface."""

from kingdomx.cli.main import build_parser


def test_ai_providers_command_parses():
    args = build_parser().parse_args(["ai", "providers"])
    assert args.command == "ai"
    assert args.ai_command == "providers"


def test_ai_set_key_command_parses_without_accepting_key_as_argument():
    args = build_parser().parse_args(["ai", "set-key", "openrouter"])
    assert args.provider == "openrouter"
    assert not hasattr(args, "api_key")


def test_ai_provider_check_deep_json_parses():
    args = build_parser().parse_args(
        ["ai", "check", "--provider", "openrouter", "--deep", "--json"]
    )
    assert args.provider == "openrouter"
    assert args.deep is True
    assert args.json is True


def test_ai_models_filter_parses():
    args = build_parser().parse_args(
        ["ai", "models", "--provider", "openrouter", "--available"]
    )
    assert args.provider == "openrouter"
    assert args.available is True


def test_ai_chat_prompt_and_model_parse():
    args = build_parser().parse_args(
        ["ai", "chat", "--provider", "openrouter", "--model", "provider/model",
         "--prompt", "hello", "--json"]
    )
    assert args.provider == "openrouter"
    assert args.model == "provider/model"
    assert args.prompt == "hello"
    assert args.json is True
