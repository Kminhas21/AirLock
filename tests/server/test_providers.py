"""B17: the UI never sends `model`, so the default must resolve to something that exists."""
import providers


def reg(env):
    return providers._build_registry(env)


def test_default_is_claude_sonnet_when_openrouter_configured():
    assert providers.pick_default_model(reg({"OPENROUTER_API_KEY": "k"}), {}) == "claude-sonnet"


def test_default_falls_back_to_first_registered_when_claude_sonnet_absent():
    r = reg({"OLLAMA_BASE_URL": "http://localhost:1/v1"})
    assert "claude-sonnet" not in r
    assert providers.pick_default_model(r, {}) == "llama-local"


def test_env_override_wins_when_registered_and_is_ignored_when_not():
    r = reg({"OPENROUTER_API_KEY": "k"})
    assert providers.pick_default_model(r, {"SENTINEL_DEFAULT_MODEL": "gpt-4o"}) == "gpt-4o"
    assert providers.pick_default_model(r, {"SENTINEL_DEFAULT_MODEL": "nope"}) == "claude-sonnet"


def test_openrouter_base_url_is_configurable():
    r = reg({"OPENROUTER_API_KEY": "k", "OPENROUTER_BASE_URL": "http://127.0.0.1:9999/v1"})
    assert str(r["claude-sonnet"].client.base_url).startswith("http://127.0.0.1:9999/v1")


def test_empty_registry_keeps_legacy_default_name():
    assert providers.pick_default_model({}, {}) == "claude-sonnet"
