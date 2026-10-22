"""
Model provider registry for SENTINEL.

Centralizes all model configuration. Both OpenRouter and Ollama expose
OpenAI-compatible APIs, so the openai SDK is all we need. Adding a new
model is just adding one entry to MODELS.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()


@dataclass
class ModelProvider:
    """A configured model: which client to use and what model string to pass."""
    client: AsyncOpenAI
    model: str          # The model ID sent to the API (e.g. "anthropic/claude-sonnet-4-6")
    display_name: str   # Human-readable name for the frontend dropdown


def _build_registry(env: Mapping[str, str] = os.environ) -> dict[str, ModelProvider]:
    """Build the model registry from environment variables."""
    providers: dict[str, ModelProvider] = {}

    # --- OpenRouter models (one API key, many models) ---
    openrouter_key = env.get("OPENROUTER_API_KEY")
    if openrouter_key:
        or_client = AsyncOpenAI(
            base_url=env.get("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1",
            api_key=openrouter_key,
        )
        # Each entry: registry_key -> (client, model_string, display_name)
        # To add a model, just add one line here.
        or_models = {
            "claude-sonnet":  ("anthropic/claude-sonnet-4-6",       "Claude Sonnet 4"),
            "gpt-4o-mini":    ("openai/gpt-4o-mini",                "GPT-4o Mini"),
            "gpt-4o":         ("openai/gpt-4o",                     "GPT-4o"),
            "deepseek":       ("deepseek/deepseek-chat-v3-0324",    "DeepSeek V3"),
            "gemini-flash":   ("google/gemini-2.0-flash-001",       "Gemini 2.0 Flash"),
            "llama-70b":      ("meta-llama/llama-3.1-70b-instruct", "Llama 3.1 70B"),
        }
        for key, (model_id, name) in or_models.items():
            providers[key] = ModelProvider(or_client, model_id, name)

    # --- Ollama local models (free, no API key needed) ---
    # Only registered if OLLAMA_BASE_URL is set in .env
    # e.g. OLLAMA_BASE_URL=http://localhost:11434/v1
    ollama_url = env.get("OLLAMA_BASE_URL")
    if ollama_url:
        ollama_client = AsyncOpenAI(
            base_url=ollama_url,
            api_key="ollama",  # Ollama doesn't check this but the SDK requires it
        )
        providers["llama-local"] = ModelProvider(
            ollama_client, "llama3.1:8b", "Llama 3.1 8B (Local)"
        )

    return providers


# Module-level registry — built once on import
PROVIDERS = _build_registry()

def pick_default_model(registry: Mapping[str, ModelProvider], env: Mapping[str, str] = os.environ) -> str:
    """Model used when the frontend sends none (it never does).

    SENTINEL_DEFAULT_MODEL if registered, else "claude-sonnet" if registered, else the first
    registered model, so a deployment without OpenRouter still works from the UI.
    """
    wanted = env.get("SENTINEL_DEFAULT_MODEL")
    if wanted in registry:
        return wanted
    if "claude-sonnet" in registry or not registry:
        return "claude-sonnet"
    return next(iter(registry))


# Default model for when frontend doesn't specify one
DEFAULT_MODEL = pick_default_model(PROVIDERS)


def get_client(model_key: str) -> tuple[AsyncOpenAI, str]:
    """
    Look up a model by its registry key (e.g. "claude-sonnet", "deepseek").
    Returns (async_client, model_id_string) for use with the OpenAI SDK.
    Raises KeyError if the model key is not found.
    """
    provider = PROVIDERS[model_key]
    return provider.client, provider.model


def list_models() -> list[dict]:
    """
    Returns the list of available models for the GET /models endpoint.
    Frontend uses this to populate its model dropdown.
    """
    return [
        {"key": key, "display_name": p.display_name}
        for key, p in PROVIDERS.items()
    ]
