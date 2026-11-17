from __future__ import annotations

import functools
from typing import Any

from backend.app import config
from backend.app.ai.providers.base import LLMProvider, ProviderError
from backend.app.ai.providers.openai_provider import OpenAIProvider
from backend.app.ai.providers.ollama_provider import OllamaProvider
from backend.app.ai.providers.gemini_provider import GeminiProvider


@functools.lru_cache(maxsize=1)
def get_provider() -> LLMProvider:
    """Instantiate the selected provider.

    Never fall back to another provider silently – raise ``ProviderError``
    for unknown ``AI_PROVIDER`` values.
    """
    if config.AI_PROVIDER == "openai":
        return OpenAIProvider()
    if config.AI_PROVIDER == "ollama":
        return OllamaProvider()
    if config.AI_PROVIDER == "gemini":
        return GeminiProvider()
    raise ProviderError("invalid_provider", "AI_PROVIDER must be one of 'openai', 'ollama', or 'gemini'.")


def provider_status() -> dict[str, Any]:
    """Return a concise status dict for the configured provider.

    The dict never contains the raw API key value.
    """
    if config.AI_PROVIDER == "openai":
        configured = bool(config.OPENAI_API_KEY and config.OPENAI_MODEL)
        return {
            "provider": "openai",
            "model": config.OPENAI_MODEL,
            "configured": configured,
            "api_key_configured": bool(config.OPENAI_API_KEY),
            "status": "configured" if configured else "configuration_required",
        }
    if config.AI_PROVIDER == "ollama":
        configured = bool(config.OLLAMA_BASE_URL and config.OLLAMA_MODEL)
        return {
            "provider": "ollama",
            "model": config.OLLAMA_MODEL,
            "configured": configured,
            "api_key_configured": False,
            "status": "configured" if configured else "configuration_required",
        }
    if config.AI_PROVIDER == "gemini":
        configured = bool(config.GEMINI_API_KEY and config.GEMINI_MODEL)
        return {
            "provider": "gemini",
            "model": config.GEMINI_MODEL,
            "configured": configured,
            "api_key_configured": bool(config.GEMINI_API_KEY),
            "status": "configured" if configured else "configuration_required",
        }
    # Fallback for unexpected values
    return {
        "provider": config.AI_PROVIDER or "unset",
        "model": None,
        "configured": False,
        "api_key_configured": False,
        "status": "invalid_configuration",
    }
