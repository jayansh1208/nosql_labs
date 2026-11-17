from __future__ import annotations

from typing import Any

import httpx

from backend.app import config
from backend.app.ai.providers.base import LLMProvider, LLMResult, ProviderError, normalize_usage


class OllamaProvider(LLMProvider):
    def __init__(self, *, base_url: str | None = None, model: str | None = None,
                 temperature: float | None = None, max_tokens: int | None = None,
                 timeout_seconds: float | None = None):
        self._base_url = (config.OLLAMA_BASE_URL if base_url is None else base_url).rstrip("/")
        self._model = config.OLLAMA_MODEL if model is None else model
        self._temperature = config.AI_TEMPERATURE if temperature is None else temperature
        self._max_tokens = config.AI_MAX_TOKENS if max_tokens is None else max_tokens
        self._timeout = config.AI_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
        if not self._base_url.startswith(("http://", "https://")):
            raise ProviderError("invalid_ollama_url", "OLLAMA_BASE_URL must be an HTTP or HTTPS URL.")
        if not self._model:
            raise ProviderError("missing_model", "Set OLLAMA_MODEL before using the Ollama provider.")

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, messages: list[dict[str, str]]) -> LLMResult:
        timeout = httpx.Timeout(self._timeout, connect=min(self._timeout, 5.0))
        payload = {"model": self._model, "messages": messages, "stream": False,
                   "options": {"temperature": self._temperature, "num_predict": self._max_tokens}}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(f"{self._base_url}/api/chat", json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderError("provider_timeout", "Ollama did not respond before the configured timeout.") from exc
        except httpx.ConnectError as exc:
            raise ProviderError("provider_unavailable", "Ollama is unavailable. Start Ollama or select another provider.") from exc
        except httpx.RequestError as exc:
            raise ProviderError("provider_request_failed", "The Ollama request could not be completed.") from exc

        if response.status_code == 404:
            raise ProviderError("ollama_model_unavailable", f"The configured Ollama model '{self._model}' is not available locally. Install it using 'ollama pull {self._model}'.")
        if response.status_code >= 500:
            raise ProviderError("provider_unavailable", "Ollama is temporarily unavailable.")
        if response.status_code >= 400:
            raise ProviderError("provider_request_rejected", "Ollama rejected the request. Check its model and settings.")
        try:
            data: Any = response.json()
            content = data["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ProviderError("invalid_provider_response", "Ollama returned an invalid response.") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("empty_provider_response", "Ollama returned an empty response.")
        return LLMResult(content=content.strip(),
                         token_usage=normalize_usage(data, prompt_key="prompt_eval_count",
                                                     completion_key="eval_count"))
