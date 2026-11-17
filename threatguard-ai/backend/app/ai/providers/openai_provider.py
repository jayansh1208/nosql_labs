from __future__ import annotations

from typing import Any

import httpx

from backend.app import config
from backend.app.ai.providers.base import LLMProvider, LLMResult, ProviderError, normalize_usage


class OpenAIProvider(LLMProvider):
    def __init__(self, *, api_key: str | None = None, model: str | None = None,
                 temperature: float | None = None, max_tokens: int | None = None,
                 timeout_seconds: float | None = None):
        self._api_key = config.OPENAI_API_KEY if api_key is None else api_key
        self._model = config.OPENAI_MODEL if model is None else model
        self._temperature = config.AI_TEMPERATURE if temperature is None else temperature
        self._max_tokens = config.AI_MAX_TOKENS if max_tokens is None else max_tokens
        self._timeout = config.AI_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
        if not self._api_key:
            raise ProviderError("missing_api_key", "OpenAI is selected but OPENAI_API_KEY is not configured.")
        if not self._model:
            raise ProviderError("missing_model", "Set OPENAI_MODEL before using the OpenAI provider.")

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, messages: list[dict[str, str]]) -> LLMResult:
        payload = {"model": self._model, "messages": messages,
                   "temperature": self._temperature, "max_tokens": self._max_tokens}
        timeout = httpx.Timeout(self._timeout, connect=min(self._timeout, 10.0))
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise ProviderError("provider_timeout", "OpenAI did not respond before the configured timeout.") from exc
        except httpx.ConnectError as exc:
            raise ProviderError("provider_unavailable", "OpenAI could not be reached. Check network connectivity.") from exc
        except httpx.RequestError as exc:
            raise ProviderError("provider_request_failed", "The OpenAI request could not be completed.") from exc

        if response.status_code == 401:
            raise ProviderError("invalid_api_key", "OpenAI rejected the configured API key.")
        if response.status_code == 429:
            raise ProviderError("provider_rate_limited", "OpenAI is rate limiting requests. Retry later.")
        if response.status_code >= 500:
            raise ProviderError("provider_unavailable", "OpenAI is temporarily unavailable.")
        if response.status_code >= 400:
            raise ProviderError("provider_request_rejected", "OpenAI rejected the request. Check the model and settings.")
        try:
            data: Any = response.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("invalid_provider_response", "OpenAI returned an invalid response.") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("empty_provider_response", "OpenAI returned an empty response.")
        return LLMResult(content=content.strip(),
                         token_usage=normalize_usage(data.get("usage"), prompt_key="prompt_tokens",
                                                     completion_key="completion_tokens"))
