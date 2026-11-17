from __future__ import annotations

from typing import Any

import httpx

from backend.app import config
from backend.app.ai.providers.base import LLMProvider, LLMResult, ProviderError


class GeminiProvider(LLMProvider):
    """Google Gemini provider using the generateContent REST API."""

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str:
        return config.GEMINI_MODEL

    def _build_payload(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        system_instructions = []
        contents = []

        for message in messages:
            role = message.get("role", "")
            content = message.get("content", "")

            if not isinstance(content, str) or not content.strip():
                continue

            if role == "system":
                system_instructions.append(content)
            elif role == "user":
                contents.append({"role": "user", "parts": [{"text": content}]})
            elif role == "assistant":
                contents.append({"role": "model", "parts": [{"text": content}]})
            else:
                raise ProviderError(
                    "invalid_message_role",
                    f"Unsupported chat message role: {role or 'empty'}.",
                )

        if not contents:
            raise ProviderError("empty_prompt", "Gemini requires at least one message.")

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": config.AI_TEMPERATURE,
                "maxOutputTokens": config.AI_MAX_TOKENS,
            },
        }

        if system_instructions:
            payload["systemInstruction"] = {
                "parts": [{"text": "\n\n".join(system_instructions)}]
            }

        return payload

    async def generate(self, messages: list[dict[str, str]]) -> LLMResult:
        api_key = config.GEMINI_API_KEY.strip()

        if not api_key:
            raise ProviderError(
                "missing_api_key",
                "GEMINI_API_KEY must be configured to use Gemini.",
            )

        model = self.model_name.strip()

        if not model:
            raise ProviderError("missing_model", "GEMINI_MODEL must be configured.")

        payload = self._build_payload(messages)

        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent"
        )

        timeout = httpx.Timeout(
            config.AI_TIMEOUT_SECONDS,
            connect=min(config.AI_TIMEOUT_SECONDS, 10.0),
        )

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    url,
                    headers={
                        "Content-Type": "application/json",
                        "x-goog-api-key": api_key,
                    },
                    json=payload,
                )

        except httpx.TimeoutException as exc:
            raise ProviderError(
                "provider_timeout",
                "Gemini did not respond before the configured timeout.",
            ) from exc

        except httpx.ConnectError as exc:
            raise ProviderError(
                "provider_unavailable",
                "Gemini could not be reached. Check network connectivity.",
            ) from exc

        except httpx.RequestError as exc:
            raise ProviderError(
                "provider_request_failed",
                "The Gemini request could not be completed.",
            ) from exc

        if response.status_code in (401, 403):
            raise ProviderError(
                "invalid_api_key",
                "Gemini rejected the API key or its permissions.",
            )

        if response.status_code == 429:
            raise ProviderError(
                "provider_rate_limited",
                "Gemini is rate limiting requests. Check your quota and retry later.",
            )

        if response.status_code == 404:
            raise ProviderError(
                "model_unavailable",
                f"Gemini model '{model}' was not found or is unavailable.",
            )

        if response.status_code >= 500:
            raise ProviderError(
                "provider_unavailable",
                "Gemini is temporarily unavailable. Try again later.",
            )

        if response.status_code >= 400:
            raise ProviderError(
                "provider_request_rejected",
                "Gemini rejected the request. Check the model and request settings.",
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError(
                "invalid_provider_response",
                "Gemini returned an unreadable response.",
            ) from exc

        candidates = data.get("candidates") or []

        if not candidates:
            feedback = data.get("promptFeedback", {})
            if feedback.get("blockReason"):
                raise ProviderError(
                    "content_blocked",
                    "Gemini blocked the prompt under its safety policies.",
                )

            raise ProviderError(
                "empty_provider_response",
                "Gemini returned no response candidates.",
            )

        parts = candidates[0].get("content", {}).get("parts", [])

        content = "".join(
            part.get("text", "")
            for part in parts
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ).strip()

        if not content:
            raise ProviderError(
                "empty_provider_response",
                "Gemini returned an empty text response.",
            )

        usage = data.get("usageMetadata", {})
        prompt_tokens = usage.get("promptTokenCount")
        completion_tokens = usage.get("candidatesTokenCount")

        token_usage = None

        if isinstance(prompt_tokens, int) and isinstance(completion_tokens, int):
            token_usage = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": usage.get(
                    "totalTokenCount",
                    prompt_tokens + completion_tokens,
                ),
            }

        return LLMResult(content=content, token_usage=token_usage)
