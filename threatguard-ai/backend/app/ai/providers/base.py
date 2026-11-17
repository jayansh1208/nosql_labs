from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LLMResult:
    content: str
    token_usage: dict[str, int] | None = None


class ProviderError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class LLMProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str: ...

    @property
    @abstractmethod
    def model_name(self) -> str: ...

    @abstractmethod
    async def generate(self, messages: list[dict[str, str]]) -> LLMResult: ...

    async def test_connection(self) -> LLMResult:
        return await self.generate([
            {"role": "system", "content": "Respond with the single word OK."},
            {"role": "user", "content": "Connection test. Reply OK."},
        ])


def normalize_usage(value: Any, *, prompt_key: str, completion_key: str) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    usage: dict[str, int] = {}
    for target, source in (("prompt_tokens", prompt_key), ("completion_tokens", completion_key)):
        item = value.get(source)
        if isinstance(item, int) and item >= 0:
            usage[target] = item
    if len(usage) == 2:
        usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
    return usage or None
