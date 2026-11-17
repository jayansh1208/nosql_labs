from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.config import AI_MAX_MESSAGE_CHARS


class ChatSessionCreate(BaseModel):
    title: str = Field(default="New chat", max_length=100)
    model_config = ConfigDict(extra="forbid")

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Session title cannot be empty.")
        return value.strip()


class ChatSessionRename(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    model_config = ConfigDict(extra="forbid")

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Session title cannot be empty.")
        return value.strip()


class ChatMessageRequest(BaseModel):
    content: str = Field(min_length=1, max_length=AI_MAX_MESSAGE_CHARS)
    use_rag: bool = True
    include_scanner_context: bool = False
    model_config = ConfigDict(extra="forbid")

    @field_validator("content")
    @classmethod
    def content_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Message cannot be empty.")
        return value.strip()


class ChatAskRequest(ChatMessageRequest):
    session_id: str | None = Field(default=None, max_length=100)


class ChatCitation(BaseModel):
    citation_id: str
    document_id: str
    title: str
    source: str
    page_number: int | None
    chunk_index: int | None
    excerpt: str
    relevance_score: float


class ScannerSource(BaseModel):
    scan_id: str | None
    generated_at: datetime | str | None
    host: str | None = None
    summary: str
    completeness: dict | None = None
    findings: list[dict] = Field(default_factory=list)


class ChatTurnResponse(BaseModel):
    session_id: str
    answer: str
    citations: list[ChatCitation]
    scanner_sources: list[ScannerSource]
    provider: str
    model: str
    token_usage: dict[str, int] | None
    rag_enabled: bool


class StoredChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str
    timestamp: datetime
    provider: str | None = None
    model: str | None = None
    citations: list[ChatCitation] = Field(default_factory=list)
    scanner_sources: list[ScannerSource] = Field(default_factory=list)
    token_usage: dict[str, int] | None = None


class ChatSessionSummary(BaseModel):
    session_id: str
    title: str
    provider: str | None = None
    model: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    last_message_at: datetime | None = None
    message_count: int = 0


class ChatSessionListResponse(BaseModel):
    items: list[ChatSessionSummary]
    page: int
    page_size: int
    total: int


class ChatSessionDetail(ChatSessionSummary):
    messages: list[StoredChatMessage]
    total_messages: int
    message_offset: int


class ProviderStatusResponse(BaseModel):
    provider: str
    model: str | None
    configured: bool
    api_key_configured: bool
    status: str


class ProviderTestResponse(BaseModel):
    provider: str
    model: str
    connected: bool
    response: str
    token_usage: dict[str, int] | None
