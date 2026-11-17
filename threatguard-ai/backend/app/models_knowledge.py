from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.config import KB_MAX_QUERY_CHARS, KB_RETRIEVAL_TOP_K


class KnowledgeDocumentResponse(BaseModel):
    document_id: str
    title: str
    original_filename: str
    content_hash: str
    content_type: str
    file_type: Literal["pdf", "txt", "markdown"]
    chunk_count: int = Field(ge=0)
    embedding_model: str
    embedding_dimension: int = Field(gt=0)
    uploaded_at: datetime
    uploaded_by: str | None = None

    model_config = ConfigDict(extra="ignore")


class KnowledgeDocumentListResponse(BaseModel):
    items: list[KnowledgeDocumentResponse]
    page: int
    page_size: int
    total: int


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=KB_MAX_QUERY_CHARS)
    top_k: int = Field(default=KB_RETRIEVAL_TOP_K, ge=1, le=20)

    model_config = ConfigDict(extra="forbid")

    @field_validator("query")
    @classmethod
    def query_must_contain_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Search query cannot be empty.")
        return value.strip()


class KnowledgeSearchResult(BaseModel):
    document_id: str
    filename: str
    source: str
    file_type: str | None
    page_number: int | None
    chunk_index: int
    excerpt: str
    relevance_score: float


class KnowledgeSearchResponse(BaseModel):
    query: str
    retrieval_mode: Literal["local_cosine", "atlas_vector_search"]
    results: list[KnowledgeSearchResult]

