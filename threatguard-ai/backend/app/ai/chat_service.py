from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable

from pymongo.database import Database

from backend.app import config
from backend.app.ai.context_manager import load_scanner_evidence, scanner_context_requested
from backend.app.ai.prompt_builder import build_prompt, remove_unknown_citation_tags
from backend.app.ai.provider_factory import get_provider
from backend.app.ai.providers.base import LLMProvider, ProviderError
from backend.app.knowledge.service import search_documents


@dataclass(frozen=True)
class ChatTurn:
    answer: str
    citations: list[dict[str, Any]]
    scanner_sources: list[dict[str, Any]]
    provider: str
    model: str
    token_usage: dict[str, int] | None
    rag_enabled: bool


def _select_citations(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen_sources: set[tuple[str, int | None]] = set()
    for result in results:
        try:
            score = float(result.get("relevance_score", 0.0))
        except (ValueError, TypeError):
            continue
        if score < config.CHAT_RAG_MIN_SIMILARITY:
            continue
        doc_id = str(result.get("document_id") or "")
        source_key = (doc_id, result.get("page_number"))
        if not doc_id or source_key in seen_sources:
            continue
        seen_sources.add(source_key)
        selected.append({
            "citation_id": f"S{len(selected) + 1}", "document_id": doc_id,
            "title": str(result.get("filename") or result.get("source") or "Untitled document"),
            "source": str(result.get("source") or result.get("filename") or "Unknown source"),
            "page_number": result.get("page_number"),
            "chunk_index": result.get("chunk_index"),
            "excerpt": str(result.get("excerpt") or "")[:2000],
            "relevance_score": score,
        })
    return selected


async def generate_chat_turn(
    db: Database, *, org_id: str, tenant_id: str, question: str,
    history: list[dict[str, Any]], use_rag: bool = True,
    include_scanner: bool = False, provider: LLMProvider | None = None,
    retriever: Callable[..., list[dict[str, Any]]] | None = None,
) -> ChatTurn:
    active_provider = provider or get_provider()
    rag_enabled = bool(use_rag and config.CHAT_RAG_ENABLED)
    citations: list[dict[str, Any]] = []
    if rag_enabled:
        retrieval = retriever or search_documents
        try:
            results = await asyncio.to_thread(
                retrieval, db, org_id=org_id, tenant_id=tenant_id,
                query=question, top_k=config.CHAT_RAG_TOP_K,
            )
        except Exception as exc:
            raise ProviderError("rag_unavailable", "Knowledge retrieval failed; no answer was generated.") from exc
        citations = _select_citations(results)

    use_scanner = scanner_context_requested(question, explicit=include_scanner)
    scanner_sources = await asyncio.to_thread(
        load_scanner_evidence, db, org_id=org_id, tenant_id=tenant_id,
    ) if use_scanner else []
    messages, included_citations, included_scanner = build_prompt(
        question=question, history=history, citations=citations, scanner_sources=scanner_sources,
        max_context_chars=config.AI_CONTEXT_MAX_CHARS, history_window=config.AI_HISTORY_WINDOW,
        rag_requested=rag_enabled, scanner_requested=use_scanner,
    )
    result = await active_provider.generate(messages)
    if not isinstance(result.content, str) or not result.content.strip():
        raise ProviderError("invalid_provider_response", "The configured AI provider returned an invalid answer.")
    answer = remove_unknown_citation_tags(
        result.content.strip()[:20000], {source["citation_id"] for source in included_citations},
    )
    if rag_enabled and not included_citations:
        answer = "No relevant knowledge-base source was retrieved. General guidance: " + answer
    return ChatTurn(
        answer=answer, citations=included_citations, scanner_sources=included_scanner,
        provider=active_provider.provider_name, model=active_provider.model_name,
        token_usage=result.token_usage, rag_enabled=rag_enabled,
    )
