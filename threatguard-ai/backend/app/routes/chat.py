from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.app import config
from backend.app.ai.chat_service import generate_chat_turn
from backend.app.ai.provider_factory import get_provider, provider_status
from backend.app.ai.providers.base import ProviderError
from backend.app.ai.rate_limit import consume_chat_rate_limit
from backend.app.database.connection import get_db
from backend.app.database.repositories import AuditLogRepository, ChatSessionRepository, serialize_document
from backend.app.models_chat import (
    ChatAskRequest, ChatMessageRequest, ChatSessionCreate, ChatSessionDetail,
    ChatSessionListResponse, ChatSessionRename, ChatTurnResponse,
    ProviderStatusResponse, ProviderTestResponse,
)
from backend.app.security import enforce_permission, get_current_user

router = APIRouter(prefix="/chat", tags=["chat"])


def _identity(user: dict[str, Any]) -> tuple[str, str, str]:
    return user["org_id"], user["tenant_id"], user["user_id"]


def _repo() -> ChatSessionRepository:
    return ChatSessionRepository(get_db())


def _audit(user: dict[str, Any], *, action: str, resource_type: str,
           resource_id: str, details: dict[str, Any] | None = None) -> None:
    org_id, tenant_id, user_id = _identity(user)
    AuditLogRepository(get_db()).log(
        org_id=org_id, tenant_id=tenant_id, actor_id=user_id,
        action=action, resource_type=resource_type, resource_id=resource_id, details=details or {},
    )


def _rate_check(user: dict[str, Any]) -> None:
    key = _identity(user)
    retry_after = consume_chat_rate_limit(key)
    if retry_after is not None:
        raise HTTPException(status_code=429, detail="Chat request limit reached. Try again shortly.",
                            headers={"Retry-After": str(retry_after)})


def _provider_exception(exc: ProviderError) -> HTTPException:
    return HTTPException(status_code=503, detail={"code": exc.code, "message": exc.message})


def _session_summary(item: dict[str, Any]) -> dict[str, Any]:
    session = serialize_document(item) or {}
    session.setdefault("title", "Conversation")
    session["message_count"] = int(session.get("message_count", len(session.get("messages", []))) or 0)
    return session


@router.post("/sessions", response_model=ChatSessionDetail, status_code=201)
def create_session(payload: ChatSessionCreate, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id, user_id = _identity(current_user)
    now = datetime.now(timezone.utc)
    session_id = f"chat-{uuid.uuid4().hex}"
    session = _repo().create_for_user({
        "org_id": org_id, "tenant_id": tenant_id, "user_id": user_id,
        "session_id": session_id, "title": payload.title, "messages": [], "message_count": 0,
        "provider": None, "model": None, "status": "active", "last_message_at": None,
        "created_at": now,
    })
    _audit(current_user, action="chat_session_created", resource_type="chat_session", resource_id=session_id)
    return {**_session_summary(session), "messages": [], "total_messages": 0, "message_offset": 0}


@router.get("/sessions", response_model=ChatSessionListResponse)
def list_sessions(
    page: int = Query(default=1, ge=1), page_size: int = Query(default=20, ge=1, le=100),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id, user_id = _identity(current_user)
    result = _repo().list_for_user(org_id=org_id, tenant_id=tenant_id, user_id=user_id,
                                   page=page, page_size=page_size)
    return {**result, "items": [_session_summary(item) for item in result["items"]]}


@router.get("/sessions/{session_id}", response_model=ChatSessionDetail)
def get_session(
    session_id: str, message_offset: int = Query(default=0, ge=0),
    message_limit: int = Query(default=50, ge=1, le=100),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id, user_id = _identity(current_user)
    session = _repo().get_for_user(session_id, org_id=org_id, tenant_id=tenant_id, user_id=user_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Chat session not found")
    messages = session.get("messages", [])
    summary = _session_summary(session)
    return {**summary, "messages": messages[message_offset:message_offset + message_limit],
            "total_messages": len(messages), "message_offset": message_offset}


@router.patch("/sessions/{session_id}", response_model=ChatSessionDetail)
def rename_session(
    session_id: str, payload: ChatSessionRename,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id, user_id = _identity(current_user)
    session = _repo().rename_for_user(session_id, payload.title, org_id=org_id,
                                      tenant_id=tenant_id, user_id=user_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Chat session not found")
    _audit(current_user, action="chat_session_renamed", resource_type="chat_session", resource_id=session_id)
    messages = session.get("messages", [])
    return {**_session_summary(session), "messages": messages[-50:],
            "total_messages": len(messages), "message_offset": max(0, len(messages) - 50)}


@router.delete("/sessions/{session_id}")
def delete_session(session_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, str]:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id, user_id = _identity(current_user)
    if not _repo().delete_for_user(session_id, org_id=org_id, tenant_id=tenant_id, user_id=user_id):
        raise HTTPException(status_code=404, detail="Chat session not found")
    _audit(current_user, action="chat_session_deleted", resource_type="chat_session", resource_id=session_id)
    return {"session_id": session_id, "status": "deleted"}


async def _send_message(session_id: str, payload: ChatMessageRequest,
                        current_user: dict[str, Any], *, rate_checked: bool = False) -> dict[str, Any]:
    enforce_permission(current_user, "write_threats")
    if not rate_checked:
        _rate_check(current_user)
    org_id, tenant_id, user_id = _identity(current_user)
    repo = _repo()
    session = repo.get_for_user(session_id, org_id=org_id, tenant_id=tenant_id, user_id=user_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Chat session not found")
    try:
        provider = get_provider()
        turn = await generate_chat_turn(
            get_db(), org_id=org_id, tenant_id=tenant_id, question=payload.content,
            history=session.get("messages", []), use_rag=payload.use_rag,
            include_scanner=payload.include_scanner_context, provider=provider,
        )
    except ProviderError as exc:
        _audit(current_user, action="chat_message_failed", resource_type="chat_session",
               resource_id=session_id, details={"error_code": exc.code})
        raise _provider_exception(exc) from exc
    except Exception as exc:
        _audit(current_user, action="chat_message_failed", resource_type="chat_session",
               resource_id=session_id, details={"error_code": "chat_processing_failed"})
        raise HTTPException(status_code=503, detail={"code": "chat_processing_failed",
                            "message": "The chat request could not be completed."}) from exc

    now = datetime.now(timezone.utc)
    user_message = {"role": "user", "content": payload.content, "timestamp": now}
    assistant_message = {
        "role": "assistant", "content": turn.answer, "timestamp": now,
        "provider": turn.provider, "model": turn.model, "citations": turn.citations,
        "scanner_sources": turn.scanner_sources, "token_usage": turn.token_usage,
    }
    if not repo.append_messages(session_id, [user_message, assistant_message], org_id=org_id,
                                tenant_id=tenant_id, user_id=user_id,
                                provider=turn.provider, model=turn.model):
        raise HTTPException(status_code=404, detail="Chat session not found")
    if session.get("message_count", 0) == 0 and session.get("title") == "New chat":
        repo.rename_for_user(session_id, payload.content[:60], org_id=org_id,
                             tenant_id=tenant_id, user_id=user_id)
    _audit(current_user, action="chat_message_sent", resource_type="chat_session", resource_id=session_id,
           details={"message_length": len(payload.content), "provider": turn.provider,
                    "model": turn.model, "citation_count": len(turn.citations)})
    return {
        "session_id": session_id, "answer": turn.answer, "citations": turn.citations,
        "scanner_sources": turn.scanner_sources, "provider": turn.provider,
        "model": turn.model, "token_usage": turn.token_usage, "rag_enabled": turn.rag_enabled,
    }


@router.post("/sessions/{session_id}/messages", response_model=ChatTurnResponse)
async def send_message(
    session_id: str, payload: ChatMessageRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return await _send_message(session_id, payload, current_user)


@router.post("/ask", response_model=ChatTurnResponse)
async def ask(payload: ChatAskRequest, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(current_user, "write_threats")
    _rate_check(current_user)
    org_id, tenant_id, user_id = _identity(current_user)
    session_id = payload.session_id
    if session_id is None:
        now = datetime.now(timezone.utc)
        session_id = f"chat-{uuid.uuid4().hex}"
        created = _repo().create_for_user({
            "org_id": org_id, "tenant_id": tenant_id, "user_id": user_id,
            "session_id": session_id, "title": payload.content[:60], "messages": [],
            "message_count": 0, "provider": None, "model": None,
            "status": "active", "last_message_at": None, "created_at": now,
        })
        if created is None:
            raise HTTPException(status_code=503, detail="Could not create a chat session.")
        _audit(current_user, action="chat_session_created", resource_type="chat_session", resource_id=session_id)
    return await _send_message(session_id, payload, current_user, rate_checked=True)


@router.get("/providers", response_model=ProviderStatusResponse)
def get_provider_status(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(current_user, "read_threats")
    return provider_status()


@router.post("/providers/test", response_model=ProviderTestResponse)
async def test_provider(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    # A provider test can create an external request and potential usage, so it is
    # deliberately restricted to roles that can send chat messages.
    enforce_permission(current_user, "write_threats")
    _rate_check(current_user)
    try:
        provider = get_provider()
        result = await provider.test_connection()
    except ProviderError as exc:
        _audit(current_user, action="ai_provider_test_failed", resource_type="ai_provider",
               resource_id=provider_status().get("provider", "unknown"), details={"error_code": exc.code})
        raise _provider_exception(exc) from exc
    _audit(current_user, action="ai_provider_test_succeeded", resource_type="ai_provider",
           resource_id=provider.provider_name, details={"model": provider.model_name})
    return {"provider": provider.provider_name, "model": provider.model_name,
            "connected": True, "response": result.content[:200], "token_usage": result.token_usage}
