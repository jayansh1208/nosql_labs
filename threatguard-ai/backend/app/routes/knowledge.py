from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from backend.app.config import (
    KB_ATLAS_VECTOR_SEARCH_ENABLED, KB_MAX_QUERY_CHARS,
    KB_MAX_UPLOAD_BYTES,
)
from backend.app.database.connection import get_db
from backend.app.database.repositories import AuditLogRepository, KnowledgeBaseRepository
from backend.app.knowledge.service import DuplicateDocumentError, ingest_document, search_documents
from backend.app.models_knowledge import (
    KnowledgeDocumentListResponse, KnowledgeDocumentResponse, KnowledgeSearchRequest,
    KnowledgeSearchResponse,
)
from backend.app.security import enforce_permission, get_current_user

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


def _context(current_user: dict[str, Any]) -> tuple[str, str, str]:
    return current_user["org_id"], current_user["tenant_id"], current_user["user_id"]


@router.post("/documents", response_model=KnowledgeDocumentResponse, status_code=201)
async def upload_document(
    file: UploadFile = File(...),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id, actor_id = _context(current_user)
    if file.size is not None and file.size > KB_MAX_UPLOAD_BYTES:
        await file.close()
        raise HTTPException(status_code=413, detail=f"File exceeds the {KB_MAX_UPLOAD_BYTES}-byte upload limit.")
    data = await file.read(KB_MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(data) > KB_MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {KB_MAX_UPLOAD_BYTES}-byte upload limit.")
    try:
        document = ingest_document(get_db(), org_id=org_id, tenant_id=tenant_id,
                                   filename=file.filename or "", data=data, uploaded_by=actor_id)
    except DuplicateDocumentError as exc:
        raise HTTPException(status_code=409, detail={"message": str(exc), "document_id": exc.document_id}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Document embedding or storage failed.") from exc
    AuditLogRepository(get_db()).log(
        org_id=org_id, tenant_id=tenant_id, actor_id=actor_id,
        action="knowledge_document_uploaded", resource_type="kb_document",
        resource_id=document["document_id"],
        details={"filename": document["original_filename"], "file_type": document["file_type"],
                 "chunk_count": document["chunk_count"], "content_hash": document["content_hash"]},
    )
    return document


@router.get("/documents", response_model=KnowledgeDocumentListResponse)
def list_documents(
    page: int = Query(default=1, ge=1), page_size: int = Query(default=20, ge=1, le=100),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id, _ = _context(current_user)
    return KnowledgeBaseRepository(get_db()).list_documents(
        org_id=org_id, tenant_id=tenant_id, page=page, page_size=page_size,
    )


@router.get("/documents/{document_id}", response_model=KnowledgeDocumentResponse)
def get_document(document_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id, _ = _context(current_user)
    document = KnowledgeBaseRepository(get_db()).get_document(document_id, org_id=org_id, tenant_id=tenant_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


@router.delete("/documents/{document_id}")
def delete_document(document_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id, actor_id = _context(current_user)
    repo = KnowledgeBaseRepository(get_db())
    existing = repo.get_document(document_id, org_id=org_id, tenant_id=tenant_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Document not found")
    uploaded_by = existing.get("uploaded_by")
    if uploaded_by and uploaded_by != actor_id and current_user.get("role") not in {"tenant_admin", "super_admin"}:
        raise HTTPException(status_code=403, detail="Only the document owner or a tenant administrator can delete this document")
    if not uploaded_by and current_user.get("role") not in {"tenant_admin", "super_admin"}:
        raise HTTPException(status_code=403, detail="Only a tenant administrator can delete a legacy document with no owner")
    document = repo.delete_document(document_id, org_id=org_id, tenant_id=tenant_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    AuditLogRepository(get_db()).log(
        org_id=org_id, tenant_id=tenant_id, actor_id=actor_id,
        action="knowledge_document_deleted", resource_type="kb_document",
        resource_id=document_id,
        details={"filename": document.get("original_filename"), "chunk_count": document.get("chunk_count", 0)},
    )
    return {"document_id": document_id, "status": "deleted"}


@router.post("/search", response_model=KnowledgeSearchResponse)
def search_knowledge(
    payload: KnowledgeSearchRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id, actor_id = _context(current_user)
    query = payload.query.strip()
    if len(query) > KB_MAX_QUERY_CHARS:
        raise HTTPException(status_code=422, detail=f"Query exceeds the {KB_MAX_QUERY_CHARS}-character limit.")
    try:
        results = search_documents(get_db(), org_id=org_id, tenant_id=tenant_id,
                                   query=query, top_k=payload.top_k)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Semantic retrieval is unavailable.") from exc
    AuditLogRepository(get_db()).log(
        org_id=org_id, tenant_id=tenant_id, actor_id=actor_id,
        action="knowledge_search", resource_type="kb_search", resource_id="semantic-search",
        details={"query_length": len(query), "top_k": payload.top_k, "result_count": len(results)},
    )
    return {"query": query,
            "retrieval_mode": "atlas_vector_search" if KB_ATLAS_VECTOR_SEARCH_ENABLED else "local_cosine",
            "results": results}
