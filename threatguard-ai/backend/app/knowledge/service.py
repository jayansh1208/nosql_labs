from __future__ import annotations

import mimetypes
import uuid
from datetime import datetime, timezone
from typing import Any

import numpy as np
from pymongo.errors import DuplicateKeyError
from pymongo.database import Database

from backend.app.config import (
    EMBEDDING_MODEL, KB_ATLAS_VECTOR_INDEX, KB_ATLAS_VECTOR_SEARCH_ENABLED,
    KB_CHUNK_OVERLAP, KB_CHUNK_SIZE, KB_MAX_UPLOAD_BYTES, KB_RETRIEVAL_TOP_K,
)
from backend.app.database.repositories import KnowledgeBaseRepository
from backend.app.knowledge.documents import chunk_pages, extract_document, sha256_content
from backend.app.knowledge.embeddings import EmbeddingProvider, get_embedding_provider


class DuplicateDocumentError(ValueError):
    def __init__(self, document_id: str):
        super().__init__("This document has already been uploaded to this tenant.")
        self.document_id = document_id


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _normalized_vector(values: list[float], dimension: int) -> list[float]:
    vector = np.asarray(values, dtype=np.float64)
    if vector.shape != (dimension,):
        raise RuntimeError(f"Expected an embedding with {dimension} dimensions.")
    norm = float(np.linalg.norm(vector))
    if not np.isfinite(norm) or norm == 0:
        raise RuntimeError("Embedding provider returned an invalid or zero vector.")
    return (vector / norm).astype(np.float32).tolist()


def ingest_document(
    db: Database, *, org_id: str, tenant_id: str, filename: str, data: bytes,
    provider: EmbeddingProvider | None = None, uploaded_by: str | None = None,
) -> dict[str, Any]:
    if len(data) > KB_MAX_UPLOAD_BYTES:
        raise ValueError(f"File exceeds the {KB_MAX_UPLOAD_BYTES}-byte upload limit.")
    content_hash = sha256_content(data)
    repo = KnowledgeBaseRepository(db)
    duplicate = repo.find_duplicate(org_id=org_id, tenant_id=tenant_id, content_hash=content_hash)
    if duplicate:
        raise DuplicateDocumentError(duplicate["document_id"])

    file_type, pages = extract_document(filename, data)
    chunks = chunk_pages(pages, chunk_size=KB_CHUNK_SIZE, overlap=KB_CHUNK_OVERLAP)
    embedding_provider = provider or get_embedding_provider()
    vectors = embedding_provider.embed([chunk.text for chunk in chunks])
    if len(vectors) != len(chunks):
        raise RuntimeError("Embedding provider returned an inconsistent number or size of vectors.")
    vectors = [_normalized_vector(vector, embedding_provider.dimension) for vector in vectors]

    document_id = _new_id("doc")
    now = datetime.now(timezone.utc)
    original_filename = filename.replace("\\", "/").split("/")[-1].strip()
    content_type = mimetypes.guess_type(original_filename)[0] or "application/octet-stream"
    document = {
        "org_id": org_id, "tenant_id": tenant_id, "document_id": document_id,
        "title": original_filename, "original_filename": original_filename,
        "content_hash": content_hash, "content_type": content_type, "file_type": file_type,
        "chunk_count": len(chunks), "embedding_model": embedding_provider.model_name,
        "embedding_dimension": embedding_provider.dimension,
        "created_at": now, "updated_at": now, "uploaded_at": now,
        "source": original_filename, "uploaded_by": uploaded_by,
    }
    chunk_records = []
    for chunk, vector in zip(chunks, vectors):
        record = {
            "org_id": org_id, "tenant_id": tenant_id, "chunk_id": _new_id("chunk"),
            "doc_id": document_id, "content": chunk.text, "chunk_index": chunk.chunk_index,
            "page_number": chunk.page_number, "embedding": [float(value) for value in vector],
            "embedding_model": embedding_provider.model_name,
            "embedding_dimension": embedding_provider.dimension,
            "created_at": now, "updated_at": now,
        }
        chunk_records.append(record)

    try:
        repo.create_document(document)
    except DuplicateKeyError as exc:
        existing = repo.find_duplicate(org_id=org_id, tenant_id=tenant_id, content_hash=content_hash)
        if existing:
            raise DuplicateDocumentError(existing["document_id"]) from exc
        raise
    try:
        db["kb_chunks"].insert_many(chunk_records, ordered=True)
    except Exception:
        # Roll back only these newly created records inside the caller's tenant.
        db["kb_chunks"].delete_many({"org_id": org_id, "tenant_id": tenant_id, "doc_id": document_id})
        db["kb_documents"].delete_one({"org_id": org_id, "tenant_id": tenant_id, "document_id": document_id})
        raise
    return document


def _format_match(chunk: dict[str, Any], document: dict[str, Any], score: float) -> dict[str, Any]:
    return {
        "document_id": document["document_id"],
        "filename": document.get("original_filename") or document.get("title"),
        "source": document.get("source") or document.get("original_filename") or document.get("title"),
        "file_type": document.get("file_type"), "page_number": chunk.get("page_number"),
        "chunk_index": chunk.get("chunk_index"), "excerpt": chunk.get("content", ""),
        "relevance_score": round(float(score), 6),
    }


def _atlas_search(db: Database, *, org_id: str, tenant_id: str, vector: list[float],
                  provider: EmbeddingProvider, top_k: int) -> list[dict[str, Any]]:
    pipeline = [{"$vectorSearch": {
        "index": KB_ATLAS_VECTOR_INDEX, "path": "embedding", "queryVector": vector,
        "numCandidates": max(top_k * 20, 100), "limit": top_k,
        "filter": {"org_id": {"$eq": org_id}, "tenant_id": {"$eq": tenant_id},
                   "embedding_model": {"$eq": provider.model_name},
                   "embedding_dimension": {"$eq": provider.dimension}},
    }}, {"$project": {"org_id": 1, "tenant_id": 1, "doc_id": 1, "content": 1,
                     "chunk_index": 1, "page_number": 1, "score": {"$meta": "vectorSearchScore"}}}]
    matches = list(db["kb_chunks"].aggregate(pipeline))
    docs = {doc["document_id"]: doc for doc in db["kb_documents"].find({
        "org_id": org_id, "tenant_id": tenant_id,
        "document_id": {"$in": list({item["doc_id"] for item in matches})},
    })}
    return [_format_match(item, docs[item["doc_id"]], item["score"])
            for item in matches if item["doc_id"] in docs]


def search_documents(
    db: Database, *, org_id: str, tenant_id: str, query: str,
    top_k: int | None = None, provider: EmbeddingProvider | None = None,
) -> list[dict[str, Any]]:
    if not org_id or not tenant_id:
        raise ValueError("Authenticated organization and tenant context are required.")
    normalized_query = query.strip()
    if not normalized_query:
        raise ValueError("Search query cannot be empty.")
    embedding_provider = provider or get_embedding_provider()
    k = max(1, min(int(top_k or KB_RETRIEVAL_TOP_K), 20))
    query_vector = _normalized_vector(embedding_provider.embed([normalized_query])[0], embedding_provider.dimension)
    if KB_ATLAS_VECTOR_SEARCH_ENABLED:
        return _atlas_search(db, org_id=org_id, tenant_id=tenant_id, vector=query_vector,
                             provider=embedding_provider, top_k=k)

    query_array = np.asarray(query_vector, dtype=np.float64)
    query_norm = float(np.linalg.norm(query_array))
    if query_norm == 0:
        raise RuntimeError("Query embedding has zero length.")
    chunks = db["kb_chunks"].find({
        "org_id": org_id, "tenant_id": tenant_id,
        "embedding_model": embedding_provider.model_name,
        "embedding_dimension": embedding_provider.dimension,
    })
    scored: list[tuple[float, dict[str, Any]]] = []
    for chunk in chunks:
        vector = np.asarray(chunk.get("embedding", []), dtype=np.float64)
        if vector.shape != query_array.shape:
            continue
        norm = float(np.linalg.norm(vector))
        if norm == 0:
            continue
        similarity = float(np.clip(np.dot(query_array, vector) / (query_norm * norm), -1.0, 1.0))
        scored.append((similarity, chunk))
        scored.sort(key=lambda row: (-row[0], row[1].get("doc_id", ""), row[1].get("chunk_index", 0)))
        del scored[k:]
    document_ids = list({chunk["doc_id"] for _, chunk in scored})
    documents = {doc["document_id"]: doc for doc in db["kb_documents"].find({
        "org_id": org_id, "tenant_id": tenant_id, "document_id": {"$in": document_ids},
    })}
    return [_format_match(chunk, documents[chunk["doc_id"]], score)
            for score, chunk in scored if chunk["doc_id"] in documents]
