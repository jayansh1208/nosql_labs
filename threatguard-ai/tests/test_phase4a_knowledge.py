from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from backend.app.database.schema import apply_all_schema_and_indexes
from backend.app.database.repositories import KnowledgeBaseRepository
from backend.app.knowledge.documents import chunk_pages, extract_document
from backend.app.knowledge.embeddings import EmbeddingProvider
from backend.app.knowledge.service import DuplicateDocumentError, ingest_document, search_documents


class TestSemanticProvider(EmbeddingProvider):
    """Small deterministic fixture for unit tests only; never selected by the app."""

    @property
    def model_name(self) -> str:
        return "test-only-two-dimensional-provider"

    @property
    def dimension(self) -> int:
        return 2

    def embed(self, texts):
        vectors = []
        for text in texts:
            lowered = text.lower()
            vectors.append([1.0, 0.0] if any(word in lowered for word in ("malware", "phishing", "incident")) else [0.0, 1.0])
        return vectors


@pytest.fixture
def rag_db():
    database_name = os.getenv("THREATGUARD_TEST_DB", f"threatguard_rag_test_{uuid.uuid4().hex}")
    client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27030"), serverSelectionTimeoutMS=5000)
    db = client[database_name]
    for collection_name in db.list_collection_names():
        db[collection_name].delete_many({})
    apply_all_schema_and_indexes(db)
    try:
        yield db
    finally:
        for collection_name in db.list_collection_names():
            db[collection_name].delete_many({})
        client.close()


def test_txt_and_markdown_extraction_and_normalization():
    file_type, pages = extract_document("note.txt", b"  Incident\r\n\r\n  response  \t plan ")
    assert file_type == "txt"
    assert pages == [(None, "Incident\n\nresponse plan")]

    file_type, pages = extract_document("guide.md", b"# Malware\n\nContainment steps")
    assert file_type == "markdown"
    assert "# Malware" in pages[0][1]


def _pdf_with_text(text: str) -> bytes:
    # Build a tiny valid one-page PDF fixture without a binary fixture file.
    stream = f"BT /F1 12 Tf 30 250 Td ({text}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    result = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, 1):
        offsets.append(len(result))
        result.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref_offset = len(result)
    result.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode())
    result.extend(f"trailer\n<< /Root 1 0 R /Size {len(offsets)} >>\nstartxref\n{xref_offset}\n%%EOF".encode())
    return bytes(result)


def test_pdf_extraction_preserves_page_number():
    file_type, pages = extract_document("incident.pdf", _pdf_with_text("Incident response plan"))
    assert file_type == "pdf"
    assert pages == [(1, "Incident response plan")]


def test_chunking_is_ordered_and_overlaps():
    chunks = chunk_pages([(None, "0123456789ABCDEFGHIJ")], chunk_size=10, overlap=3)
    assert [item.chunk_index for item in chunks] == list(range(len(chunks)))
    assert chunks[0].text[-3:] == chunks[1].text[:3]
    assert len(chunks) >= 2


@pytest.mark.parametrize(("filename", "data"), [("script.exe", b"not text"), ("empty.txt", b""), ("bad.pdf", b"not a pdf")])
def test_invalid_or_empty_documents_are_rejected(filename, data):
    with pytest.raises(ValueError):
        extract_document(filename, data)


def test_upload_size_limit_is_enforced(monkeypatch, rag_db):
    import backend.app.knowledge.service as knowledge_service

    monkeypatch.setattr(knowledge_service, "KB_MAX_UPLOAD_BYTES", 8)
    with pytest.raises(ValueError, match="upload limit"):
        ingest_document(rag_db, org_id="org-a", tenant_id="tenant-a", filename="large.txt", data=b"0123456789",
                        provider=TestSemanticProvider())


def test_ingestion_stores_model_vectors_counts_and_source_metadata(rag_db):
    provider = TestSemanticProvider()
    document = ingest_document(
        rag_db, org_id="org-a", tenant_id="tenant-a", filename="advisory.md",
        data=b"TEST DATA: Malware response uses isolation and evidence preservation.", provider=provider,
    )
    chunks = list(rag_db.kb_chunks.find({"org_id": "org-a", "tenant_id": "tenant-a", "doc_id": document["document_id"]}))
    assert document["original_filename"] == "advisory.md"
    assert document["file_type"] == "markdown"
    assert document["chunk_count"] == len(chunks) == 1
    assert document["embedding_model"] == provider.model_name
    assert document["embedding_dimension"] == 2
    assert chunks[0]["page_number"] is None
    assert len(chunks[0]["embedding"]) == 2
    assert chunks[0]["content"].startswith("TEST DATA:")


def test_duplicate_detection_is_scoped_to_tenant(rag_db):
    provider = TestSemanticProvider()
    data = b"TEST DATA: Unique malware note for duplicate handling."
    first = ingest_document(rag_db, org_id="org-a", tenant_id="tenant-a", filename="one.txt", data=data, provider=provider)
    with pytest.raises(DuplicateDocumentError):
        ingest_document(rag_db, org_id="org-a", tenant_id="tenant-a", filename="copy.txt", data=data, provider=provider)
    second_tenant = ingest_document(rag_db, org_id="org-a", tenant_id="tenant-b", filename="copy.txt", data=data, provider=provider)
    assert first["content_hash"] == second_tenant["content_hash"]
    assert first["document_id"] != second_tenant["document_id"]


def test_semantic_retrieval_returns_cosine_rank_and_source(rag_db):
    provider = TestSemanticProvider()
    malware = ingest_document(rag_db, org_id="org-a", tenant_id="tenant-a", filename="malware.md",
                              data=b"TEST DATA: Malware incident containment and response.", provider=provider)
    ingest_document(rag_db, org_id="org-a", tenant_id="tenant-a", filename="replication.txt",
                    data=b"TEST DATA: MongoDB replica set election and replication.", provider=provider)
    results = search_documents(rag_db, org_id="org-a", tenant_id="tenant-a", query="malware incident", provider=provider)
    assert results[0]["document_id"] == malware["document_id"]
    assert results[0]["relevance_score"] == pytest.approx(1.0)
    assert results[0]["filename"] == "malware.md"
    assert results[0]["source"] == "malware.md"
    assert results[0]["chunk_index"] == 0


def test_retrieval_and_delete_are_tenant_scoped(rag_db):
    provider = TestSemanticProvider()
    a_doc = ingest_document(rag_db, org_id="org-a", tenant_id="tenant-a", filename="a.txt",
                            data=b"TEST DATA: Phishing incident response.", provider=provider)
    ingest_document(rag_db, org_id="org-a", tenant_id="tenant-b", filename="b.txt",
                    data=b"TEST DATA: Phishing incident response.", provider=provider)
    assert len(search_documents(rag_db, org_id="org-a", tenant_id="tenant-a", query="phishing", provider=provider)) == 1

    repo_delete = KnowledgeBaseRepository(rag_db)
    assert repo_delete.delete_document(a_doc["document_id"], org_id="org-a", tenant_id="tenant-b") is None
    assert rag_db.kb_documents.count_documents({"org_id": "org-a", "tenant_id": "tenant-a", "document_id": a_doc["document_id"]}) == 1
    assert rag_db.kb_chunks.count_documents({"org_id": "org-a", "tenant_id": "tenant-a", "doc_id": a_doc["document_id"]}) == 1


def test_api_auth_tenant_isolation_delete_audit_and_search(
    monkeypatch, rag_db, create_test_user, login_test_user
):
    import backend.app.database.connection as db_connection
    import backend.app.main as app_module
    import backend.app.routes.auth as auth_routes
    import backend.app.routes.knowledge as knowledge_routes
    import backend.app.security as security_module

    monkeypatch.setattr(auth_routes, "get_db", lambda: rag_db)
    monkeypatch.setattr(security_module, "get_db", lambda: rag_db)
    monkeypatch.setattr(db_connection, "get_db", lambda: rag_db)
    monkeypatch.setattr(knowledge_routes, "get_db", lambda: rag_db)

    provider = TestSemanticProvider()
    real_search = knowledge_routes.search_documents
    real_ingest = knowledge_routes.ingest_document

    monkeypatch.setattr(
        knowledge_routes,
        "ingest_document",
        lambda *args, **kwargs: real_ingest(
            *args, **{**kwargs, "provider": provider}
        ),
    )
    monkeypatch.setattr(
        knowledge_routes,
        "search_documents",
        lambda *args, **kwargs: real_search(
            *args, **{**kwargs, "provider": provider}
        ),
    )

    client = TestClient(app_module.app)

    unauthorized = client.get("/knowledge/documents")
    assert unauthorized.status_code == 401

    def create_token(tenant_id: str, email: str) -> str:
        registration = client.post(
            "/auth/register",
            json={
                "org_id": "org-a",
                "tenant_id": tenant_id,
                "email": email,
                "password": "S3cur3!Pass",
                "display_name": tenant_id,
                "role": "security_analyst",
            },
        )
        assert registration.status_code == 403

        create_test_user(
            rag_db,
            org_id="org-a",
            tenant_id=tenant_id,
            email=email,
            display_name=tenant_id,
        )

        headers = login_test_user(client, email=email)
        return headers["Authorization"].replace("Bearer ", "")

    token_a = create_token("tenant-a", "rag-a@example.com")
    token_b = create_token("tenant-b", "rag-b@example.com")

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    uploaded = client.post(
        "/knowledge/documents",
        headers=headers_a,
        files={
            "file": (
                "test-advisory.md",
                b"TEST DATA: Malware incident response steps.",
                "text/markdown",
            )
        },
    )
    assert uploaded.status_code == 201, uploaded.text

    doc = uploaded.json()
    assert doc["embedding_model"] == provider.model_name
    assert doc["chunk_count"] == 1

    assert client.get(
        "/knowledge/documents", headers=headers_a
    ).json()["total"] == 1

    assert client.get(
        "/knowledge/documents", headers=headers_b
    ).json()["total"] == 0

    assert client.get(
        f"/knowledge/documents/{doc['document_id']}",
        headers=headers_b,
    ).status_code == 404

    search = client.post(
        "/knowledge/search",
        headers=headers_a,
        json={"query": "malware response", "top_k": 2},
    )
    assert search.status_code == 200, search.text
    assert search.json()["results"][0]["source"] == "test-advisory.md"
    assert search.json()["retrieval_mode"] == "local_cosine"

    invalid_search = client.post(
        "/knowledge/search",
        headers=headers_a,
        json={"query": "malware", "tenant_id": "tenant-b"},
    )
    assert invalid_search.status_code == 422

    cross_delete = client.delete(
        f"/knowledge/documents/{doc['document_id']}",
        headers=headers_b,
    )
    assert cross_delete.status_code == 404

    assert rag_db.kb_chunks.count_documents(
        {"tenant_id": "tenant-a", "doc_id": doc["document_id"]}
    ) == 1

    deleted = client.delete(
        f"/knowledge/documents/{doc['document_id']}",
        headers=headers_a,
    )
    assert deleted.status_code == 200

    assert rag_db.kb_chunks.count_documents(
        {"tenant_id": "tenant-a", "doc_id": doc["document_id"]}
    ) == 0

    actions = {
        row["action"]
        for row in rag_db.audit_logs.find({"tenant_id": "tenant-a"})
    }
    assert {
        "knowledge_document_uploaded",
        "knowledge_search",
        "knowledge_document_deleted",
    }.issubset(actions)


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("THREATGUARD_RUN_EMBEDDING_INTEGRATION") != "1", reason="Set THREATGUARD_RUN_EMBEDDING_INTEGRATION=1 to load the real model")
def test_real_embedding_generation_dimension_and_normalization():
    import numpy as np
    from backend.app.knowledge.embeddings import get_embedding_provider

    provider = get_embedding_provider()
    vectors = provider.embed(["A synthetic test note about phishing response.", "A test note on MongoDB replication."])
    assert provider.model_name == "sentence-transformers/all-MiniLM-L6-v2"
    assert provider.dimension == len(vectors[0]) == 384
    np.testing.assert_allclose(np.linalg.norm(np.asarray(vectors), axis=1), [1.0, 1.0], atol=1e-5)
