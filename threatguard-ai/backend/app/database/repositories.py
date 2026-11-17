from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from bson import ObjectId
from bson.errors import InvalidId
from pymongo.database import Database

from backend.app.database.connection import get_db


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def serialize_document(document: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if document is None:
        return None
    result = dict(document)
    if "_id" in result:
        result["_id"] = str(result["_id"])
    return result


class BaseRepository:
    def __init__(self, db: Database, collection_name: str):
        self.db = db
        self.collection = db[collection_name]

    def _ensure_tenant_context(self, org_id: str | None, tenant_id: str | None) -> None:
        if not org_id:
            raise ValueError("org_id is required")
        if not tenant_id:
            raise ValueError("tenant_id is required")

    def _build_identifier_filter(self, record_id: str, *, org_id: Optional[str] = None, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        filters: Dict[str, Any]
        try:
            filters = {"_id": ObjectId(record_id)}
        except (TypeError, InvalidId):
            filters = {"threat_id": record_id}
        if org_id is not None:
            filters["org_id"] = org_id
        if tenant_id is not None:
            filters["tenant_id"] = tenant_id
        return filters

    def _tenant_filter(self, org_id: str | None = None, tenant_id: str | None = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query: Dict[str, Any] = {}
        if org_id is not None:
            query["org_id"] = org_id
        if tenant_id is not None:
            query["tenant_id"] = tenant_id
        if extra:
            query.update(extra)
        return query

    def _serialize_list(self, records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [serialize_document(record) for record in records]

    def create_one(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        payload.setdefault("created_at", now)
        payload["updated_at"] = now
        result = self.collection.insert_one(payload)
        return self.collection.find_one({"_id": result.inserted_id})

    def list_paginated(
        self,
        *,
        query: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 20,
        sort_field: str = "created_at",
        sort_order: int = -1,
    ) -> Dict[str, Any]:
        filters = query or {}
        total = self.collection.count_documents(filters)
        records = list(
            self.collection.find(filters).sort(sort_field, sort_order).skip((page - 1) * page_size).limit(page_size)
        )
        return {
            "items": self._serialize_list(records),
            "page": page,
            "page_size": page_size,
            "total": total,
        }

    def get_by_id(self, record_id: str, *, org_id: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        filters = self._build_identifier_filter(record_id, org_id=org_id, tenant_id=tenant_id)
        return self.collection.find_one(filters)

    def update_by_id(self, record_id: str, update_fields: Dict[str, Any], *, org_id: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        filters = self._build_identifier_filter(record_id, org_id=org_id, tenant_id=tenant_id)
        update_fields = dict(update_fields)
        update_fields["updated_at"] = utc_now()
        self.collection.update_one(filters, {"$set": update_fields})
        return self.collection.find_one(filters)

    def delete_by_id(self, record_id: str, *, org_id: Optional[str] = None, tenant_id: Optional[str] = None) -> bool:
        filters = self._build_identifier_filter(record_id, org_id=org_id, tenant_id=tenant_id)
        result = self.collection.delete_one(filters)
        return result.deleted_count > 0


class OrganizationRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "organizations")

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not payload.get("org_id"):
            raise ValueError("org_id is required")
        return super().create_one(payload)

    def list(self, *, org_id: Optional[str] = None, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        query = {"org_id": org_id} if org_id else {}
        return self.list_paginated(query=query, page=page, page_size=page_size)


class TenantRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "tenants")

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_tenant_context(payload.get("org_id"), payload.get("tenant_id"))
        return super().create_one(payload)

    def list(self, *, org_id: str, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id is required")
        return self.list_paginated(query={"org_id": org_id}, page=page, page_size=page_size)


class UserRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "users")

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_tenant_context(payload.get("org_id"), payload.get("tenant_id"))
        if not payload.get("email"):
            raise ValueError("email is required")
        if not payload.get("password_hash"):
            raise ValueError("password_hash is required")
        return super().create_one(payload)

    def get_by_email(self, email: str, *, org_id: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        query: Dict[str, Any] = {"email": email}
        if org_id is not None:
            query["org_id"] = org_id
        if tenant_id is not None:
            query["tenant_id"] = tenant_id
        return self.collection.find_one(query)

    def get_by_user_id(self, user_id: str, *, org_id: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        query: Dict[str, Any] = {"user_id": user_id}
        if org_id is not None:
            query["org_id"] = org_id
        if tenant_id is not None:
            query["tenant_id"] = tenant_id
        return self.collection.find_one(query)

    def list(self, *, org_id: str, tenant_id: str, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        self._ensure_tenant_context(org_id, tenant_id)
        return self.list_paginated(query={"org_id": org_id, "tenant_id": tenant_id}, page=page, page_size=page_size)


class AuditLogRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "audit_logs")

    def log(
        self,
        *,
        org_id: str,
        tenant_id: str,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._ensure_tenant_context(org_id, tenant_id)
        audit_id = f"audit-{utc_now().strftime('%Y%m%d%H%M%S%f')}"
        payload = {
            "org_id": org_id,
            "tenant_id": tenant_id,
            "audit_id": audit_id,
            "actor_id": actor_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
            "created_at": utc_now(),
        }
        return super().create_one(payload)


class RevokedTokenRepository(BaseRepository):
    """Stores JWT identifiers only; raw bearer tokens are never persisted."""

    def __init__(self, db: Database):
        super().__init__(db, "revoked_tokens")

    def revoke(self, *, token_id: str, org_id: str, tenant_id: str, user_id: str,
               expires_at: datetime) -> None:
        self._ensure_tenant_context(org_id, tenant_id)
        self.collection.update_one(
            {"token_id": token_id},
            {"$setOnInsert": {
                "token_id": token_id,
                "org_id": org_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "expires_at": expires_at,
                "created_at": utc_now(),
            }},
            upsert=True,
        )

    def is_revoked(self, token_id: str) -> bool:
        return self.collection.find_one({"token_id": token_id}, {"_id": 1}) is not None


class ThreatRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "threats")

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_tenant_context(payload.get("org_id"), payload.get("tenant_id"))
        valid_statuses = {"Anticipated", "Active", "Evolving", "Resolved"}
        if payload.get("lifecycle_status") not in valid_statuses:
            raise ValueError("Invalid threat lifecycle_status")
        if payload.get("severity") not in {"low", "medium", "high", "critical"}:
            raise ValueError("Invalid threat severity")
        return super().create_one(payload)

    def list(self, *, org_id: str, tenant_id: str, page: int = 1, page_size: int = 20, severity: Optional[str] = None, lifecycle_status: Optional[str] = None) -> Dict[str, Any]:
        self._ensure_tenant_context(org_id, tenant_id)
        query = {"org_id": org_id, "tenant_id": tenant_id}
        if severity:
            query["severity"] = severity
        if lifecycle_status:
            query["lifecycle_status"] = lifecycle_status
        return self.list_paginated(query=query, page=page, page_size=page_size)

    def get_by_id(self, record_id: str, *, org_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_tenant_context(org_id, tenant_id)
        return super().get_by_id(record_id, org_id=org_id, tenant_id=tenant_id)

    def update_status(self, record_id: str, *, org_id: str, tenant_id: str, lifecycle_status: str) -> Optional[Dict[str, Any]]:
        self._ensure_tenant_context(org_id, tenant_id)
        if lifecycle_status not in {"Anticipated", "Active", "Evolving", "Resolved"}:
            raise ValueError("Invalid threat lifecycle_status")
        updated = super().update_by_id(record_id, {"lifecycle_status": lifecycle_status}, org_id=org_id, tenant_id=tenant_id)
        if updated is None:
            raise ValueError("Threat not found for the provided tenant context")
        return updated

    def delete(self, record_id: str, *, org_id: str, tenant_id: str) -> bool:
        self._ensure_tenant_context(org_id, tenant_id)
        return super().delete_by_id(record_id, org_id=org_id, tenant_id=tenant_id)


class ScanRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "scan_results")

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_tenant_context(payload.get("org_id"), payload.get("tenant_id"))
        return super().create_one(payload)

    def list(self, *, org_id: str, tenant_id: str, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        self._ensure_tenant_context(org_id, tenant_id)
        return self.list_paginated(query={"org_id": org_id, "tenant_id": tenant_id}, page=page, page_size=page_size)


class MitigationRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "mitigations")

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_tenant_context(payload.get("org_id"), payload.get("tenant_id"))
        return super().create_one(payload)

    def list(self, *, org_id: str, tenant_id: str, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        self._ensure_tenant_context(org_id, tenant_id)
        return self.list_paginated(query={"org_id": org_id, "tenant_id": tenant_id}, page=page, page_size=page_size)


class KnowledgeBaseRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "kb_documents")

    def create_document(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_tenant_context(payload.get("org_id"), payload.get("tenant_id"))
        return super().create_one(payload)

    def list_documents(self, *, org_id: str, tenant_id: str, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        self._ensure_tenant_context(org_id, tenant_id)
        return self.list_paginated(query={"org_id": org_id, "tenant_id": tenant_id}, page=page, page_size=page_size)

    def find_duplicate(self, *, org_id: str, tenant_id: str, content_hash: str) -> Optional[Dict[str, Any]]:
        self._ensure_tenant_context(org_id, tenant_id)
        return self.collection.find_one({"org_id": org_id, "tenant_id": tenant_id, "content_hash": content_hash})

    def get_document(self, document_id: str, *, org_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_tenant_context(org_id, tenant_id)
        return self.collection.find_one({"org_id": org_id, "tenant_id": tenant_id, "document_id": document_id})

    def delete_document(self, document_id: str, *, org_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Delete only a document and chunks matching the caller's full tenant scope."""
        self._ensure_tenant_context(org_id, tenant_id)
        query = {"org_id": org_id, "tenant_id": tenant_id, "document_id": document_id}
        document = self.collection.find_one(query)
        if document is None:
            return None
        chunk_query = {"org_id": org_id, "tenant_id": tenant_id, "doc_id": document_id}
        self.db["kb_chunks"].delete_many(chunk_query)
        deleted = self.collection.delete_one(query)
        return document if deleted.deleted_count == 1 else None

    def list_chunks(self, *, org_id: str, tenant_id: str, document_id: str) -> list[Dict[str, Any]]:
        self._ensure_tenant_context(org_id, tenant_id)
        return list(self.db["kb_chunks"].find({
            "org_id": org_id, "tenant_id": tenant_id, "doc_id": document_id,
        }).sort("chunk_index", 1))

    def document_count(self, *, org_id: str, tenant_id: str) -> int:
        self._ensure_tenant_context(org_id, tenant_id)
        return self.collection.count_documents({"org_id": org_id, "tenant_id": tenant_id})


class ChatSessionRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "chat_sessions")

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_tenant_context(payload.get("org_id"), payload.get("tenant_id"))
        return super().create_one(payload)

    def list(self, *, org_id: str, tenant_id: str, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        self._ensure_tenant_context(org_id, tenant_id)
        return self.list_paginated(query={"org_id": org_id, "tenant_id": tenant_id}, page=page, page_size=page_size)

    def create_for_user(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_tenant_context(payload.get("org_id"), payload.get("tenant_id"))
        if not payload.get("user_id") or not payload.get("session_id"):
            raise ValueError("user_id and session_id are required")
        return super().create_one(payload)

    def list_for_user(self, *, org_id: str, tenant_id: str, user_id: str,
                      page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        self._ensure_tenant_context(org_id, tenant_id)
        if not user_id:
            raise ValueError("user_id is required")
        query = {"org_id": org_id, "tenant_id": tenant_id, "user_id": user_id}
        total = self.collection.count_documents(query)
        cursor = (self.collection.find(query, {"messages": 0})
                  .sort([("updated_at", -1), ("session_id", 1)])
                  .skip((page - 1) * page_size).limit(page_size))
        return {"items": self._serialize_list(cursor), "page": page, "page_size": page_size, "total": total}

    def get_for_user(self, session_id: str, *, org_id: str, tenant_id: str,
                     user_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_tenant_context(org_id, tenant_id)
        if not user_id:
            raise ValueError("user_id is required")
        return self.collection.find_one({"session_id": session_id, "org_id": org_id,
                                         "tenant_id": tenant_id, "user_id": user_id})

    def rename_for_user(self, session_id: str, title: str, *, org_id: str,
                        tenant_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_tenant_context(org_id, tenant_id)
        query = {"session_id": session_id, "org_id": org_id, "tenant_id": tenant_id, "user_id": user_id}
        self.collection.update_one(query, {"$set": {"title": title, "updated_at": utc_now()}})
        return self.collection.find_one(query)

    def append_messages(self, session_id: str, messages: list[Dict[str, Any]], *, org_id: str,
                        tenant_id: str, user_id: str, provider: str, model: str) -> bool:
        self._ensure_tenant_context(org_id, tenant_id)
        now = utc_now()
        query = {"session_id": session_id, "org_id": org_id, "tenant_id": tenant_id, "user_id": user_id}
        result = self.collection.update_one(query, {
            "$push": {"messages": {"$each": messages}},
            "$inc": {"message_count": len(messages)},
            "$set": {"provider": provider, "model": model, "updated_at": now, "last_message_at": now},
        })
        return result.matched_count == 1

    def delete_for_user(self, session_id: str, *, org_id: str, tenant_id: str, user_id: str) -> bool:
        self._ensure_tenant_context(org_id, tenant_id)
        query = {"session_id": session_id, "org_id": org_id, "tenant_id": tenant_id, "user_id": user_id}
        return self.collection.delete_one(query).deleted_count == 1


class AuditRepository(BaseRepository):
    def __init__(self, db: Database):
        super().__init__(db, "audit_logs")

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_tenant_context(payload.get("org_id"), payload.get("tenant_id"))
        return super().create_one(payload)

    def list(self, *, org_id: str, tenant_id: str, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        self._ensure_tenant_context(org_id, tenant_id)
        return self.list_paginated(query={"org_id": org_id, "tenant_id": tenant_id}, page=page, page_size=page_size)


def get_default_db() -> Database:
    return get_db()
