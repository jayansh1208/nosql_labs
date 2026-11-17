from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from pymongo import ASCENDING
from pymongo.database import Database

THREAT_LIFECYCLE_STATUSES = ["Anticipated", "Active", "Evolving", "Resolved"]
THREAT_SEVERITY_VALUES = ["low", "medium", "high", "critical"]
SCAN_STATUSES = ["pending", "running", "completed", "failed"]
MITIGATION_EXECUTION_STATUSES = ["pending", "in_progress", "completed", "failed", "blocked"]

SCHEMA_MAP: Dict[str, Dict[str, Any]] = {
    "organizations": {
        "bsonType": "object",
        "required": ["org_id", "name", "status", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "name": {"bsonType": "string"},
            "description": {"bsonType": ["string", "null"]},
            "status": {"bsonType": "string", "enum": ["active", "inactive"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "tenants": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "name", "status", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "name": {"bsonType": "string"},
            "status": {"bsonType": "string", "enum": ["active", "inactive", "suspended"]},
            "metadata": {"bsonType": ["object", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "users": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "user_id", "email", "display_name", "role", "status", "password_hash", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "user_id": {"bsonType": "string"},
            "email": {"bsonType": "string"},
            "display_name": {"bsonType": "string"},
            "role": {"bsonType": "string", "enum": ["super_admin", "tenant_admin", "security_analyst", "security_operator", "auditor"]},
            "status": {"bsonType": "string", "enum": ["active", "disabled"]},
            "password_hash": {"bsonType": "string"},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "threats": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "threat_id", "title", "description", "severity", "lifecycle_status", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "threat_id": {"bsonType": "string"},
            "title": {"bsonType": "string"},
            "description": {"bsonType": "string"},
            "severity": {"bsonType": "string", "enum": THREAT_SEVERITY_VALUES},
            "lifecycle_status": {"bsonType": "string", "enum": THREAT_LIFECYCLE_STATUSES},
            "source": {"bsonType": ["string", "null"]},
            "confidence": {"bsonType": "double"},
            "tags": {"bsonType": ["array", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "scan_results": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "scan_id", "scan_type", "status", "summary", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "scan_id": {"bsonType": "string"},
            "scan_type": {"bsonType": "string"},
            "status": {"bsonType": "string", "enum": SCAN_STATUSES},
            "summary": {"bsonType": "string"},
            "details": {"bsonType": ["object", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "mitigations": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "mitigation_id", "threat_id", "title", "execution_status", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "mitigation_id": {"bsonType": "string"},
            "threat_id": {"bsonType": "string"},
            "title": {"bsonType": "string"},
            "execution_status": {"bsonType": "string", "enum": MITIGATION_EXECUTION_STATUSES},
            "details": {"bsonType": ["object", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "kb_documents": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "document_id", "title", "content_hash", "content_type", "updated_at", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "document_id": {"bsonType": "string"},
            "title": {"bsonType": "string"},
            "original_filename": {"bsonType": "string"},
            "content_hash": {"bsonType": "string"},
            "content_type": {"bsonType": "string"},
            "file_type": {"bsonType": "string", "enum": ["pdf", "txt", "markdown"]},
            "chunk_count": {"bsonType": "int"},
            "embedding_model": {"bsonType": "string"},
            "embedding_dimension": {"bsonType": "int"},
            "uploaded_at": {"bsonType": "date"},
            "uploaded_by": {"bsonType": ["string", "null"]},
            "source": {"bsonType": ["string", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": "date"},
        },
    },
    "kb_chunks": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "chunk_id", "doc_id", "content", "chunk_index", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "chunk_id": {"bsonType": "string"},
            "doc_id": {"bsonType": "string"},
            "content": {"bsonType": "string"},
            "chunk_index": {"bsonType": "int"},
            "page_number": {"bsonType": ["int", "null"]},
            "embedding": {"bsonType": "array", "items": {"bsonType": "double"}},
            "embedding_model": {"bsonType": "string"},
            "embedding_dimension": {"bsonType": "int"},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "chat_sessions": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "session_id", "user_id", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "session_id": {"bsonType": "string"},
            "user_id": {"bsonType": "string"},
            "title": {"bsonType": "string"},
            "provider": {"bsonType": ["string", "null"]},
            "model": {"bsonType": ["string", "null"]},
            "messages": {
                "bsonType": "array",
                "items": {
                    "bsonType": "object",
                    "required": ["role", "content", "timestamp"],
                    "properties": {
                        "role": {"bsonType": "string", "enum": ["user", "assistant"]},
                        "content": {"bsonType": "string"},
                        "timestamp": {"bsonType": "date"},
                        "provider": {"bsonType": ["string", "null"]},
                        "model": {"bsonType": ["string", "null"]},
                        "citations": {"bsonType": "array", "items": {"bsonType": "object"}},
                        "scanner_sources": {"bsonType": "array", "items": {"bsonType": "object"}},
                        "token_usage": {"bsonType": ["object", "null"]},
                    },
                },
            },
            "message_count": {"bsonType": "int"},
            "status": {"bsonType": ["string", "null"]},
            "last_message_at": {"bsonType": ["date", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "audit_logs": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "audit_id", "actor_id", "action", "resource_type", "resource_id", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "audit_id": {"bsonType": "string"},
            "actor_id": {"bsonType": "string"},
            "action": {"bsonType": "string"},
            "resource_type": {"bsonType": "string"},
            "resource_id": {"bsonType": "string"},
            "details": {"bsonType": ["object", "null"]},
            "created_at": {"bsonType": "date"},
        },
    },
    "revoked_tokens": {
        "bsonType": "object",
        "required": ["token_id", "org_id", "tenant_id", "user_id", "expires_at", "created_at"],
        "properties": {
            "token_id": {"bsonType": "string"},
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "user_id": {"bsonType": "string"},
            "expires_at": {"bsonType": "date"},
            "created_at": {"bsonType": "date"},
        },
    },
    "metrics_snapshots": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "snapshot_id", "metric_name", "metric_value", "captured_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "snapshot_id": {"bsonType": "string"},
            "metric_name": {"bsonType": "string"},
            "metric_value": {"bsonType": ["double", "int", "long", "decimal"]},
            "captured_at": {"bsonType": "date"},
            "created_at": {"bsonType": ["date", "null"]},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
}

INDEX_DEFINITIONS: Dict[str, Sequence[Sequence[Any]]] = {
    "organizations": [[("org_id", ASCENDING), {"unique": True}]],
    "tenants": [[("tenant_id", ASCENDING), {"unique": True}], [("org_id", ASCENDING)]],
    "users": [[("tenant_id", ASCENDING), ("email", ASCENDING), {"unique": True}], [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("user_id", ASCENDING), {"unique": True}]],
    "threats": [[("tenant_id", ASCENDING), ("lifecycle_status", ASCENDING), ("created_at", ASCENDING)], [("tenant_id", ASCENDING), ("severity", ASCENDING)]],
    "scan_results": [[("tenant_id", ASCENDING), ("created_at", ASCENDING)]],
    "mitigations": [[("tenant_id", ASCENDING), ("execution_status", ASCENDING)]],
    "kb_documents": [
        [("tenant_id", ASCENDING), ("content_hash", ASCENDING)],
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("content_hash", ASCENDING),
         {"unique": True, "name": "uq_kb_document_tenant_content_hash"}],
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("created_at", ASCENDING)],
    ],
    "kb_chunks": [
        [("tenant_id", ASCENDING), ("doc_id", ASCENDING)],
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("doc_id", ASCENDING), ("chunk_index", ASCENDING)],
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("embedding_model", ASCENDING)],
    ],
    "chat_sessions": [
        [("tenant_id", ASCENDING), ("user_id", ASCENDING)],
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("user_id", ASCENDING), ("created_at", ASCENDING)],
    ],
    "audit_logs": [[("tenant_id", ASCENDING), ("created_at", ASCENDING)]],
    "revoked_tokens": [
        [("token_id", ASCENDING), {"unique": True}],
        [("expires_at", ASCENDING), {"expireAfterSeconds": 0}],
    ],
    "metrics_snapshots": [[("tenant_id", ASCENDING), ("captured_at", ASCENDING)]],
}


def create_or_update_collection(db: Database, collection_name: str, validator: Dict[str, Any]) -> None:
    expected = {"$jsonSchema": validator}
    if collection_name not in db.list_collection_names():
        db.create_collection(
            collection_name,
            validator=expected,
            validationAction="error",
            validationLevel="strict",
        )
        return

    collection = db[collection_name]
    options = collection.options()
    current_validator = options.get("validator")
    current_action = options.get("validationAction")
    current_level = options.get("validationLevel")

    if current_validator == expected and current_action == "error" and current_level == "strict":
        return

    db.command(
        "collMod",
        collection_name,
        validator=expected,
        validationAction="error",
        validationLevel="strict",
    )


def apply_indexes(collection, index_specs: Sequence[Sequence[Any]]) -> None:
    for index_spec in index_specs:
        keys = []
        options = {}
        for key in index_spec:
            if isinstance(key, tuple):
                keys.append(key)
            elif isinstance(key, dict):
                options.update(key)
        collection.create_index(keys, **options)


def apply_all_schema_and_indexes(db: Database) -> Dict[str, bool]:
    verification: Dict[str, bool] = {}
    for collection_name, validator in SCHEMA_MAP.items():
        create_or_update_collection(db, collection_name, validator)
        verification[collection_name] = collection_name in db.list_collection_names()

    for collection_name, index_specs in INDEX_DEFINITIONS.items():
        collection = db[collection_name]
        apply_indexes(collection, index_specs)

    return verification
