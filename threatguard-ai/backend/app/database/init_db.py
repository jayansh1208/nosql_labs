from __future__ import annotations

import os
import sys
from typing import Dict, Optional

from pymongo.database import Database

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BACKEND_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for candidate in (PROJECT_ROOT, BACKEND_ROOT):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from backend.app.config import MONGO_DB, MONGO_URI
from backend.app.database.connection import get_db
from backend.app.database.schema import apply_all_schema_and_indexes


def initialize_database(db: Optional[Database] = None) -> Dict[str, object]:
    target_db = db if db is not None else get_db()
    required_collections = [
        "organizations",
        "tenants",
        "users",
        "threats",
        "scan_results",
        "mitigations",
        "kb_documents",
        "kb_chunks",
        "chat_sessions",
        "audit_logs",
        "revoked_tokens",
        "metrics_snapshots",
    ]

    verification = apply_all_schema_and_indexes(target_db)
    existing = set(target_db.list_collection_names())
    for collection_name in required_collections:
        if collection_name not in existing:
            verification[collection_name] = False

    report = {
        "database": target_db.name,
        "collections_verified": all(verification.get(name, False) for name in required_collections),
        "collections": sorted(target_db.list_collection_names()),
    }
    return report


if __name__ == "__main__":
    result = initialize_database(get_db())
    print(f"Database: {result['database']}")
    print(f"Collections verified: {result['collections_verified']}")
    print(f"Collections: {', '.join(result['collections'])}")
    print("ThreatGuard initialization complete.")
