from __future__ import annotations

from typing import Optional

from pymongo import MongoClient
from pymongo.database import Database

from backend.app.config import MONGO_DB, MONGO_URI

_client: Optional[MongoClient] = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        _client.admin.command("ping")
    return _client


def get_db() -> Database:
    return get_client()[MONGO_DB]


def close_client() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None
