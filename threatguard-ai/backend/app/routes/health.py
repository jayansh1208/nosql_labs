from fastapi import APIRouter

from backend.app.database.connection import get_db

health_router = APIRouter(prefix="", tags=["health"])


@health_router.get("/health")
def health() -> dict:
    try:
        db = get_db()
        db.command("ping")
        mongo_status = "connected"
    except Exception:
        mongo_status = "disconnected"

    return {
        "status": "ok",
        "service": "threatguard-ai",
        "mongo": mongo_status,
    }
