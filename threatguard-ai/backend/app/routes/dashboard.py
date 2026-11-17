from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends

from backend.app.database.connection import get_db
from backend.app.security import enforce_permission, get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/metrics")
def get_dashboard_metrics(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Retrieve tenant-scoped metrics and recent activity directly from database records."""
    enforce_permission(current_user, "read_threats")
    db = get_db()
    org_id = current_user["org_id"]
    tenant_id = current_user["tenant_id"]
    user_id = current_user["user_id"]
    tenant_filter = {"org_id": org_id, "tenant_id": tenant_id}

    # 1. Scans count and recent scan history
    total_scans = db["scan_results"].count_documents(tenant_filter)
    recent_scans_cursor = (
        db["scan_results"]
        .find(tenant_filter)
        .sort("created_at", -1)
        .limit(10)
    )
    recent_scans = []
    for scan in recent_scans_cursor:
        details = scan.get("details") or {}
        summary = details.get("summary") or {}
        severity = summary.get("severity") if isinstance(summary, dict) else "unknown"
        total_findings = summary.get("total_findings", 0) if isinstance(summary, dict) else len(details.get("findings", []))
        created_at = scan.get("created_at")
        recent_scans.append({
            "scan_id": scan.get("scan_id"),
            "scan_type": scan.get("scan_type", "native-windows-scanner"),
            "status": scan.get("status", "completed"),
            "severity": severity or "low",
            "total_findings": total_findings,
            "host": details.get("host") or "unknown",
            "observation_mode": details.get("observation_mode", "live"),
            "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at or ""),
        })

    # 2. Threats count, severity distribution, lifecycle distribution
    total_threats = db["threats"].count_documents(tenant_filter)
    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in db["threats"].aggregate([
        {"$match": tenant_filter},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]):
        sev = str(item.get("_id") or "").lower()
        if sev in severity_distribution:
            severity_distribution[sev] = item["count"]

    lifecycle_distribution = {"Anticipated": 0, "Active": 0, "Evolving": 0, "Resolved": 0}
    for item in db["threats"].aggregate([
        {"$match": tenant_filter},
        {"$group": {"_id": "$lifecycle_status", "count": {"$sum": 1}}},
    ]):
        status_key = item.get("_id")
        if status_key in lifecycle_distribution:
            lifecycle_distribution[status_key] = item["count"]

    recent_threats_cursor = (
        db["threats"]
        .find(tenant_filter)
        .sort("created_at", -1)
        .limit(5)
    )
    recent_threats = []
    for threat in recent_threats_cursor:
        created_at = threat.get("created_at")
        recent_threats.append({
            "threat_id": threat.get("threat_id"),
            "title": threat.get("title"),
            "severity": threat.get("severity"),
            "lifecycle_status": threat.get("lifecycle_status"),
            "source": threat.get("source"),
            "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at or ""),
        })

    # 3. Knowledge base documents count
    kb_document_count = db["kb_documents"].count_documents(tenant_filter)

    # 4. Chatbot sessions count (scoped to tenant and user)
    chat_session_count = db["chat_sessions"].count_documents(
        {"org_id": org_id, "tenant_id": tenant_id, "user_id": user_id}
    )

    # 5. MongoDB and backend status
    try:
        db.command("ping")
        mongo_status = "connected"
    except Exception:
        mongo_status = "disconnected"

    return {
        "status": "ok",
        "system_status": {
            "backend": "ok",
            "mongo": mongo_status,
        },
        "metrics": {
            "total_scans": total_scans,
            "total_threats": total_threats,
            "kb_document_count": kb_document_count,
            "chat_session_count": chat_session_count,
            "severity_distribution": severity_distribution,
            "lifecycle_distribution": lifecycle_distribution,
        },
        "recent_scans": recent_scans,
        "recent_threats": recent_threats,
    }
