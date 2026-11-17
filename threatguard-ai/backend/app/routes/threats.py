from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.app.database.connection import get_db
from backend.app.database.repositories import ThreatRepository, serialize_document
from backend.app.models import ThreatCreate, ThreatStatusUpdate
from backend.app.security import enforce_permission, enforce_tenant_context, get_current_user

router = APIRouter(prefix="/threats", tags=["threats"])


@router.post("", status_code=201)
def create_threat(payload: ThreatCreate, current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    repo = ThreatRepository(get_db())
    enforce_permission(current_user, "write_threats")
    enforce_tenant_context(current_user, payload.org_id, payload.tenant_id)
    payload_data = payload.model_dump()
    payload_data["org_id"] = current_user["org_id"]
    payload_data["tenant_id"] = current_user["tenant_id"]
    record = repo.create(payload_data)
    return serialize_document(record)


@router.get("")
def list_threats(
    org_id: str = Query(..., min_length=1),
    tenant_id: str = Query(..., min_length=1),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = None,
    lifecycle_status: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    repo = ThreatRepository(get_db())
    enforce_permission(current_user, "read_threats")
    enforce_tenant_context(current_user, org_id, tenant_id)
    return repo.list(org_id=current_user["org_id"], tenant_id=current_user["tenant_id"], page=page, page_size=page_size, severity=severity, lifecycle_status=lifecycle_status)


@router.get("/{threat_id}")
def get_threat(
    threat_id: str,
    org_id: str = Query(..., min_length=1),
    tenant_id: str = Query(..., min_length=1),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    repo = ThreatRepository(get_db())
    enforce_permission(current_user, "read_threats")
    enforce_tenant_context(current_user, org_id, tenant_id)
    record = repo.get_by_id(threat_id, org_id=current_user["org_id"], tenant_id=current_user["tenant_id"])
    if record is None:
        raise HTTPException(status_code=404, detail="Threat not found for this tenant")
    return serialize_document(record)


@router.patch("/{threat_id}/status")
def update_threat_status(
    threat_id: str,
    payload: ThreatStatusUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    repo = ThreatRepository(get_db())
    enforce_permission(current_user, "write_threats")
    enforce_tenant_context(current_user, payload.org_id, payload.tenant_id)
    payload_org_id = current_user["org_id"]
    payload_tenant_id = current_user["tenant_id"]

    try:
        record = repo.update_status(
            threat_id,
            org_id=payload_org_id,
            tenant_id=payload_tenant_id,
            lifecycle_status=payload.lifecycle_status,
        )
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    return serialize_document(record)
