from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.app.database.connection import get_db
from backend.app.database.repositories import TenantRepository, serialize_document
from backend.app.models import TenantCreate
from backend.app.security import enforce_permission, enforce_tenant_context, get_current_user

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.post("", status_code=201)
def create_tenant(payload: TenantCreate, current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    enforce_permission(current_user, "manage_roles")
    if payload.org_id != current_user["org_id"]:
        raise HTTPException(status_code=403, detail="Cross-organization access denied")
    repo = TenantRepository(get_db())
    record = repo.create(payload.model_dump())
    return serialize_document(record)


@router.get("")
def list_tenants(org_id: str = Query(..., min_length=1), page: int = Query(default=1, ge=1), page_size: int = Query(default=20, ge=1, le=100), current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    enforce_permission(current_user, "manage_roles")
    if org_id != current_user["org_id"]:
        raise HTTPException(status_code=403, detail="Cross-organization access denied")
    repo = TenantRepository(get_db())
    return repo.list(org_id=current_user["org_id"], page=page, page_size=page_size)
