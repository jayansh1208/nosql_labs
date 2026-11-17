from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials

from backend.app.database.connection import get_db
from backend.app.database.repositories import AuditLogRepository, UserRepository
from backend.app.models import UserLogin, UserRegistration
from backend.app.security import (
    create_access_token,
    enforce_permission,
    enforce_tenant_context,
    get_current_user,
    hash_password,
    revoke_access_token,
    sanitize_user_record,
    security_scheme,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _create_user(payload: UserRegistration, *, actor_id: str) -> Dict[str, Any]:
    db = get_db()
    repo = UserRepository(db)

    if repo.get_by_email(payload.email, org_id=payload.org_id, tenant_id=payload.tenant_id):
        raise HTTPException(status_code=409, detail="User already exists for this tenant")

    user_id = f"usr-{uuid.uuid4().hex[:12]}"
    created = repo.create(
        {
            "org_id": payload.org_id,
            "tenant_id": payload.tenant_id,
            "user_id": user_id,
            "email": payload.email,
            "display_name": payload.display_name,
            "role": payload.role,
            "status": "active",
            "password_hash": hash_password(payload.password),
        }
    )

    AuditLogRepository(db).log(
        org_id=payload.org_id,
        tenant_id=payload.tenant_id,
        actor_id=actor_id,
        action="user_created",
        resource_type="user",
        resource_id=user_id,
        details={"email": payload.email, "role": payload.role},
    )
    return sanitize_user_record(created)


@router.post("/users", status_code=201)
def create_user(
    payload: UserRegistration,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create users only from an already authenticated administrator session."""
    enforce_permission(current_user, "manage_users")
    enforce_tenant_context(current_user, payload.org_id, payload.tenant_id)
    if current_user["role"] != "super_admin" and payload.role in {"super_admin", "tenant_admin"}:
        raise HTTPException(status_code=403, detail="Only a super administrator can create administrator accounts")
    return _create_user(payload, actor_id=current_user["user_id"])


@router.get("/users")
def list_users(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """List users within the authenticated tenant context."""
    enforce_permission(current_user, "manage_users")
    repo = UserRepository(get_db())
    result = repo.list(
        org_id=current_user["org_id"],
        tenant_id=current_user["tenant_id"],
        page=page,
        page_size=page_size,
    )
    result["items"] = [sanitize_user_record(item) for item in result.get("items", [])]
    return result


@router.post("/register", status_code=403, include_in_schema=False)
def public_registration_disabled() -> None:
    """Preserve a clear response for legacy clients without allowing self-provisioning."""
    raise HTTPException(
        status_code=403,
        detail="Public registration is disabled. Use the development bootstrap command or an administrator.",
    )


@router.post("/login")
def login_user(payload: UserLogin) -> Dict[str, Any]:
    db = get_db()
    repo = UserRepository(db)
    user = repo.get_by_email(payload.email)

    if user is None or not verify_password(payload.password, user.get("password_hash", "")):
        AuditLogRepository(db).log(
            org_id="unknown",
            tenant_id="unknown",
            actor_id="unknown",
            action="login_failed",
            resource_type="auth",
            resource_id=payload.email,
            details={"email": payload.email, "reason": "invalid_credentials"},
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if user.get("status") != "active":
        AuditLogRepository(db).log(
            org_id=user.get("org_id", "unknown"),
            tenant_id=user.get("tenant_id", "unknown"),
            actor_id=user.get("user_id", "unknown"),
            action="login_failed",
            resource_type="auth",
            resource_id=user.get("user_id", "unknown"),
            details={"email": payload.email, "reason": "inactive_account"},
        )
        raise HTTPException(status_code=401, detail="Account is inactive")

    token = create_access_token(
        user_id=user["user_id"],
        org_id=user["org_id"],
        tenant_id=user["tenant_id"],
        role=user["role"],
        email=user["email"],
    )
    AuditLogRepository(db).log(
        org_id=user["org_id"],
        tenant_id=user["tenant_id"],
        actor_id=user["user_id"],
        action="login_success",
        resource_type="auth",
        resource_id=user["user_id"],
        details={"email": user["email"], "role": user["role"]},
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": sanitize_user_record(user),
    }


@router.get("/me")
def read_current_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return sanitize_user_record(current_user)


@router.post("/logout", status_code=200)
def logout_user(
    current_user: Dict[str, Any] = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> None:
    # The raw token is used only to derive its signed identifier and is never stored.
    if credentials is not None and credentials.credentials:
        revoke_access_token(credentials.credentials, current_user=current_user)
    AuditLogRepository(get_db()).log(
        org_id=current_user["org_id"],
        tenant_id=current_user["tenant_id"],
        actor_id=current_user["user_id"],
        action="logout",
        resource_type="auth",
        resource_id=current_user["user_id"],
        details={},
    )
