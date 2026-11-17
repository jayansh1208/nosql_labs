from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.config import JWT_ALGORITHM, JWT_EXPIRY_MINUTES, JWT_SECRET_KEY
from backend.app.database.connection import get_db
from backend.app.database.repositories import AuditLogRepository, RevokedTokenRepository, UserRepository

security_scheme = HTTPBearer(auto_error=False)
ROLE_PERMISSIONS: Dict[str, set[str]] = {
    "super_admin": {
        "read_threats",
        "write_threats",
        "manage_users",
        "manage_roles",
        "approve_mitigation",
        "view_audit",
        "write_audit",
    },
    "tenant_admin": {"read_threats", "write_threats", "manage_users", "approve_mitigation", "view_audit"},
    "security_analyst": {"read_threats", "write_threats", "view_audit"},
    "security_operator": {"read_threats", "write_threats"},
    "auditor": {"read_threats", "view_audit"},
}


def sanitize_user_record(user: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if user is None:
        return None
    safe = dict(user)
    safe.pop("password_hash", None)
    if "_id" in safe:
        safe["_id"] = str(safe["_id"])
    return safe


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(*, user_id: str, org_id: str, tenant_id: str, role: str, email: str) -> str:
    if len(JWT_SECRET_KEY) < 32:
        raise RuntimeError("JWT_SECRET_KEY must be configured with at least 32 characters.")
    expires = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES)
    payload = {
        "sub": user_id,
        "user_id": user_id,
        "email": email,
        "org_id": org_id,
        "tenant_id": tenant_id,
        "role": role,
        "exp": expires,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    if len(JWT_SECRET_KEY) < 32:
        raise ValueError("Authentication is not configured securely.")
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as exc:
        raise ValueError("Invalid or expired authentication token") from exc


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)) -> Dict[str, Any]:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Missing authentication token")

    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    user_id = payload.get("user_id")
    org_id = payload.get("org_id")
    tenant_id = payload.get("tenant_id")
    role = payload.get("role")
    email = payload.get("email")
    if not user_id or not org_id or not tenant_id or not role or not email:
        raise HTTPException(status_code=401, detail="Authentication token missing required identity claims")

    user = UserRepository(get_db()).get_by_user_id(user_id, org_id=org_id, tenant_id=tenant_id)
    if user is None or user.get("status") != "active":
        raise HTTPException(status_code=401, detail="User account is not active")
    token_id = payload.get("jti")
    if token_id and RevokedTokenRepository(get_db()).is_revoked(token_id):
        raise HTTPException(status_code=401, detail="Authentication token has been revoked")
    return sanitize_user_record(user)


def revoke_access_token(token: str, *, current_user: Dict[str, Any]) -> None:
    """Invalidate a JWT until its natural expiry without recording the token itself."""
    payload = decode_access_token(token)
    token_id = payload.get("jti")
    expires_at = payload.get("exp")
    if not token_id or not isinstance(expires_at, (int, float)):
        return
    expiry = datetime.fromtimestamp(expires_at, tz=timezone.utc)
    RevokedTokenRepository(get_db()).revoke(
        token_id=token_id,
        org_id=current_user["org_id"],
        tenant_id=current_user["tenant_id"],
        user_id=current_user["user_id"],
        expires_at=expiry,
    )


async def get_optional_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)) -> Optional[Dict[str, Any]]:
    if credentials is None or not credentials.credentials:
        return None
    return await get_current_user(credentials)


def enforce_permission(current_user: Dict[str, Any], permission: str) -> None:
    role = current_user.get("role")
    allowed = ROLE_PERMISSIONS.get(role, set())
    if permission not in allowed:
        db = get_db()
        AuditLogRepository(db).log(
            org_id=current_user.get("org_id", "unknown"),
            tenant_id=current_user.get("tenant_id", "unknown"),
            actor_id=current_user.get("user_id", "unknown"),
            action="permission_denied",
            resource_type="rbac",
            resource_id=permission,
            details={"required_permission": permission, "role": role},
        )
        raise HTTPException(status_code=403, detail=f"Permission denied: requires {permission}")


def enforce_tenant_context(current_user: Dict[str, Any], org_id: str, tenant_id: str) -> None:
    if current_user.get("org_id") != org_id or current_user.get("tenant_id") != tenant_id:
        db = get_db()
        AuditLogRepository(db).log(
            org_id=current_user.get("org_id", org_id),
            tenant_id=current_user.get("tenant_id", tenant_id),
            actor_id=current_user.get("user_id", "unknown"),
            action="cross_tenant_denied",
            resource_type="tenant",
            resource_id=tenant_id,
            details={"requested_org_id": org_id, "requested_tenant_id": tenant_id, "identity_org_id": current_user.get("org_id"), "identity_tenant_id": current_user.get("tenant_id")},
        )
        raise HTTPException(status_code=403, detail="Cross-tenant access denied")
