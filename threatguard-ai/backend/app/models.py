from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

THREAT_LIFECYCLE_STATUSES = ["Anticipated", "Active", "Evolving", "Resolved"]
THREAT_SEVERITY_VALUES = ["low", "medium", "high", "critical"]
SCAN_STATUSES = ["pending", "running", "completed", "failed"]
MITIGATION_STATUSES = ["pending", "in_progress", "completed", "failed", "blocked"]
ROLE_NAMES = ["super_admin", "tenant_admin", "security_analyst", "security_operator", "auditor"]


class BaseTenantContext(BaseModel):
    org_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    model_config = ConfigDict(extra="forbid")


class OrganizationCreate(BaseModel):
    org_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    status: Literal["active", "inactive"] = "active"
    model_config = ConfigDict(extra="forbid")


class OrganizationResponse(OrganizationCreate):
    created_at: datetime
    updated_at: Optional[datetime] = None


class TenantCreate(BaseTenantContext):
    name: str = Field(..., min_length=1)
    status: Literal["active", "inactive", "suspended"] = "active"
    metadata: Optional[dict] = None


class TenantResponse(TenantCreate):
    created_at: datetime
    updated_at: Optional[datetime] = None


class UserCreate(BaseTenantContext):
    user_id: str = Field(..., min_length=1)
    email: str = Field(..., min_length=3)
    display_name: str = Field(..., min_length=1)
    role: Literal["super_admin", "tenant_admin", "security_analyst", "security_operator", "auditor"] = "security_analyst"
    status: Literal["active", "disabled"] = "active"
    password_hash: Optional[str] = None


class UserResponse(UserCreate):
    created_at: datetime
    updated_at: Optional[datetime] = None


class UserRegistration(BaseModel):
    org_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=8)
    display_name: str = Field(..., min_length=1)
    role: Literal["super_admin", "tenant_admin", "security_analyst", "security_operator", "auditor"] = "security_analyst"
    model_config = ConfigDict(extra="forbid")


class UserLogin(BaseModel):
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=8)
    model_config = ConfigDict(extra="forbid")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict
    model_config = ConfigDict(extra="forbid")


class ThreatCreate(BaseTenantContext):
    threat_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    severity: Literal["low", "medium", "high", "critical"]
    lifecycle_status: Literal["Anticipated", "Active", "Evolving", "Resolved"]
    source: Optional[str] = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    tags: Optional[list[str]] = None


class ThreatStatusUpdate(BaseModel):
    org_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    lifecycle_status: Literal["Anticipated", "Active", "Evolving", "Resolved"]
    model_config = ConfigDict(extra="forbid")


class ThreatResponse(ThreatCreate):
    created_at: datetime
    updated_at: Optional[datetime] = None


class ThreatListQuery(BaseModel):
    org_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
    severity: Optional[Literal["low", "medium", "high", "critical"]] = None
    lifecycle_status: Optional[Literal["Anticipated", "Active", "Evolving", "Resolved"]] = None


class AuditLogCreate(BaseTenantContext):
    audit_id: str = Field(..., min_length=1)
    actor_id: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    resource_type: str = Field(..., min_length=1)
    resource_id: str = Field(..., min_length=1)
    details: Optional[dict] = None


class AuditLogResponse(AuditLogCreate):
    created_at: datetime


class PaginationQuery(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
    model_config = ConfigDict(extra="forbid")
