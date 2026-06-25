import uuid
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, EmailStr, HttpUrl, field_validator, ConfigDict

from app.models.models import (
    UserRole, ScanStatus, ScanType, FindingSeverity,
    DeploymentVerdict, ScheduleFrequency
)


# ─── Auth ───────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain an uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain a digit")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    is_verified: bool
    avatar_url: Optional[str] = None
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


# ─── Organizations ───────────────────────────────────────────────────────────

class OrganizationCreate(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    webhook_url: Optional[str] = None
    webhook_channel: str = "generic"

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        import re
        if not re.match(r"^[a-z0-9-]+$", v):
            raise ValueError("Slug must contain only lowercase letters, numbers, and hyphens")
        return v


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    description: Optional[str] = None
    plan: str
    webhook_url: Optional[str] = None
    webhook_channel: str = "generic"
    created_at: datetime


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.MEMBER


# ─── Scans ───────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    target_url: str
    scan_type: ScanType = ScanType.FULL
    organization_id: uuid.UUID
    scan_config: Optional[Dict[str, Any]] = None
    consent_confirmed: bool
    scheduled: bool = False
    schedule_frequency: Optional[ScheduleFrequency] = None

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @field_validator("consent_confirmed")
    @classmethod
    def validate_consent(cls, v: bool) -> bool:
        if not v:
            raise ValueError("You must confirm authorization to scan this target")
        return v


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_url: str
    target_domain: str
    scan_type: ScanType
    status: ScanStatus
    security_score: Optional[float] = None
    verdict: Optional[DeploymentVerdict] = None
    scan_metadata: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    per_page: int


# ─── Findings ────────────────────────────────────────────────────────────────

class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    severity: FindingSeverity
    category: str
    description: str
    evidence: Optional[Dict[str, Any]] = None
    impact: str
    remediation: str
    reproduction_steps: Optional[str] = None
    verification_steps: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    cvss_score: Optional[float] = None
    risk_score: Optional[float] = None
    affected_url: Optional[str] = None
    tool_name: Optional[str] = None
    screenshot_path: Optional[str] = None
    is_false_positive: bool
    is_resolved: bool
    created_at: datetime


class FindingUpdate(BaseModel):
    is_false_positive: Optional[bool] = None
    is_resolved: Optional[bool] = None


class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


# ─── Reports ─────────────────────────────────────────────────────────────────

class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    report_type: str
    file_size: Optional[int] = None
    generated_at: datetime


# ─── API Keys ────────────────────────────────────────────────────────────────

class ApiKeyCreate(BaseModel):
    name: str
    organization_id: Optional[uuid.UUID] = None
    scopes: Optional[List[str]] = None


class ApiKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: Optional[List[str]] = None
    last_used_at: Optional[datetime] = None
    created_at: datetime


class ApiKeyCreatedResponse(ApiKeyResponse):
    key: str  # Only returned once on creation


# ─── Dashboard ───────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_scans: int
    active_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    average_score: float
    recent_scans: List[ScanResponse]
    score_trend: List[Dict[str, Any]]


# ─── CI/CD ───────────────────────────────────────────────────────────────────

class CICDGateResult(BaseModel):
    status: str  # GO, GO_WITH_CONDITIONS, NO_GO
    security_score: float
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    scan_id: str
    scan_url: str
    timestamp: str
    passed: bool
