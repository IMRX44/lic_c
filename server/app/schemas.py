"""
Pydantic schemas for API requests/responses.
"""
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import datetime
from app.models import LicenseStatus, LicenseType


# ─── License API (client-facing) ──────────────────────────────────────────────

class ActivateRequest(BaseModel):
    license_key: str
    hwid_hash: str          # SHA-256( raw_hwid + server_salt ) - computed client-side
    platform: str           # "windows" | "linux"
    product_slug: str
    client_version: str
    nonce: str              # random UUID, one-time use
    timestamp: int          # unix timestamp - server rejects if >60s old


class ActivateResponse(BaseModel):
    session_token: str      # JWT signed with Ed25519
    session_key_hex: str    # AES-256 key for this session (encrypted with client's HWID-derived key)
    expires_at: int         # unix timestamp - when session_key expires
    server_public_key: str  # hex of Ed25519 public key for pinning verification
    heartbeat_interval: int # seconds between heartbeats


class HeartbeatRequest(BaseModel):
    session_token: str
    hwid_hash: str
    nonce: str
    timestamp: int
    # optional integrity report (sent if client detects anomalies)
    integrity_report: Optional[dict] = None


class HeartbeatResponse(BaseModel):
    session_key_hex: str    # renewed AES-256 session key
    expires_at: int
    next_heartbeat: int     # unix timestamp of when to send next heartbeat
    # push: if server has a message (revoke/warning), it goes here too
    message: Optional[str] = None
    action: Optional[str] = None  # "revoke" | "warn" | None


# ─── Admin API ────────────────────────────────────────────────────────────────

class AdminLoginRequest(BaseModel):
    email: str
    password: str
    totp_code: Optional[str] = None


class ProductCreate(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None


class ProductResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class LicenseCreate(BaseModel):
    product_id: str
    customer_email: Optional[str] = None
    customer_name: Optional[str] = None
    license_type: LicenseType = LicenseType.single
    max_seats: int = 1
    expires_at: Optional[datetime] = None
    notes: Optional[str] = None

    @field_validator("max_seats")
    @classmethod
    def seats_must_be_positive(cls, v):
        if v < 1 or v > 100:
            raise ValueError("max_seats must be between 1 and 100")
        return v


class LicenseUpdate(BaseModel):
    customer_email: Optional[str] = None
    customer_name: Optional[str] = None
    max_seats: Optional[int] = None
    expires_at: Optional[datetime] = None
    notes: Optional[str] = None


class LicenseResponse(BaseModel):
    id: str
    key: str
    product_id: str
    product_name: Optional[str] = None
    customer_email: Optional[str]
    customer_name: Optional[str]
    license_type: LicenseType
    max_seats: int
    status: LicenseStatus
    expires_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    active_seats: int = 0
    tamper_count: int = 0

    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    id: str
    action: str
    license_id: Optional[str]
    admin_id: Optional[str]
    hwid_hash: Optional[str]
    ip_address: Optional[str]
    detail: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
