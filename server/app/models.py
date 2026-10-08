"""
Database models for the licensing system.
"""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Boolean, Integer, DateTime, ForeignKey,
    Text, Enum as SAEnum, Index, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base
import enum


def new_uuid():
    return str(uuid.uuid4())


class LicenseStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"
    expired = "expired"
    revoked = "revoked"


class LicenseType(str, enum.Enum):
    single = "single"      # max_seats = 1
    multi = "multi"        # max_seats > 1


class AuditAction(str, enum.Enum):
    license_created = "license_created"
    license_activated = "license_activated"
    license_suspended = "license_suspended"
    license_revoked = "license_revoked"
    license_renewed = "license_renewed"
    hwid_reset = "hwid_reset"
    session_killed = "session_killed"
    seats_changed = "seats_changed"
    admin_login = "admin_login"
    admin_login_failed = "admin_login_failed"
    tamper_alert = "tamper_alert"
    product_created = "product_created"


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    totp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Product(Base):
    """Each binary/software product that can be licensed."""
    __tablename__ = "products"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # AES-256 key (hex) used to encrypt the product's core module
    # Each product has its own unique encryption key
    core_key_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    licenses: Mapped[list["License"]] = relationship("License", back_populates="product")


class License(Base):
    __tablename__ = "licenses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    product_id: Mapped[str] = mapped_column(String(36), ForeignKey("products.id"), nullable=False)
    customer_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    customer_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    license_type: Mapped[LicenseType] = mapped_column(SAEnum(LicenseType), default=LicenseType.single)
    max_seats: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[LicenseStatus] = mapped_column(SAEnum(LicenseStatus), default=LicenseStatus.active)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)  # None = never expires
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tamper_count: Mapped[int] = mapped_column(Integer, default=0)

    product: Mapped["Product"] = relationship("Product", back_populates="licenses")
    activations: Mapped[list["Activation"]] = relationship("Activation", back_populates="license")

    __table_args__ = (
        Index("ix_licenses_key", "key"),
        Index("ix_licenses_status", "status"),
        Index("ix_licenses_product_id", "product_id"),
    )


class Activation(Base):
    """A specific HWID binding for a license seat."""
    __tablename__ = "activations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    license_id: Mapped[str] = mapped_column(String(36), ForeignKey("licenses.id"), nullable=False)
    hwid_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 of HWID+salt
    seat_label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    platform: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # "windows" | "linux"

    license: Mapped["License"] = relationship("License", back_populates="activations")

    __table_args__ = (
        UniqueConstraint("license_id", "hwid_hash", name="uq_activation_license_hwid"),
        Index("ix_activations_hwid_hash", "hwid_hash"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    action: Mapped[AuditAction] = mapped_column(SAEnum(AuditAction), nullable=False)
    license_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    admin_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    hwid_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_audit_logs_license_id", "license_id"),
        Index("ix_audit_logs_created_at", "created_at"),
    )
