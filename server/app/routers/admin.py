"""
Admin API routes: products, licenses, activations, audit log.
"""
import secrets
import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.database import get_db
from app.models import (
    License, Activation, Product, AuditLog, AdminUser,
    LicenseStatus, AuditAction
)
from app.schemas import (
    LicenseCreate, LicenseUpdate, LicenseResponse,
    ProductCreate, ProductResponse, AuditLogResponse,
    AdminLoginRequest,
)
import pyotp
from app.auth import (
    get_current_admin, authenticate_admin,
    create_admin_session, delete_admin_session,
    generate_totp_setup,
)
from app.crypto import generate_license_key, hash_password, verify_password
from app.websocket_manager import manager
from app import redis_client
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/api", tags=["admin"])


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ─── Auth ─────────────────────────────────────────────────────────────────────

@router.post("/auth/login")
async def admin_login(
    req: AdminLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = get_client_ip(request)

    # Step 1: find user and verify password
    result = await db.execute(
        select(AdminUser).where(AdminUser.email == req.email, AdminUser.is_active == True)
    )
    admin = result.scalar_one_or_none()

    if not admin or not verify_password(req.password, admin.password_hash):
        db.add(AuditLog(action=AuditAction.admin_login_failed, ip_address=ip, detail=f"email={req.email}"))
        await db.commit()
        raise HTTPException(401, "Invalid credentials")

    # Step 2: TOTP check (only after password is confirmed correct)
    if admin.totp_enabled:
        if not req.totp_code:
            return {"requires_totp": True}
        if not pyotp.TOTP(admin.totp_secret).verify(req.totp_code, valid_window=1):
            db.add(AuditLog(action=AuditAction.admin_login_failed, admin_id=admin.id, ip_address=ip, detail="wrong_totp"))
            await db.commit()
            raise HTTPException(401, "Invalid TOTP code")

    # Step 3: create session
    token = await create_admin_session(admin.id)
    admin.last_login = datetime.utcnow()
    db.add(AuditLog(action=AuditAction.admin_login, admin_id=admin.id, ip_address=ip))
    await db.commit()

    https = settings.domain.startswith("https://")
    response.set_cookie(
        key="admin_session",
        value=token,
        httponly=True,
        secure=https,
        samesite="strict",
        max_age=3600 * 8,
    )
    return {"ok": True, "email": admin.email, "is_superadmin": admin.is_superadmin}


@router.post("/auth/logout")
async def admin_logout(request: Request, response: Response):
    token = request.cookies.get("admin_session")
    if token:
        await delete_admin_session(token)
    response.delete_cookie("admin_session")
    return {"ok": True}


@router.get("/auth/me")
async def admin_me(admin: AdminUser = Depends(get_current_admin)):
    return {"id": admin.id, "email": admin.email, "is_superadmin": admin.is_superadmin, "totp_enabled": admin.totp_enabled}


@router.post("/auth/totp/setup")
async def setup_totp(
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    secret, url, qr_b64 = generate_totp_setup(admin.email)
    admin.totp_secret = secret
    await db.commit()
    return {"secret": secret, "qr_code": f"data:image/png;base64,{qr_b64}"}


@router.post("/auth/totp/confirm")
async def confirm_totp(
    code: str,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    import pyotp
    if not admin.totp_secret:
        raise HTTPException(400, "Run setup first")
    totp = pyotp.TOTP(admin.totp_secret)
    if not totp.verify(code, valid_window=1):
        raise HTTPException(400, "Invalid TOTP code")
    admin.totp_enabled = True
    await db.commit()
    return {"ok": True}


# ─── Products ─────────────────────────────────────────────────────────────────

@router.get("/products", response_model=list[ProductResponse])
async def list_products(
    db: AsyncSession = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    result = await db.execute(select(Product).order_by(Product.created_at.desc()))
    return result.scalars().all()


@router.post("/products", response_model=ProductResponse)
async def create_product(
    req: ProductCreate,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    import secrets as sc
    existing = await db.execute(select(Product).where(Product.slug == req.slug))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Slug already exists")

    product = Product(
        name=req.name,
        slug=req.slug,
        description=req.description,
        core_key_hex=sc.token_hex(32),  # 256-bit AES key
    )
    db.add(product)
    db.add(AuditLog(action=AuditAction.product_created, admin_id=admin.id, detail=f"slug={req.slug}"))
    await db.commit()
    await db.refresh(product)
    return product


@router.get("/products/{product_id}/key")
async def get_product_key(
    product_id: str,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """Get the AES key for a product (for encrypting the core module)."""
    if not admin.is_superadmin:
        raise HTTPException(403, "Superadmin only")
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(404, "Product not found")
    return {"product_id": product.id, "core_key_hex": product.core_key_hex}


# ─── Licenses ─────────────────────────────────────────────────────────────────

@router.get("/licenses", response_model=list[LicenseResponse])
async def list_licenses(
    product_id: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    q = select(License).order_by(License.created_at.desc()).offset(skip).limit(limit)
    if product_id:
        q = q.where(License.product_id == product_id)
    if status:
        q = q.where(License.status == status)
    result = await db.execute(q)
    licenses = result.scalars().all()

    out = []
    for lic in licenses:
        active = await redis_client.get_active_seat_count(lic.id)
        prod_result = await db.execute(select(Product).where(Product.id == lic.product_id))
        prod = prod_result.scalar_one_or_none()
        out.append(LicenseResponse(
            id=lic.id, key=lic.key, product_id=lic.product_id,
            product_name=prod.name if prod else None,
            customer_email=lic.customer_email, customer_name=lic.customer_name,
            license_type=lic.license_type, max_seats=lic.max_seats,
            status=lic.status, expires_at=lic.expires_at,
            created_at=lic.created_at, updated_at=lic.updated_at,
            active_seats=active, tamper_count=lic.tamper_count,
        ))
    return out


@router.post("/licenses", response_model=LicenseResponse)
async def create_license(
    req: LicenseCreate,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    prod_result = await db.execute(select(Product).where(Product.id == req.product_id))
    if not prod_result.scalar_one_or_none():
        raise HTTPException(404, "Product not found")

    key = generate_license_key()
    lic = License(
        key=key,
        product_id=req.product_id,
        customer_email=req.customer_email,
        customer_name=req.customer_name,
        license_type=req.license_type,
        max_seats=req.max_seats,
        expires_at=req.expires_at,
        notes=req.notes,
    )
    db.add(lic)
    db.add(AuditLog(
        action=AuditAction.license_created,
        license_id=lic.id,
        admin_id=admin.id,
        detail=f"key={key}",
    ))
    await db.commit()
    await db.refresh(lic)

    prod_r = await db.execute(select(Product).where(Product.id == lic.product_id))
    prod = prod_r.scalar_one_or_none()
    return LicenseResponse(
        id=lic.id, key=lic.key, product_id=lic.product_id,
        product_name=prod.name if prod else None,
        customer_email=lic.customer_email, customer_name=lic.customer_name,
        license_type=lic.license_type, max_seats=lic.max_seats,
        status=lic.status, expires_at=lic.expires_at,
        created_at=lic.created_at, updated_at=lic.updated_at,
    )


@router.patch("/licenses/{license_id}")
async def update_license(
    license_id: str,
    req: LicenseUpdate,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    old_seats = lic.max_seats
    if req.customer_email is not None:
        lic.customer_email = req.customer_email
    if req.customer_name is not None:
        lic.customer_name = req.customer_name
    if req.max_seats is not None:
        lic.max_seats = req.max_seats
    if req.expires_at is not None:
        lic.expires_at = req.expires_at
    if req.notes is not None:
        lic.notes = req.notes

    changes = []
    if req.max_seats and req.max_seats != old_seats:
        changes.append(f"seats {old_seats}->{req.max_seats}")
    if req.expires_at:
        changes.append(f"expires={req.expires_at}")

    if changes:
        db.add(AuditLog(
            action=AuditAction.seats_changed,
            license_id=license_id,
            admin_id=admin.id,
            detail=", ".join(changes),
        ))
    await db.commit()
    return {"ok": True}


@router.post("/licenses/{license_id}/suspend")
async def suspend_license(
    license_id: str,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    lic.status = LicenseStatus.suspended
    db.add(AuditLog(action=AuditAction.license_suspended, license_id=license_id, admin_id=admin.id))
    await db.commit()

    # Push revoke to connected clients immediately
    pushed = await manager.revoke_license(license_id, "license_suspended")
    # Mark in Redis so heartbeat also fails
    await redis_client.kill_all_sessions_for_license(license_id)

    return {"ok": True, "clients_notified": pushed}


@router.post("/licenses/{license_id}/revoke")
async def revoke_license(
    license_id: str,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    lic.status = LicenseStatus.revoked
    db.add(AuditLog(action=AuditAction.license_revoked, license_id=license_id, admin_id=admin.id))
    await db.commit()

    pushed = await manager.revoke_license(license_id, "license_revoked")
    await redis_client.kill_all_sessions_for_license(license_id)

    return {"ok": True, "clients_notified": pushed}


@router.post("/licenses/{license_id}/reactivate")
async def reactivate_license(
    license_id: str,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")
    if lic.status == LicenseStatus.revoked and not admin.is_superadmin:
        raise HTTPException(403, "Only superadmin can reactivate revoked licenses")

    lic.status = LicenseStatus.active
    db.add(AuditLog(action=AuditAction.license_renewed, license_id=license_id, admin_id=admin.id))
    await db.commit()
    return {"ok": True}


@router.post("/licenses/{license_id}/reset-hwid")
async def reset_hwid(
    license_id: str,
    hwid_hash: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """Reset HWID binding. If hwid_hash provided, only reset that one. Else reset all."""
    result = await db.execute(select(License).where(License.id == license_id))
    lic = result.scalar_one_or_none()
    if not lic:
        raise HTTPException(404, "License not found")

    if hwid_hash:
        act_result = await db.execute(
            select(Activation).where(
                Activation.license_id == license_id,
                Activation.hwid_hash == hwid_hash,
            )
        )
        act = act_result.scalar_one_or_none()
        if act:
            act.is_active = False
    else:
        act_result = await db.execute(
            select(Activation).where(Activation.license_id == license_id)
        )
        for act in act_result.scalars().all():
            act.is_active = False

    db.add(AuditLog(
        action=AuditAction.hwid_reset,
        license_id=license_id,
        admin_id=admin.id,
        hwid_hash=hwid_hash,
    ))
    await db.commit()
    return {"ok": True}


@router.post("/licenses/{license_id}/kill-sessions")
async def kill_sessions(
    license_id: str,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """Force-close all active sessions for a license without revoking."""
    pushed = await manager.revoke_license(license_id, "admin_killed_sessions")
    killed = await redis_client.kill_all_sessions_for_license(license_id)
    db.add(AuditLog(action=AuditAction.session_killed, license_id=license_id, admin_id=admin.id))
    await db.commit()
    return {"ok": True, "sessions_killed": killed, "clients_notified": pushed}


# ─── Activations ──────────────────────────────────────────────────────────────

@router.get("/licenses/{license_id}/activations")
async def get_activations(
    license_id: str,
    db: AsyncSession = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    result = await db.execute(
        select(Activation).where(Activation.license_id == license_id).order_by(Activation.last_seen.desc())
    )
    activations = result.scalars().all()
    active_count = await redis_client.get_active_seat_count(license_id)

    return {
        "activations": [
            {
                "id": a.id,
                "hwid_hash": a.hwid_hash[:16] + "...",
                "seat_label": a.seat_label,
                "is_active": a.is_active,
                "platform": a.platform,
                "first_seen": a.first_seen,
                "last_seen": a.last_seen,
                "ip_address": a.ip_address,
            }
            for a in activations
        ],
        "active_now": active_count,
    }


# ─── Audit Log ────────────────────────────────────────────────────────────────

@router.get("/audit-log", response_model=list[AuditLogResponse])
async def get_audit_log(
    license_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    q = select(AuditLog).order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)
    if license_id:
        q = q.where(AuditLog.license_id == license_id)
    result = await db.execute(q)
    return result.scalars().all()


# ─── Stats ────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    from app.websocket_manager import manager as ws_mgr

    total_lic = (await db.execute(select(func.count()).select_from(License))).scalar_one()
    active_lic = (await db.execute(
        select(func.count()).select_from(License).where(License.status == LicenseStatus.active)
    )).scalar_one()
    total_products = (await db.execute(select(func.count()).select_from(Product))).scalar_one()
    tamper_alerts = (await db.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.action == AuditAction.tamper_alert)
    )).scalar_one()

    return {
        "total_licenses": total_lic,
        "active_licenses": active_lic,
        "total_products": total_products,
        "active_ws_connections": ws_mgr.total_connections(),
        "tamper_alerts": tamper_alerts,
    }
