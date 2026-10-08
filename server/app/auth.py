"""
Admin authentication: session cookies, TOTP, RBAC.
"""
import secrets
import pyotp
import qrcode
import io
import base64
from typing import Optional
from fastapi import Cookie, HTTPException, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import redis.asyncio as aioredis

from app.models import AdminUser, AuditLog, AuditAction
from app.crypto import hash_password, verify_password
from app.config import settings
from app.database import get_db
from app import redis_client as rc

SESSION_TTL = 3600 * 8  # 8 hours


async def create_admin_session(admin_id: str) -> str:
    """Create a new session token in Redis."""
    r = await rc.get_redis()
    token = secrets.token_urlsafe(32)
    await r.setex(f"admin_session:{token}", SESSION_TTL, admin_id)
    return token


async def get_admin_session(token: str) -> Optional[str]:
    """Returns admin_id or None."""
    r = await rc.get_redis()
    return await r.get(f"admin_session:{token}")


async def delete_admin_session(token: str):
    r = await rc.get_redis()
    await r.delete(f"admin_session:{token}")


async def get_current_admin(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AdminUser:
    """Dependency: verify admin session cookie."""
    token = request.cookies.get("admin_session")
    if not token:
        raise HTTPException(401, "Not authenticated")

    admin_id = await get_admin_session(token)
    if not admin_id:
        raise HTTPException(401, "Session expired")

    result = await db.execute(select(AdminUser).where(AdminUser.id == admin_id))
    admin = result.scalar_one_or_none()
    if not admin or not admin.is_active:
        raise HTTPException(401, "Admin account not found or inactive")

    return admin


async def authenticate_admin(
    email: str,
    password: str,
    totp_code: Optional[str],
    db: AsyncSession,
    client_ip: str,
) -> Optional[AdminUser]:
    result = await db.execute(select(AdminUser).where(AdminUser.email == email))
    admin: Optional[AdminUser] = result.scalar_one_or_none()

    if not admin or not admin.is_active:
        db.add(AuditLog(
            action=AuditAction.admin_login_failed,
            ip_address=client_ip,
            detail=f"email={email}",
        ))
        await db.commit()
        return None

    if not verify_password(password, admin.password_hash):
        db.add(AuditLog(
            action=AuditAction.admin_login_failed,
            admin_id=admin.id,
            ip_address=client_ip,
            detail="wrong_password",
        ))
        await db.commit()
        return None

    if admin.totp_enabled:
        if not totp_code:
            return None  # signal: needs TOTP
        totp = pyotp.TOTP(admin.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            db.add(AuditLog(
                action=AuditAction.admin_login_failed,
                admin_id=admin.id,
                ip_address=client_ip,
                detail="wrong_totp",
            ))
            await db.commit()
            return None

    return admin


def generate_totp_setup(admin_email: str) -> tuple[str, str, str]:
    """Returns (secret, otpauth_url, qr_base64)."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    url = totp.provisioning_uri(name=admin_email, issuer_name="LicenseSystem")

    # Generate QR code as base64 PNG
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return secret, url, qr_b64


async def create_initial_admin(db: AsyncSession):
    """Create the first superadmin on first run."""
    result = await db.execute(select(AdminUser))
    existing = result.scalars().first()
    if existing:
        return

    admin = AdminUser(
        email=settings.admin_email,
        password_hash=hash_password(settings.admin_password),
        is_superadmin=True,
        is_active=True,
    )
    db.add(admin)
    await db.commit()
    print(f"[*] Initial admin created: {settings.admin_email}")
