"""
Core licensing logic: activation, heartbeat, seat management.
"""
import hashlib
import secrets
import time
import logging
from datetime import datetime
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from fastapi import HTTPException, Request

from app.models import License, Activation, Product, AuditLog, LicenseStatus, AuditAction
from app.schemas import ActivateRequest, ActivateResponse, HeartbeatRequest, HeartbeatResponse
from app.crypto import (
    generate_session_key, encrypt_session_key, build_session_token,
    verify_session_token, get_public_key_hex, generate_license_key
)
from app import redis_client
from app.config import settings

logger = logging.getLogger(__name__)


def _session_id_from_token(token: str) -> str:
    """Derive a stable session ID from token (first 32 chars of SHA-256)."""
    return hashlib.sha256(token.encode()).hexdigest()[:32]


async def activate_license(
    req: ActivateRequest,
    db: AsyncSession,
    client_ip: str,
) -> ActivateResponse:
    """
    Activation flow:
    1. Validate request freshness (timestamp + nonce)
    2. Look up license by key
    3. Verify license is active, not expired, correct product
    4. Check seat availability
    5. Create or refresh activation (HWID binding)
    6. Generate session token + session key
    """
    # 1. Freshness check
    now = int(time.time())
    if abs(now - req.timestamp) > 60:
        raise HTTPException(400, "Request timestamp out of range")

    nonce_ok = await redis_client.check_and_store_nonce(req.nonce)
    if not nonce_ok:
        raise HTTPException(400, "Nonce already used (replay detected)")

    # 2. Lookup license
    result = await db.execute(select(License).where(License.key == req.license_key.upper()))
    license_obj: Optional[License] = result.scalar_one_or_none()

    if not license_obj:
        raise HTTPException(404, "License not found")

    # 3. Validity checks
    if license_obj.status != LicenseStatus.active:
        raise HTTPException(403, f"License is {license_obj.status.value}")

    if license_obj.expires_at and license_obj.expires_at < datetime.utcnow():
        license_obj.status = LicenseStatus.expired
        await db.commit()
        raise HTTPException(403, "License has expired")

    # Check correct product
    product_result = await db.execute(
        select(Product).where(Product.id == license_obj.product_id)
    )
    product: Optional[Product] = product_result.scalar_one_or_none()
    if not product or product.slug != req.product_slug:
        raise HTTPException(403, "License is not valid for this product")

    if not product.is_active:
        raise HTTPException(403, "Product is not active")

    # 4. Check seats
    active_seats = await redis_client.get_active_seat_count(license_obj.id)

    # Check if this HWID already has an activation (returning device)
    act_result = await db.execute(
        select(Activation).where(
            Activation.license_id == license_obj.id,
            Activation.hwid_hash == req.hwid_hash,
            Activation.is_active == True,
        )
    )
    existing_activation: Optional[Activation] = act_result.scalar_one_or_none()

    if not existing_activation:
        # New device - check seat limit
        # Count distinct active HWIDs (not just Redis sessions)
        hwid_count_result = await db.execute(
            select(func.count()).where(
                Activation.license_id == license_obj.id,
                Activation.is_active == True,
            )
        )
        hwid_count = hwid_count_result.scalar_one()

        if hwid_count >= license_obj.max_seats:
            raise HTTPException(403, f"Seat limit reached ({license_obj.max_seats})")

        # Create new activation
        existing_activation = Activation(
            license_id=license_obj.id,
            hwid_hash=req.hwid_hash,
            ip_address=client_ip,
            platform=req.platform,
        )
        db.add(existing_activation)
    else:
        # Update last seen
        existing_activation.last_seen = datetime.utcnow()
        existing_activation.ip_address = client_ip

    await db.commit()

    # 5. Generate session
    seq = await redis_client.get_and_increment_sequence(license_obj.id)
    expires_at = now + settings.session_key_ttl_seconds

    token = build_session_token(
        license_id=license_obj.id,
        hwid_hash=req.hwid_hash,
        product_slug=product.slug,
        expires_at=expires_at,
        sequence=seq,
    )
    session_id = _session_id_from_token(token)
    session_key = generate_session_key()
    encrypted_key = encrypt_session_key(session_key, req.hwid_hash, license_obj.id)

    await redis_client.create_session(
        session_id=session_id,
        license_id=license_obj.id,
        hwid_hash=req.hwid_hash,
        product_slug=product.slug,
        sequence=seq,
        ttl=settings.session_key_ttl_seconds + settings.grace_period_seconds,
    )

    # Audit
    db.add(AuditLog(
        action=AuditAction.license_activated,
        license_id=license_obj.id,
        hwid_hash=req.hwid_hash,
        ip_address=client_ip,
        detail=f"platform={req.platform} product={product.slug}",
    ))
    await db.commit()

    return ActivateResponse(
        session_token=token,
        session_key_hex=encrypted_key,
        expires_at=expires_at,
        server_public_key=get_public_key_hex(),
        heartbeat_interval=settings.heartbeat_interval_seconds,
    )


async def process_heartbeat(
    req: HeartbeatRequest,
    db: AsyncSession,
    client_ip: str,
) -> HeartbeatResponse:
    """
    Heartbeat flow:
    1. Verify token signature + freshness
    2. Check nonce
    3. Verify license still active
    4. Renew session key
    5. Return new key
    """
    # 1. Verify token
    claims = verify_session_token(req.session_token)
    if not claims:
        raise HTTPException(401, "Invalid or expired session token")

    if claims["hwid_hash"] != req.hwid_hash:
        raise HTTPException(401, "HWID mismatch")

    # 2. Nonce
    now = int(time.time())
    if abs(now - req.timestamp) > 60:
        raise HTTPException(400, "Request timestamp out of range")

    nonce_ok = await redis_client.check_and_store_nonce(req.nonce)
    if not nonce_ok:
        raise HTTPException(400, "Nonce replay detected")

    license_id = claims["license_id"]

    # Check for pending revoke signal
    if await redis_client.is_license_revoked(license_id):
        raise HTTPException(403, "license_revoked")

    # 3. Verify license in DB
    result = await db.execute(select(License).where(License.id == license_id))
    license_obj: Optional[License] = result.scalar_one_or_none()

    if not license_obj:
        raise HTTPException(404, "License not found")

    if license_obj.status != LicenseStatus.active:
        raise HTTPException(403, f"license_{license_obj.status.value}")

    if license_obj.expires_at and license_obj.expires_at < datetime.utcnow():
        license_obj.status = LicenseStatus.expired
        await db.commit()
        raise HTTPException(403, "license_expired")

    # Handle integrity report (tamper detection)
    if req.integrity_report:
        anomalies = req.integrity_report.get("anomalies", [])
        if anomalies:
            license_obj.tamper_count += 1
            db.add(AuditLog(
                action=AuditAction.tamper_alert,
                license_id=license_id,
                hwid_hash=req.hwid_hash,
                ip_address=client_ip,
                detail=str(req.integrity_report),
            ))
            await db.commit()
            logger.warning(f"Tamper alert for license {license_id[:8]} count={license_obj.tamper_count}")

    # 4. Renew session
    session_id = _session_id_from_token(req.session_token)
    seq = await redis_client.get_and_increment_sequence(license_id)
    expires_at = now + settings.session_key_ttl_seconds

    new_token = build_session_token(
        license_id=license_id,
        hwid_hash=req.hwid_hash,
        product_slug=claims["product_slug"],
        expires_at=expires_at,
        sequence=seq,
    )
    new_session_id = _session_id_from_token(new_token)
    session_key = generate_session_key()
    encrypted_key = encrypt_session_key(session_key, req.hwid_hash, license_id)

    # Transfer session
    await redis_client.delete_session(session_id, license_id)
    await redis_client.create_session(
        session_id=new_session_id,
        license_id=license_id,
        hwid_hash=req.hwid_hash,
        product_slug=claims["product_slug"],
        sequence=seq,
        ttl=settings.session_key_ttl_seconds + settings.grace_period_seconds,
    )

    # Update activation last_seen
    act_result = await db.execute(
        select(Activation).where(
            Activation.license_id == license_id,
            Activation.hwid_hash == req.hwid_hash,
        )
    )
    act = act_result.scalar_one_or_none()
    if act:
        act.last_seen = datetime.utcnow()
        await db.commit()

    next_heartbeat = now + settings.heartbeat_interval_seconds

    return HeartbeatResponse(
        session_key_hex=encrypted_key,
        expires_at=expires_at,
        next_heartbeat=next_heartbeat,
    )
