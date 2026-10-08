"""
Redis helpers for:
- Active sessions (heartbeat TTL, seat counting)
- Nonce deduplication (replay protection)
- Rate limiting state
"""
import json
import time
from typing import Optional
import redis.asyncio as aioredis
from app.config import settings

_redis: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


# ─── Nonce (replay protection) ────────────────────────────────────────────────

async def check_and_store_nonce(nonce: str, ttl: int = 120) -> bool:
    """Return True if nonce is new (not seen). Stores it for `ttl` seconds."""
    r = await get_redis()
    key = f"nonce:{nonce}"
    result = await r.set(key, "1", nx=True, ex=ttl)
    return result is True  # None means key already existed


# ─── Active sessions ──────────────────────────────────────────────────────────

SESSION_PREFIX = "session:"
SEAT_PREFIX = "seats:"


async def create_session(
    session_id: str,
    license_id: str,
    hwid_hash: str,
    product_slug: str,
    sequence: int,
    ttl: int,
) -> None:
    r = await get_redis()
    data = {
        "license_id": license_id,
        "hwid_hash": hwid_hash,
        "product_slug": product_slug,
        "sequence": sequence,
        "created_at": int(time.time()),
    }
    await r.setex(f"{SESSION_PREFIX}{session_id}", ttl, json.dumps(data))
    # Track active seat
    await r.sadd(f"{SEAT_PREFIX}{license_id}", session_id)
    await r.expire(f"{SEAT_PREFIX}{license_id}", 3600 * 24)


async def get_session(session_id: str) -> Optional[dict]:
    r = await get_redis()
    raw = await r.get(f"{SESSION_PREFIX}{session_id}")
    if raw:
        return json.loads(raw)
    return None


async def refresh_session(session_id: str, ttl: int) -> bool:
    """Refresh session TTL. Returns False if session not found."""
    r = await get_redis()
    result = await r.expire(f"{SESSION_PREFIX}{session_id}", ttl)
    return result == 1


async def delete_session(session_id: str, license_id: str) -> None:
    r = await get_redis()
    await r.delete(f"{SESSION_PREFIX}{session_id}")
    await r.srem(f"{SEAT_PREFIX}{license_id}", session_id)


async def get_active_seat_count(license_id: str) -> int:
    """Count currently active sessions for a license."""
    r = await get_redis()
    # Clean up expired sessions first
    members = await r.smembers(f"{SEAT_PREFIX}{license_id}")
    active = 0
    for sid in members:
        exists = await r.exists(f"{SESSION_PREFIX}{sid}")
        if exists:
            active += 1
        else:
            await r.srem(f"{SEAT_PREFIX}{license_id}", sid)
    return active


async def kill_all_sessions_for_license(license_id: str) -> int:
    """Kill all active sessions for a license (used when revoking/suspending)."""
    r = await get_redis()
    members = await r.smembers(f"{SEAT_PREFIX}{license_id}")
    count = 0
    for sid in members:
        await r.delete(f"{SESSION_PREFIX}{sid}")
        count += 1
    await r.delete(f"{SEAT_PREFIX}{license_id}")
    # Set a revoke signal that WebSocket connections can pick up
    await r.setex(f"revoke:{license_id}", 300, "1")
    return count


async def is_license_revoked(license_id: str) -> bool:
    r = await get_redis()
    return await r.exists(f"revoke:{license_id}") == 1


async def get_all_session_ids_for_license(license_id: str) -> list[str]:
    r = await get_redis()
    return list(await r.smembers(f"{SEAT_PREFIX}{license_id}"))


# ─── Sequence counter (anti-rollback) ─────────────────────────────────────────

async def get_and_increment_sequence(license_id: str) -> int:
    r = await get_redis()
    key = f"seq:{license_id}"
    val = await r.incr(key)
    await r.expire(key, 3600 * 24 * 7)
    return int(val)
