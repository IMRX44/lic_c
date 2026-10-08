"""
Client-facing API: activate, heartbeat, WebSocket push.
"""
import asyncio
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas import ActivateRequest, ActivateResponse, HeartbeatRequest, HeartbeatResponse
from app.licensing import activate_license, process_heartbeat
from app.websocket_manager import manager
from app.crypto import verify_session_token
from app import redis_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["license"])


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/activate", response_model=ActivateResponse)
async def activate(
    req: ActivateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Activate a license key for a specific HWID and product."""
    client_ip = get_client_ip(request)
    return await activate_license(req, db, client_ip)


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    req: HeartbeatRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Renew session token. Must be called before session_key expires."""
    client_ip = get_client_ip(request)
    return await process_heartbeat(req, db, client_ip)


@router.websocket("/ws/{session_token}")
async def websocket_endpoint(
    websocket: WebSocket,
    session_token: str,
):
    """
    WebSocket connection for immediate push messages (revoke, warn).
    Client connects after activation and keeps connection open.
    """
    claims = verify_session_token(session_token)
    if not claims:
        await websocket.close(code=4001)
        return

    license_id = claims["license_id"]
    await manager.connect(license_id, websocket)

    try:
        # Keep connection alive; listen for pings from client
        while True:
            try:
                # Wait for client ping (keepalive)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=120)
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                # Client should be pinging every 60s; if 120s pass with nothing, disconnect
                break
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(license_id, websocket)
