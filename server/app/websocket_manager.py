"""
WebSocket connection manager.
- Keeps track of active WS connections per license.
- Used to push revoke/warn messages immediately when admin acts.
"""
import asyncio
import json
import logging
from typing import Optional
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        # license_id -> list of WebSocket connections
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, license_id: str, websocket: WebSocket):
        await websocket.accept()
        if license_id not in self._connections:
            self._connections[license_id] = []
        self._connections[license_id].append(websocket)
        logger.info(f"WS connected for license {license_id[:8]}... total={len(self._connections[license_id])}")

    def disconnect(self, license_id: str, websocket: WebSocket):
        if license_id in self._connections:
            try:
                self._connections[license_id].remove(websocket)
            except ValueError:
                pass
            if not self._connections[license_id]:
                del self._connections[license_id]

    async def send_to_license(self, license_id: str, message: dict) -> int:
        """Send message to all connections of a license. Returns count sent."""
        if license_id not in self._connections:
            return 0

        payload = json.dumps(message)
        dead = []
        sent = 0

        for ws in list(self._connections[license_id]):
            try:
                await ws.send_text(payload)
                sent += 1
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(license_id, ws)

        return sent

    async def revoke_license(self, license_id: str, reason: str = "license_revoked") -> int:
        """Push immediate revoke signal to all active connections."""
        return await self.send_to_license(license_id, {
            "action": "revoke",
            "reason": reason,
            "countdown_seconds": 10,
            "message": "لایسنس شما غیرفعال شد. برنامه در ۱۰ ثانیه بسته می‌شود."
        })

    async def warn_license(self, license_id: str, message: str) -> int:
        """Push a warning to all active connections."""
        return await self.send_to_license(license_id, {
            "action": "warn",
            "message": message,
        })

    def get_active_count(self, license_id: str) -> int:
        return len(self._connections.get(license_id, []))

    def total_connections(self) -> int:
        return sum(len(v) for v in self._connections.values())


manager = ConnectionManager()
