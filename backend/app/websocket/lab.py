"""/ws/lab WebSocket endpoint.

Accepts signed JSON payloads, runs them through the dispatcher, and returns a
signed-style response envelope. Also handles heartbeat messages for
connection-state / offline detection. Confined to the lab network.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..state import lab_state

router = APIRouter()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@router.websocket("/ws/lab")
async def lab_ws(websocket: WebSocket) -> None:
    await websocket.accept()
    client = f"{websocket.client.host}:{websocket.client.port}" if websocket.client else "unknown"
    device_id: str | None = None
    try:
        while True:
            raw = await websocket.receive_text()
            # Heartbeat is handled separately from command dispatch.
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json(
                    {"type": "RESPONSE", "status": "REJECTED", "reason": "invalid json"}
                )
                continue

            if parsed.get("type") == "heartbeat":
                device_id = parsed.get("deviceId", device_id)
                if device_id:
                    lab_state.active_connections[device_id] = client
                await websocket.send_json(
                    {"type": "heartbeat_ack", "serverTime": _now(), "status": "online"}
                )
                continue

            result = lab_state.dispatcher.dispatch_raw(raw)
            if result.device_id:
                device_id = result.device_id
                lab_state.active_connections[device_id] = client
            await websocket.send_json(
                {
                    "type": "RESPONSE",
                    "status": result.status.value,
                    "requestId": result.request_id,
                    "deviceId": result.device_id,
                    "ruleId": result.rule_id,
                    "reason": result.reason,
                    "result": result.result,
                }
            )
    except WebSocketDisconnect:
        # Offline detection: drop the connection from the active set.
        if device_id and lab_state.active_connections.get(device_id) == client:
            lab_state.active_connections.pop(device_id, None)
