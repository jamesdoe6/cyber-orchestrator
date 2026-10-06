"""WebSocket live progress for scan runs."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..config import settings
from ..events import bus

router = APIRouter()


@router.websocket("/ws/engagements/{eid}")
async def engagement_ws(websocket: WebSocket, eid: int):
    # Auth: HTTP middleware does not cover WebSockets, so check the token here.
    token = settings.api_token
    if token:
        supplied = websocket.query_params.get("token")
        if not supplied or not secrets.compare_digest(str(supplied), str(token)):
            await websocket.close(code=1008)
            return
    await websocket.accept()
    q = bus.subscribe(eid)
    try:
        await websocket.send_json({"type": "hello", "engagement_id": eid})
        while True:
            event = await q.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - client closed abruptly
        pass
    finally:
        bus.unsubscribe(eid, q)
