# app/api/routes/ws_routes.py

from fastapi import (
    APIRouter,
    WebSocket,
    Query,
    WebSocketDisconnect,
    status
)
from app.dependencies import decode_token, _user_from_payload
from app.services.ws_manager import ws_manager
from app.utils.logger import logger

router = APIRouter(
    prefix="/ws",
    tags=["WebSocket Alerts"]
)

@router.websocket("/alerts")
async def websocket_alerts(
    websocket: WebSocket,
    token: str = Query(None)
):
    """
    WebSocket threat alert channel.
    Accepts JWT query parameter 'token' for user authentication.
    """
    if not token:
        logger.warning("🔌 WebSocket Connection Refused: Missing JWT token.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    payload = decode_token(token)
    if not payload:
        logger.warning("🔌 WebSocket Connection Refused: Invalid or expired JWT token.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user = _user_from_payload(payload)
    await ws_manager.connect(websocket, user)

    try:
        while True:
            # Maintain connection and support client ping/pong requests
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"❌ WebSocket error: {str(e)}")
        ws_manager.disconnect(websocket)
