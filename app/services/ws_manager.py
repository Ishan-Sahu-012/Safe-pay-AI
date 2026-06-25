# app/services/ws_manager.py

import asyncio
from fastapi import WebSocket
from app.utils.logger import logger

class ConnectionManager:
    """
    Manages active WebSocket connections for push threat feeds.
    Includes robust disconnection pruning to avoid memory leaks.
    """
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket, user: dict):
        """
        Accept connection and track it.
        """
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"🔌 WebSocket client connected | User: {user.get('email') or user.get('user_id')} | Total connections: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        """
        Remove connection from tracking list.
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                f"🔌 WebSocket client disconnected | Total connections: {len(self.active_connections)}"
            )

    async def broadcast(self, message: dict):
        """
        Broadcast JSON message to all active clients.
        Failed transfers trigger immediate socket closure and cleanup to prevent leaks.
        """
        if not self.active_connections:
            return

        logger.info(f"📢 Broadcasting real-time alert to {len(self.active_connections)} client(s): {message}")
        
        disconnected_sockets = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"⚠️ Failed to transmit JSON to client: {str(e)}")
                disconnected_sockets.append(connection)

        # Cleanup failed connections
        for connection in disconnected_sockets:
            self.disconnect(connection)

# Global singleton
ws_manager = ConnectionManager()
