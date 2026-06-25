# app/api/middleware/logging_middleware.py
import time

import uuid
import traceback

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.utils.logger import logger

# ============================================================================
# Logging Middleware
# ============================================================================

class LoggingMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        # ====================================================================
        # Unique Request ID
        # ====================================================================

        request_id = str(uuid.uuid4())[:8]

        # Attach request id globally
        request.state.request_id = request_id

        # ====================================================================
        # Request Start Time
        # ====================================================================

        start_time = time.time()

        # ====================================================================
        # Basic Request Info
        # ====================================================================

        method = request.method
        path = request.url.path
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "Unknown")

        # ====================================================================
        # Request Logging
        # ====================================================================

        logger.info(
            f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚀 REQUEST STARTED

🆔 Request ID : {request_id}
📡 Method     : {method}
🌐 Path       : {path}
🖥️ Client IP  : {client_ip}
📱 User-Agent : {user_agent}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        # ====================================================================
        # Process Request (do not consume body — breaks JSON POST handlers)
        # ====================================================================

        try:

            response = await call_next(request)

        # ====================================================================
        # Exception Handling
        # ====================================================================

        except Exception as e:

            execution_time = round((time.time() - start_time) * 1000, 2)

            error_trace = traceback.format_exc()

            logger.error(
                f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💥 INTERNAL SERVER ERROR

🆔 Request ID : {request_id}
📡 Method     : {method}
🌐 Path       : {path}
⏱️ Time       : {execution_time} ms

❌ Error:
{str(e)}

🧠 Traceback:
{error_trace}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            )

            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "message": "Internal server error",
                    "request_id": request_id
                }
            )

        # ====================================================================
        # Calculate Response Time
        # ====================================================================

        execution_time = round((time.time() - start_time) * 1000, 2)

        # ====================================================================
        # Add Extra Headers
        # ====================================================================

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(execution_time)

        # ====================================================================
        # Response Logging
        # ====================================================================

        status_emoji = (
            "✅" if response.status_code < 400
            else "⚠️" if response.status_code < 500
            else "💥"
        )

        logger.info(
            f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{status_emoji} RESPONSE SENT

🆔 Request ID : {request_id}
📡 Method     : {method}
🌐 Path       : {path}
📊 Status     : {response.status_code}
⏱️ Time       : {execution_time} ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        # ====================================================================
        # Slow API Detection
        # ====================================================================

        if execution_time > 2000:

            logger.warning(
                f"""
🐢 SLOW API DETECTED

🆔 Request ID : {request_id}
🌐 Path       : {path}
⏱️ Time       : {execution_time} ms
"""
            )

        return response