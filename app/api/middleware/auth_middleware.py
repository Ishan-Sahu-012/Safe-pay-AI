# app/api/middleware/auth_middleware.py

from fastapi import Request
from jose import jwt, JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import settings
from app.utils.logger import logger

# ============================================================================
# PUBLIC ROUTES (no Bearer token required)
# ============================================================================

PUBLIC_PREFIXES = [
    "/docs",
    "/redoc",
    "/openapi.json",
    "/auth/login",
    "/auth/register",
    "/auth/health",
    "/health",
    "/fraud/health",
    "/qr/health",
    "/sms/health",
    "/ping",
    "/system/info",
    "/dashboard",
    "/static",
    "/ws",
]


def verify_jwt_token(token: str) -> dict:
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )


def _normalize_user(payload: dict) -> dict:
    """Map JWT claims to the shape used by route dependencies."""
    user_id = payload.get("sub") or payload.get("user_id")
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        pass
    return {
        "user_id": user_id,
        "email": payload.get("email"),
        "phone": payload.get("phone"),
        "name": payload.get("name"),
        "role": payload.get("role", "user"),
        "token_payload": payload,
    }


class AuthMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        request.state.user = None

        if request.method == "OPTIONS":
            return await call_next(request)

        if path == "/" or any(
            path == route or path.startswith(route + "/")
            for route in PUBLIC_PREFIXES
        ):
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "message": "Authorization token missing",
                },
            )

        try:
            scheme, token = auth_header.split(maxsplit=1)
            if scheme.lower() != "bearer":
                return JSONResponse(
                    status_code=401,
                    content={
                        "success": False,
                        "message": "Authorization must be Bearer token",
                    },
                )
        except ValueError:
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "message": "Invalid authorization format",
                },
            )

        try:
            payload = verify_jwt_token(token)
            request.state.user = _normalize_user(payload)
        except JWTError as e:
            logger.warning(f"JWT validation failed for {path}: {e}")
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "message": "Invalid or expired token",
                },
            )

        return await call_next(request)
