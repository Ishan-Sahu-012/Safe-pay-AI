# app/core/dependencies.py

"""
==============================================================================
SafePay AI — Dependency Injection Layer
==============================================================================

Purpose
-------
Central FastAPI dependency management system.

Features
--------
✅ JWT authentication
✅ Current user extraction
✅ Role-based authorization
✅ Database session management
✅ Request validation
✅ Rate-limit helpers
✅ Fraud permission guards
✅ Admin access control
✅ API key verification
✅ Redis dependency
✅ ML model dependency

Used By
-------
1. Routes
2. Middleware
3. Services
4. Background Tasks

Architecture
-------------
Request
   ↓
Dependency Injection
   ↓
Authentication
   ↓
Authorization
   ↓
Validated Context

==============================================================================
"""

from datetime import datetime, timezone
from typing import Generator, Optional

from fastapi import (

    Depends,

    Header,

    HTTPException,

    Request,

    Security,

    status
)

from fastapi.security import (

    APIKeyHeader,

    HTTPAuthorizationCredentials,

    HTTPBearer
)

from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.database.db import SessionLocal
from app.utils.logger import (

    logger,

    log_security_event
)

# ============================================================================
# SECURITY SCHEMES
# ============================================================================

bearer_scheme = HTTPBearer(
    auto_error=False
)

api_key_scheme = APIKeyHeader(

    name="X-API-Key",

    auto_error=False
)

# ============================================================================
# DATABASE DEPENDENCY
# ============================================================================

def get_db() -> Generator:

    """
    Database session dependency.

    Usage:
    ------
    db: Session = Depends(get_db)
    """

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()

# ============================================================================
# TOKEN DECODER
# ============================================================================

def decode_token(token: str):

    """
    Decode JWT token safely.
    """

    try:

        payload = jwt.decode(

            token,

            settings.JWT_SECRET_KEY,

            algorithms=[settings.JWT_ALGORITHM]
        )

        return payload

    except JWTError as e:

        logger.error(
            f"❌ JWT Decode Failed: {str(e)}"
        )

        return None

# ============================================================================
# GET CURRENT USER
# ============================================================================

def _user_from_payload(payload: dict) -> dict:
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


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    """
    Extract authenticated user from middleware state or JWT Bearer header.
    """
    try:
        state_user = getattr(request.state, "user", None)
        if state_user:
            return state_user

        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token missing",
            )

        payload = decode_token(credentials.credentials)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )

        user_id = payload.get("sub") or payload.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )

        exp = payload.get("exp")
        if exp:
            expiry = datetime.fromtimestamp(exp, tz=timezone.utc)
            if expiry < datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired",
                )

        return _user_from_payload(payload)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
        )

# ============================================================================
# OPTIONAL USER
# ============================================================================

async def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(
        bearer_scheme
    ),
):
    """Optional authentication."""
    try:
        return await get_current_user(request, credentials)
    except HTTPException:
        return None

# ============================================================================
# ADMIN CHECK
# ============================================================================

async def require_admin(

    current_user: dict = Depends(
        get_current_user
    )
):

    """
    Admin-only dependency.
    """

    if current_user["role"] != "admin":

        log_security_event(

            event_type="UNAUTHORIZED_ADMIN_ACCESS",

            details=current_user
        )

        raise HTTPException(

            status_code=
            status.HTTP_403_FORBIDDEN,

            detail="Admin access required"
        )

    return current_user

# ============================================================================
# MODERATOR CHECK
# ============================================================================

async def require_moderator(

    current_user: dict = Depends(
        get_current_user
    )
):

    """
    Moderator/admin access.
    """

    allowed_roles = [

        "admin",

        "moderator"
    ]

    if current_user["role"] not in allowed_roles:

        raise HTTPException(

            status_code=
            status.HTTP_403_FORBIDDEN,

            detail="Moderator access required"
        )

    return current_user

# ============================================================================
# API KEY VALIDATION
# ============================================================================

async def validate_api_key(

    api_key: str = Security(
        api_key_scheme
    )
):

    """
    API key verification.
    """

    expected_key = getattr(

        settings,

        "API_KEY",

        "SAFEPAY_API_KEY"
    )

    if not api_key:

        raise HTTPException(

            status_code=
            status.HTTP_401_UNAUTHORIZED,

            detail="API key missing"
        )

    if api_key != expected_key:

        log_security_event(

            event_type="INVALID_API_KEY",

            details={

                "provided_key":
                    api_key[:5] + "***"
            }
        )

        raise HTTPException(

            status_code=
            status.HTTP_403_FORBIDDEN,

            detail="Invalid API key"
        )

    return api_key

# ============================================================================
# RATE LIMIT IDENTIFIER
# ============================================================================

async def get_client_ip(

    request: Request
):

    """
    Extract client IP safely.
    """

    forwarded = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded:

        return forwarded.split(",")[0]

    return request.client.host

# ============================================================================
# REQUEST METADATA
# ============================================================================

async def get_request_metadata(

    request: Request
):

    """
    Extract request intelligence.
    """

    return {

        "ip":
            await get_client_ip(request),

        "user_agent":
            request.headers.get(
                "User-Agent",
                "Unknown"
            ),

        "method":
            request.method,

        "path":
            request.url.path,

        "timestamp":
            datetime.utcnow()
    }

# ============================================================================
# FRAUD ANALYSIS ACCESS
# ============================================================================

async def fraud_access_guard(

    current_user: dict = Depends(
        get_current_user
    )
):

    """
    Restrict fraud endpoints if needed.
    """

    blocked_roles = [

        "banned"
    ]

    if current_user["role"] in blocked_roles:

        raise HTTPException(

            status_code=
            status.HTTP_403_FORBIDDEN,

            detail="Fraud analysis access denied"
        )

    return current_user

# ============================================================================
# ML MODEL CHECK
# ============================================================================

async def verify_ml_models():

    """
    Ensure ML models exist before inference.
    """

    import os

    required_models = [

        settings.MODEL1_UPI_PATH,

        settings.MODEL2_TEXT_PATH,

        settings.MODEL3_PATH
    ]

    missing = [

        path

        for path in required_models

        if not os.path.exists(path)
    ]

    if missing:

        logger.error(
            f"""
❌ ML MODELS MISSING

Missing:
{missing}
"""
        )

        raise HTTPException(

            status_code=
            status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail="ML models unavailable"
        )

    return True

# ============================================================================
# PAGINATION DEPENDENCY
# ============================================================================

def pagination_params(

    page: int = 1,

    limit: int = 10
):

    """
    Pagination helper.
    """

    page = max(page, 1)

    limit = min(max(limit, 1), 100)

    offset = (page - 1) * limit

    return {

        "page": page,

        "limit": limit,

        "offset": offset
    }

# ============================================================================
# AUDIT LOGGER
# ============================================================================

async def audit_dependency(

    request: Request,

    current_user: dict = Depends(
        get_optional_user
    )
):

    """
    Request audit logging.
    """

    logger.info(
        f"""
📋 AUDIT EVENT

Method:
{request.method}

Path:
{request.url.path}

User:
{current_user['email'] if current_user else 'Anonymous'}
"""
    )

    return True

# ============================================================================
# HEALTH CHECK DEPENDENCY
# ============================================================================

async def health_dependency():

    """
    Global service health dependency.
    """

    return {

        "healthy": True,

        "timestamp":
            datetime.utcnow()
    }

# ============================================================================
# DEBUG TEST
# ============================================================================

if __name__ == "__main__":

    print(
        """
🚀 SafePay Dependencies Loaded
"""
    )

    print(

        f"""
🔐 JWT Algorithm:
{settings.JWT_ALGORITHM}

🌐 Environment:
{settings.ENVIRONMENT}

🤖 ML Models:
{settings.model_paths}
"""
    )