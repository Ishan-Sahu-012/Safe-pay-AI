# app/api/routes/auth_routes.py

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from jose import jwt
from pydantic import BaseModel, EmailStr
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.database.db import get_db
from app.database.models import User
from app.utils.logger import logger
from app.utils.password import hash_password, verify_password
from app.utils.validators import validate_phone, validate_password
from app.dependencies import get_current_user

# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

# ============================================================================
# JWT Configuration
# ============================================================================

ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

# ============================================================================
# Request Models
# ============================================================================

class RegisterRequest(BaseModel):

    name: str

    email: EmailStr

    phone: str

    password: str


class LoginRequest(BaseModel):

    phone: Optional[str] = None

    email: Optional[EmailStr] = None

    password: str


# ============================================================================
# Utility Functions
# ============================================================================

def create_access_token(data: dict):

    payload = data.copy()

    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    sub_value = data.get("user_id") or data.get("sub")

    payload.update({
        "exp": expire
    })

    if sub_value is not None:
        payload["sub"] = str(sub_value)

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    return token


# ============================================================================
# REGISTER API
# ============================================================================

@router.post("/register")

async def register_user(
    data: RegisterRequest,
    db=Depends(get_db)
):

    # ------------------------------------------------------------------------
    # Validate Input
    # ------------------------------------------------------------------------

    if not validate_phone(data.phone):
        raise HTTPException(
            status_code=400,
            detail="Phone number format is invalid"
        )

    password_validation = validate_password(data.password)
    if not password_validation["valid"]:
        raise HTTPException(
            status_code=400,
            detail=password_validation["message"]
        )

    normalized_email = data.email.lower().strip()
    normalized_phone = data.phone.strip()

    # ------------------------------------------------------------------------
    # Check Existing User
    # ------------------------------------------------------------------------

    existing_user = db.query(User).filter(
        User.phone == normalized_phone
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Phone number already registered"
        )

    existing_email = db.query(User).filter(
        User.email == normalized_email
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email address already registered"
        )

    # ------------------------------------------------------------------------
    # Create New User
    # ------------------------------------------------------------------------

    hashed_password = hash_password(data.password)

    new_user = User(
        name=data.name.strip(),
        email=normalized_email,
        phone=normalized_phone,
        password=hashed_password
    )

    db.add(new_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Registration failed due to duplicate user data"
        )
    db.refresh(new_user)
    logger.info(
        f"✅ New user registered: {new_user.phone}"
    )

    # ------------------------------------------------------------------------
    # Generate JWT Token
    # ------------------------------------------------------------------------

    access_token = create_access_token({

        "user_id": new_user.id,

        "phone": new_user.phone,

        "name": new_user.name,

        "email": new_user.email,

        "role": new_user.role or "user",
    })

    # ------------------------------------------------------------------------
    # Response
    # ------------------------------------------------------------------------

    return {

        "success": True,

        "message": "User registered successfully",

        "access_token": access_token,

        "token_type": "bearer",

        "user": {

            "id": new_user.id,

            "name": new_user.name,

            "email": new_user.email,

            "phone": new_user.phone
        }
    }


# ============================================================================
# LOGIN API
# ============================================================================

@router.post("/login")

async def login_user(
    data: LoginRequest,
    db=Depends(get_db)
):

    if not data.password or (not data.phone and not data.email):
        raise HTTPException(
            status_code=400,
            detail="Phone or email and password are required"
        )

    # ------------------------------------------------------------------------
    # Find User
    # ------------------------------------------------------------------------

    user = None
    if data.phone:
        normalized_phone = data.phone.strip()
        if not validate_phone(normalized_phone):
            raise HTTPException(
                status_code=401,
                detail="Invalid phone or password"
            )
        user = db.query(User).filter(
            User.phone == normalized_phone
        ).first()
    else:
        normalized_email = data.email.lower().strip()
        user = db.query(User).filter(
            User.email == normalized_email
        ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid phone or password"
        )

    # ------------------------------------------------------------------------
    # Verify Password
    # ------------------------------------------------------------------------

    valid_password = verify_password(
        data.password,
        user.password
    )

    if not valid_password:
        raise HTTPException(
            status_code=401,
            detail="Invalid phone or password"
        )

    logger.info(
        f"🔓 Login success: {user.phone}"
    )

    # ------------------------------------------------------------------------
    # Generate JWT Token
    # ------------------------------------------------------------------------

    access_token = create_access_token({

        "user_id": user.id,

        "phone": user.phone,

        "name": user.name,

        "email": user.email,

        "role": user.role or "user",
    })

    # ------------------------------------------------------------------------
    # Response
    # ------------------------------------------------------------------------

    return {

        "success": True,

        "message": "Login successful",

        "access_token": access_token,

        "token_type": "bearer",

        "user": {

            "id": user.id,

            "name": user.name,

            "email": user.email,

            "phone": user.phone
        }
    }


# ============================================================================
# PROFILE API
# ============================================================================

@router.get("/profile")

async def get_profile(
    current_user=Depends(get_current_user),
    db=Depends(get_db)
):

    user_id = current_user["user_id"]
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        pass

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {

        "success": True,

        "user": {

            "id": user.id,

            "name": user.name,

            "email": user.email,

            "phone": user.phone
        }
    }


@router.get("/me")
async def get_me(
    current_user=Depends(get_current_user),
    db=Depends(get_db)
):
    return await get_profile(current_user=current_user, db=db)


# ============================================================================
# REFRESH TOKEN API
# ============================================================================

@router.post("/refresh-token")

async def refresh_token(
    current_user=Depends(get_current_user)
):

    new_token = create_access_token({

        "user_id": current_user["user_id"],

        "phone": current_user.get("phone"),

        "name": current_user.get("name"),

        "email": current_user.get("email"),

        "role": current_user.get("role", "user"),
    })

    return {

        "success": True,

        "access_token": new_token,

        "token_type": "bearer"
    }


# ============================================================================
# LOGOUT API
# ============================================================================

@router.post("/logout")

async def logout_user():

    """
    For JWT logout:
    Usually frontend deletes token.

    Advanced production systems:
    - Redis blacklist
    - Token revocation
    - Refresh token invalidation
    """

    return {

        "success": True,

        "message": "Logged out successfully"
    }


# ============================================================================
# HEALTH CHECK
# ============================================================================

@router.get("/health")

async def auth_health():

    return {

        "success": True,

        "service": "Auth Service",

        "status": "Running"
    }