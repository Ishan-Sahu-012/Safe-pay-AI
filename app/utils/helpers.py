# app/utils/helpers.py

"""
==============================================================================
SafePay AI — Utility Helpers
==============================================================================

Purpose
-------
Central reusable helper utilities.

Features
--------
✅ JWT helpers
✅ Password hashing
✅ Response formatter
✅ File validators
✅ Time helpers
✅ Random generators
✅ Security utilities
✅ Data sanitization
✅ Retry wrappers
✅ Async helpers

Used By
-------
1. Routes
2. Middleware
3. Services
4. ML Pipelines
5. Database Layer

Architecture
-------------
helpers.py
    ↓
Entire Backend

==============================================================================
"""

import hashlib
import os
import random
import re
import secrets
import string
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from jose import jwt
from passlib.context import CryptContext

from app.utils.constants import  (

    ACCESS_TOKEN_EXPIRE_MINUTES,

    JWT_ALGORITHM,

    JWT_SECRET_KEY
)

from app.utils.logger import logger

# ============================================================================
# PASSWORD HASHING
# ============================================================================

pwd_context = CryptContext(

    schemes=["bcrypt"],

    deprecated="auto"
)

# ============================================================================
# PASSWORD HELPERS
# ============================================================================

def hash_password(password: str):

    """
    Hash user password.
    """

    return pwd_context.hash(password)

# ----------------------------------------------------------------------------

def verify_password(

    plain_password: str,

    hashed_password: str
):

    """
    Verify password hash.
    """

    return pwd_context.verify(

        plain_password,

        hashed_password
    )

# ============================================================================
# JWT HELPERS
# ============================================================================

def create_access_token(

    data: dict,

    expires_delta: timedelta | None = None
):

    """
    Generate JWT token.
    """

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + (

        expires_delta

        or

        timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    to_encode.update({

        "exp": expire
    })

    encoded_jwt = jwt.encode(

        to_encode,

        JWT_SECRET_KEY,

        algorithm=JWT_ALGORITHM
    )

    return encoded_jwt

# ----------------------------------------------------------------------------

def decode_access_token(token: str):

    """
    Decode JWT token.
    """

    try:

        payload = jwt.decode(

            token,

            JWT_SECRET_KEY,

            algorithms=[JWT_ALGORITHM]
        )

        return payload

    except Exception as e:

        logger.error(
            f"❌ JWT Decode Failed: {str(e)}"
        )

        return None

# ============================================================================
# RESPONSE HELPERS
# ============================================================================

def success_response(

    message="Success",

    data=None,

    status_code=200
):

    """
    Standard success response.
    """

    return {

        "success": True,

        "status_code": status_code,

        "message": message,

        "timestamp":
            datetime.utcnow(),

        "data": data
    }

# ----------------------------------------------------------------------------

def error_response(

    message="Error",

    error=None,

    status_code=400
):

    """
    Standard error response.
    """

    return {

        "success": False,

        "status_code": status_code,

        "message": message,

        "error": error,

        "timestamp":
            datetime.utcnow()
    }

# ============================================================================
# RANDOM HELPERS
# ============================================================================

def generate_otp(length=6):

    """
    Generate numeric OTP.
    """

    return "".join(

        random.choice(string.digits)

        for _ in range(length)
    )

# ----------------------------------------------------------------------------

def generate_secure_token(length=32):

    """
    Generate cryptographically secure token.
    """

    return secrets.token_hex(length)

# ----------------------------------------------------------------------------

def generate_uuid():

    """
    Generate UUID4.
    """

    return str(uuid.uuid4())

# ============================================================================
# HASH HELPERS
# ============================================================================

def sha256_hash(text: str):

    """
    SHA256 hashing utility.
    """

    return hashlib.sha256(

        text.encode()

    ).hexdigest()

# ============================================================================
# FILE HELPERS
# ============================================================================

def allowed_file(

    filename: str,

    allowed_extensions: set
):

    """
    Validate file extension.
    """

    return (

        "." in filename

        and

        filename.rsplit(".", 1)[1].lower()

        in

        {

            ext.replace(".", "").lower()

            for ext in allowed_extensions
        }
    )

# ----------------------------------------------------------------------------

def get_file_size_mb(file_bytes: bytes):

    """
    Convert file size into MB.
    """

    return round(

        len(file_bytes)

        /

        (1024 * 1024),

        2
    )

# ----------------------------------------------------------------------------

def sanitize_filename(filename: str):

    """
    Secure filename sanitizer.
    """

    filename = re.sub(

        r"[^a-zA-Z0-9._-]",

        "_",

        filename
    )

    return filename

# ============================================================================
# TEXT HELPERS
# ============================================================================

def clean_text(text: str):

    """
    Basic text cleaner.
    """

    if not text:

        return ""

    text = text.lower()

    text = re.sub(

        r"http\S+|www\S+",

        " ",

        text
    )

    text = re.sub(

        r"<[^>]+>",

        " ",

        text
    )

    text = re.sub(

        r"[^a-zA-Z0-9\s]",

        " ",

        text
    )

    text = re.sub(

        r"\s+",

        " ",

        text
    )

    return text.strip()

# ----------------------------------------------------------------------------

def extract_urls(text: str):

    """
    Extract URLs from text.
    """

    return re.findall(

        r"(https?://\S+|www\.\S+)",

        text
    )

# ----------------------------------------------------------------------------

def extract_emails(text: str):

    """
    Extract email addresses.
    """

    return re.findall(

        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",

        text
    )

# ----------------------------------------------------------------------------

def extract_phone_numbers(text: str):

    """
    Extract Indian phone numbers.
    """

    return re.findall(

        r"\b[6-9]\d{9}\b",

        text
    )

# ============================================================================
# TIME HELPERS
# ============================================================================

def utc_now():

    """
    Current UTC timestamp.
    """

    return datetime.utcnow()

# ----------------------------------------------------------------------------

def current_timestamp():

    """
    UNIX timestamp.
    """

    return int(time.time())

# ----------------------------------------------------------------------------

def format_datetime(dt: datetime):

    """
    Human-readable datetime.
    """

    return dt.strftime(

        "%Y-%m-%d %H:%M:%S"
    )

# ----------------------------------------------------------------------------

def seconds_to_human(seconds: int):

    """
    Convert seconds into readable format.
    """

    hours = seconds // 3600

    minutes = (seconds % 3600) // 60

    secs = seconds % 60

    return f"{hours}h {minutes}m {secs}s"

# ============================================================================
# SECURITY HELPERS
# ============================================================================

def mask_email(email: str):

    """
    Mask sensitive email.
    """

    if "@" not in email:

        return email

    name, domain = email.split("@")

    masked = name[:2] + "*" * max(

        len(name) - 2,

        1
    )

    return f"{masked}@{domain}"

# ----------------------------------------------------------------------------

def mask_phone(phone: str):

    """
    Mask phone number.
    """

    if len(phone) < 4:

        return phone

    return "*" * 6 + phone[-4:]

# ----------------------------------------------------------------------------

def detect_sql_injection(text: str):

    """
    Basic SQL injection detection.
    """

    patterns = [

        "select ",

        "drop ",

        "insert ",

        "delete ",

        "update ",

        "--",

        ";",

        " or ",

        " union "
    ]

    lower = text.lower()

    return any(

        pattern in lower

        for pattern in patterns
    )

# ----------------------------------------------------------------------------

def detect_xss(text: str):

    """
    Basic XSS detection.
    """

    patterns = [

        "<script",

        "javascript:",

        "onerror=",

        "onload=",

        "<iframe"
    ]

    lower = text.lower()

    return any(

        pattern in lower

        for pattern in patterns
    )

# ============================================================================
# RETRY DECORATOR
# ============================================================================

def retry(

    retries=3,

    delay=1
):

    """
    Retry wrapper decorator.
    """

    def decorator(func):

        @wraps(func)

        def wrapper(*args, **kwargs):

            last_exception = None

            for attempt in range(retries):

                try:

                    return func(*args, **kwargs)

                except Exception as e:

                    last_exception = e

                    logger.warning(
                        f"""
⚠️ Retry Attempt:
{attempt + 1}

Function:
{func.__name__}

Error:
{str(e)}
"""
                    )

                    time.sleep(delay)

            raise last_exception

        return wrapper

    return decorator

# ============================================================================
# PERFORMANCE TIMER
# ============================================================================

def execution_timer(func):

    """
    Measure execution time.
    """

    @wraps(func)

    def wrapper(*args, **kwargs):

        start = time.time()

        result = func(*args, **kwargs)

        duration = round(

            (time.time() - start) * 1000,

            2
        )

        logger.info(
            f"""
⏱️ Execution Time

Function:
{func.__name__}

Duration:
{duration} ms
"""
        )

        return result

    return wrapper

# ============================================================================
# ENV HELPERS
# ============================================================================

def get_env(

    key: str,

    default=None
):

    """
    Read environment variable.
    """

    return os.getenv(key, default)

# ----------------------------------------------------------------------------

def str_to_bool(value):

    """
    String to boolean converter.
    """

    return str(value).lower() in [

        "true",

        "1",

        "yes"
    ]

# ============================================================================
# PAGINATION
# ============================================================================

def paginate(

    items,

    page=1,

    page_size=10
):

    """
    Simple pagination helper.
    """

    start = (page - 1) * page_size

    end = start + page_size

    return {

        "items": items[start:end],

        "page": page,

        "page_size": page_size,

        "total_items": len(items),

        "total_pages":

            (len(items) + page_size - 1)

            //

            page_size
    }

# ============================================================================
# DEBUG
# ============================================================================

if __name__ == "__main__":

    print(
        """
🚀 SafePay Helpers Loaded
"""
    )

    print(

        f"""
🔐 OTP:
{generate_otp()}

🆔 UUID:
{generate_uuid()}

🔑 Token:
{generate_secure_token(8)}
"""
    )