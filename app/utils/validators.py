# app/utils/validators.py

"""
==============================================================================
SafePay AI — Validation Engine
==============================================================================

Purpose
-------
Centralized validation utilities.

Features
--------
✅ Email validation
✅ Password validation
✅ UPI validation
✅ URL validation
✅ Phone validation
✅ OTP validation
✅ File validation
✅ Fraud input sanitization
✅ XSS prevention
✅ SQL injection prevention
✅ Request payload validation

Used By
-------
1. Routes
2. Services
3. Middleware
4. Authentication
5. Fraud Detection

Architecture
-------------
validators.py
    ↓
Entire Backend

==============================================================================
"""

import re
from urllib.parse import urlparse

from app.utils.logger import logger

# ============================================================================
# EMAIL REGEX
# ============================================================================

EMAIL_REGEX = re.compile(

    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)

# ============================================================================
# PHONE REGEX
# ============================================================================

PHONE_REGEX = re.compile(

    r"^[6-9]\d{9}$"
)

# ============================================================================
# UPI REGEX
# ============================================================================

UPI_REGEX = re.compile(

    r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$"
)

# ============================================================================
# PASSWORD VALIDATION
# ============================================================================

# Password complexity checks are intentionally disabled.
# Only a non-empty password is required for registration.

# ============================================================================
# OTP REGEX
# ============================================================================

OTP_REGEX = re.compile(

    r"^\d{4,8}$"
)

# ============================================================================
# URL REGEX
# ============================================================================

URL_REGEX = re.compile(

    r"^(https?:\/\/)?"
    r"(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})"
    r"(\/.*)?$"
)

# ============================================================================
# SQL INJECTION PATTERNS
# ============================================================================

SQLI_PATTERNS = [

    "select ",

    "drop ",

    "insert ",

    "delete ",

    "update ",

    "--",

    ";",

    " union ",

    " or ",

    "exec ",

    "xp_"
]

# ============================================================================
# XSS PATTERNS
# ============================================================================

XSS_PATTERNS = [

    "<script",

    "</script>",

    "javascript:",

    "onerror=",

    "onload=",

    "<iframe",

    "alert(",

    "document.cookie"
]

# ============================================================================
# VALIDATE EMAIL
# ============================================================================

def validate_email(email: str):

    """
    Validate email format.
    """

    try:

        if not email:

            return False

        return bool(

            EMAIL_REGEX.match(email)
        )

    except Exception as e:

        logger.error(
            f"❌ Email validation failed: {str(e)}"
        )

        return False

# ============================================================================
# VALIDATE PHONE
# ============================================================================

def validate_phone(phone: str):

    """
    Validate Indian mobile number.
    """

    try:

        if not phone:

            return False

        return bool(

            PHONE_REGEX.match(phone)
        )

    except Exception as e:

        logger.error(
            f"❌ Phone validation failed: {str(e)}"
        )

        return False

# ============================================================================
# VALIDATE PASSWORD
# ============================================================================

def validate_password(password: str):

    """
    Password validator with no enforced complexity rules.
    """

    try:

        if not password or not str(password).strip():

            return {

                "valid": False,

                "message":
                    "Password required"
            }

        return {

            "valid": True,

            "message":
                "Password valid"
        }

    except Exception as e:

        logger.error(
            f"❌ Password validation failed: {str(e)}"
        )

        return {
            "valid": False,
            "message": "Password validation failed"
        }

# ============================================================================
# VALIDATE UPI
# ============================================================================

def validate_upi_id(upi_id: str):

    """
    Validate UPI ID.
    """

    try:

        if not upi_id:

            return False

        upi_id = upi_id.strip()

        return bool(

            UPI_REGEX.match(upi_id)
        )

    except Exception as e:

        logger.error(
            f"❌ UPI validation failed: {str(e)}"
        )

        return False

# ============================================================================
# VALIDATE OTP
# ============================================================================

def validate_otp(otp: str):

    """
    Validate OTP format.
    """

    try:

        if not otp:

            return False

        return bool(

            OTP_REGEX.match(str(otp))
        )

    except Exception as e:

        logger.error(
            f"❌ OTP validation failed: {str(e)}"
        )

        return False

# ============================================================================
# VALIDATE URL
# ============================================================================

def validate_url(url: str):

    """
    Validate URL format.
    """

    try:

        if not url:

            return False

        parsed = urlparse(url)

        return bool(

            parsed.scheme

            and

            parsed.netloc
        )

    except Exception as e:

        logger.error(
            f"❌ URL validation failed: {str(e)}"
        )

        return False

# ============================================================================
# VALIDATE FILE EXTENSION
# ============================================================================

def validate_file_extension(

    filename: str,

    allowed_extensions: set
):

    """
    Validate uploaded file extension.
    """

    try:

        if "." not in filename:

            return False

        extension = (

            filename.rsplit(".", 1)[1]

            .lower()
        )

        cleaned = {

            ext.replace(".", "").lower()

            for ext in allowed_extensions
        }

        return extension in cleaned

    except Exception as e:

        logger.error(
            f"❌ File validation failed: {str(e)}"
        )

        return False

# ============================================================================
# VALIDATE FILE SIZE
# ============================================================================

def validate_file_size(

    size_bytes: int,

    max_size_mb: int
):

    """
    Validate upload size.
    """

    try:

        max_bytes = max_size_mb * 1024 * 1024

        return size_bytes <= max_bytes

    except Exception as e:

        logger.error(
            f"❌ File size validation failed: {str(e)}"
        )

        return False

# ============================================================================
# DETECT SQL INJECTION
# ============================================================================

def detect_sql_injection(text: str):

    """
    SQL injection detector.
    """

    try:

        if not text:

            return False

        lower = text.lower()

        return any(

            pattern in lower

            for pattern in SQLI_PATTERNS
        )

    except Exception as e:

        logger.error(
            f"❌ SQLi detection failed: {str(e)}"
        )

        return False

# ============================================================================
# DETECT XSS
# ============================================================================

def detect_xss(text: str):

    """
    XSS attack detector.
    """

    try:

        if not text:

            return False

        lower = text.lower()

        return any(

            pattern in lower

            for pattern in XSS_PATTERNS
        )

    except Exception as e:

        logger.error(
            f"❌ XSS detection failed: {str(e)}"
        )

        return False

# ============================================================================
# SANITIZE TEXT
# ============================================================================

def sanitize_text(text: str):

    """
    Remove malicious patterns.
    """

    try:

        if not text:

            return ""

        text = re.sub(

            r"<[^>]*>",

            "",

            text
        )

        text = re.sub(

            r"[\"'`;]",

            "",

            text
        )

        text = re.sub(

            r"\s+",

            " ",

            text
        )

        return text.strip()

    except Exception as e:

        logger.error(
            f"❌ Sanitization failed: {str(e)}"
        )

        return ""

# ============================================================================
# VALIDATE FRAUD PAYLOAD
# ============================================================================

def validate_fraud_payload(payload: dict):

    """
    Validate fraud analysis request.
    """

    try:

        required = [

            "upi_id",

            "amount"
        ]

        missing = [

            field

            for field in required

            if field not in payload
        ]

        if missing:

            return {

                "valid": False,

                "message":
                    f"Missing fields: {missing}"
            }

        # --------------------------------------------------------------------
        # UPI
        # --------------------------------------------------------------------

        if not validate_upi_id(

            payload["upi_id"]
        ):

            return {

                "valid": False,

                "message":
                    "Invalid UPI ID"
            }

        # --------------------------------------------------------------------
        # Amount
        # --------------------------------------------------------------------

        try:

            amount = float(

                payload["amount"]
            )

            if amount <= 0:

                return {

                    "valid": False,

                    "message":
                        "Invalid amount"
                }

        except:

            return {

                "valid": False,

                "message":
                    "Amount must be numeric"
            }

        return {

            "valid": True,

            "message":
                "Payload valid"
        }

    except Exception as e:

        logger.error(
            f"❌ Fraud payload validation failed: {str(e)}"
        )

        return {

            "valid": False,

            "message":
                "Validation error"
        }

# ============================================================================
# VALIDATE SMS PAYLOAD
# ============================================================================

def validate_sms_payload(payload: dict):

    """
    Validate SMS request.
    """

    try:

        if "text" not in payload:

            return {

                "valid": False,

                "message":
                    "SMS text missing"
            }

        text = payload["text"]

        if not isinstance(text, str):

            return {

                "valid": False,

                "message":
                    "Text must be string"
            }

        if len(text) < 2:

            return {

                "valid": False,

                "message":
                    "SMS too short"
            }

        if len(text) > 10000:

            return {

                "valid": False,

                "message":
                    "SMS too large"
            }

        return {

            "valid": True,

            "message":
                "SMS payload valid"
        }

    except Exception as e:

        logger.error(
            f"❌ SMS payload validation failed: {str(e)}"
        )

        return {

            "valid": False,

            "message":
                "Validation failed"
        }

# ============================================================================
# VALIDATE LOGIN PAYLOAD
# ============================================================================

def validate_login_payload(payload: dict):

    """
    Login request validation.
    """

    try:

        email = payload.get("email")

        password = payload.get("password")

        if not validate_email(email):

            return {

                "valid": False,

                "message":
                    "Invalid email"
            }

        if not password:

            return {

                "valid": False,

                "message":
                    "Password required"
            }

        return {

            "valid": True,

            "message":
                "Login payload valid"
        }

    except Exception as e:

        logger.error(
            f"❌ Login validation failed: {str(e)}"
        )

        return {

            "valid": False,

            "message":
                "Validation failed"
        }

# ============================================================================
# DEBUG TEST
# ============================================================================

if __name__ == "__main__":

    print(
        """
🚀 SafePay Validators Ready
"""
    )

    print(

        f"""
📧 Email:
{validate_email('rahul@gmail.com')}

📱 Phone:
{validate_phone('9876543210')}

🏦 UPI:
{validate_upi_id('rahul123@oksbi')}

🔐 Password:
{validate_password('StrongPass123@')}

🌐 URL:
{validate_url('https://google.com')}
"""
    )