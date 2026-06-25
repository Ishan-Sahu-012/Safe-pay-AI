# app/core/constants.py

"""
==============================================================================
SafePay AI — Global Constants
==============================================================================

Purpose
-------
Centralized configuration and constants.

Benefits
--------
✅ Cleaner architecture
✅ No magic numbers
✅ Easier maintenance
✅ Better scalability
✅ Production standardization

Used By
-------
1. ML Models
2. Services
3. Routes
4. Middleware
5. Security
6. Database
7. Logging
8. Monitoring

Architecture
-------------
constants.py
    ↓
Entire Backend

==============================================================================
"""

from datetime import timedelta

# ============================================================================
# APPLICATION
# ============================================================================

APP_NAME = "SafePay AI"

APP_VERSION = "1.0.0"

APP_DESCRIPTION = """
AI-Powered Fraud Detection Backend
"""

DEBUG_MODE = True

API_PREFIX = "/api/v1"

# ============================================================================
# SERVER CONFIG
# ============================================================================

HOST = "0.0.0.0"

PORT = 8000

WORKERS = 4

REQUEST_TIMEOUT = 60

# ============================================================================
# JWT AUTH
# ============================================================================

JWT_SECRET_KEY = "CHANGE_THIS_TO_SUPER_SECRET_KEY"

JWT_ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

REFRESH_TOKEN_EXPIRE_DAYS = 7

# ============================================================================
# DATABASE
# ============================================================================

DATABASE_URL = """

postgresql://postgres:password@localhost/safepay

"""

DB_POOL_SIZE = 20

DB_MAX_OVERFLOW = 10

DB_POOL_TIMEOUT = 30

# ============================================================================
# REDIS
# ============================================================================

REDIS_HOST = "localhost"

REDIS_PORT = 6379

REDIS_DB = 0

REDIS_CACHE_TTL = 3600

# ============================================================================
# LOGGING
# ============================================================================

LOG_LEVEL = "INFO"

LOG_FORMAT = """

%(asctime)s
|
%(levelname)s
|
%(name)s
|
%(message)s

"""

LOG_FILE = "logs/safepay.log"

MAX_LOG_FILE_SIZE = 10 * 1024 * 1024

BACKUP_LOG_COUNT = 5

# ============================================================================
# ML MODEL PATHS
# ============================================================================

MODEL1_UPI_PATH = """

app/ml/models/model1_upi.pkl

"""

MODEL2_TEXT_PATH = """

app/ml/models/model2_text.pkl

"""

MODEL3_URL_PATH = """

app/ml/models/model3.pkl

"""

# ============================================================================
# ML CONFIG
# ============================================================================

MODEL_LOAD_TIMEOUT = 20

MAX_TEXT_LENGTH = 10000

MAX_BATCH_SIZE = 100

ML_RANDOM_STATE = 42

# ============================================================================
# FRAUD THRESHOLDS
# ============================================================================

CRITICAL_RISK_THRESHOLD = 90

HIGH_RISK_THRESHOLD = 75

MEDIUM_RISK_THRESHOLD = 50

LOW_RISK_THRESHOLD = 25

# ============================================================================
# RISK WEIGHTS
# ============================================================================

ML_PROBABILITY_WEIGHT = 0.40

RULE_ENGINE_WEIGHT = 0.25

BEHAVIOR_WEIGHT = 0.20

HISTORY_WEIGHT = 0.10

TRUST_PENALTY_WEIGHT = 0.05

# ============================================================================
# RATE LIMITING
# ============================================================================

RATE_LIMIT_PER_MINUTE = 60

LOGIN_RATE_LIMIT = 5

OTP_RATE_LIMIT = 10

API_BURST_LIMIT = 100

# ============================================================================
# FILE UPLOADS
# ============================================================================

MAX_FILE_SIZE_MB = 10

ALLOWED_IMAGE_EXTENSIONS = {

    ".png",

    ".jpg",

    ".jpeg"
}

ALLOWED_DOCUMENT_EXTENSIONS = {

    ".pdf",

    ".txt",

    ".csv"
}

UPLOAD_DIR = "uploads"

TEMP_DIR = "temp"

# ============================================================================
# QR CONFIG
# ============================================================================

MAX_QR_IMAGE_SIZE_MB = 10

QR_SCAN_TIMEOUT = 10

SUPPORTED_QR_FORMATS = {

    "PNG",

    "JPG",

    "JPEG"
}

# ============================================================================
# SMS CONFIG
# ============================================================================

MAX_SMS_LENGTH = 5000

SMS_ANALYSIS_TIMEOUT = 10

BULK_SMS_LIMIT = 100

# ============================================================================
# EMAIL CONFIG
# ============================================================================

SMTP_HOST = "smtp.gmail.com"

SMTP_PORT = 587

SMTP_USERNAME = "your-email@gmail.com"

SMTP_PASSWORD = "your-password"

EMAIL_FROM = "noreply@safepay.ai"

# ============================================================================
# OTP CONFIG
# ============================================================================

OTP_EXPIRY_MINUTES = 5

OTP_LENGTH = 6

MAX_OTP_ATTEMPTS = 5

# ============================================================================
# CACHE KEYS
# ============================================================================

CACHE_MODEL_HEALTH = "model_health"

CACHE_SYSTEM_STATS = "system_stats"

CACHE_USER_PROFILE = "user_profile"

CACHE_FRAUD_SCORE = "fraud_score"

# ============================================================================
# TRUSTED SENDERS
# ============================================================================

TRUSTED_SENDERS = {

    "SBIINB",

    "HDFCBK",

    "ICICIB",

    "PAYTMB",

    "AMAZON",

    "FLIPKART",

    "PHONEPE"
}

# ============================================================================
# SAFE PSPs
# ============================================================================

SAFE_PSP = {

    "oksbi",

    "okhdfcbank",

    "okicici",

    "okaxis",

    "paytm",

    "ibl",

    "axl",

    "upi",

    "sbi",

    "hdfc",

    "icici"
}

# ============================================================================
# SUSPICIOUS PSPs
# ============================================================================

SUSPICIOUS_PSP = {

    "xpay",

    "qpay",

    "zpay",

    "fastpay",

    "quickpay",

    "newupi",

    "mupay"
}

# ============================================================================
# FRAUD KEYWORDS
# ============================================================================

FRAUD_KEYWORDS = {

    "urgent",

    "verify",

    "otp",

    "kyc",

    "blocked",

    "suspended",

    "winner",

    "reward",

    "cashback",

    "bonus",

    "offer",

    "claim",

    "limited",

    "click",

    "link",

    "security",

    "bank",

    "refund",

    "pin"
}

# ============================================================================
# SUSPICIOUS URL PATTERNS
# ============================================================================

SUSPICIOUS_URL_PATTERNS = [

    "verify",

    "claim",

    "bonus",

    "secure",

    "gift",

    "reward",

    "free-money",

    "cashback",

    "winner",

    "login-now"
]

# ============================================================================
# ALERT SEVERITY
# ============================================================================

ALERT_CRITICAL = "CRITICAL"

ALERT_HIGH = "HIGH"

ALERT_MEDIUM = "MEDIUM"

ALERT_LOW = "LOW"

# ============================================================================
# SECURITY HEADERS
# ============================================================================

SECURITY_HEADERS = {

    "X-Content-Type-Options":
        "nosniff",

    "X-Frame-Options":
        "DENY",

    "X-XSS-Protection":
        "1; mode=block",

    "Strict-Transport-Security":
        "max-age=31536000; includeSubDomains",

    "Referrer-Policy":
        "strict-origin-when-cross-origin"
}

# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

WS_EVENT_FRAUD_ALERT = "fraud_alert"

WS_EVENT_SYSTEM_STATUS = "system_status"

WS_EVENT_QR_SCAN = "qr_scan"

WS_EVENT_SMS_ALERT = "sms_alert"

# ============================================================================
# HEALTH CHECK
# ============================================================================

HEALTHY_STATUS = "HEALTHY"

UNHEALTHY_STATUS = "UNHEALTHY"

DEGRADED_STATUS = "DEGRADED"

# ============================================================================
# RESPONSE MESSAGES
# ============================================================================

SUCCESS_MESSAGE = "Operation completed successfully"

ERROR_MESSAGE = "Something went wrong"

UNAUTHORIZED_MESSAGE = "Unauthorized access"

INVALID_TOKEN_MESSAGE = "Invalid authentication token"

MODEL_LOAD_ERROR = "Failed to load ML model"

FRAUD_DETECTED_MESSAGE = """

Potential fraud detected

"""

SAFE_TRANSACTION_MESSAGE = """

Transaction appears safe

"""

# ============================================================================
# TIME CONSTANTS
# ============================================================================

ONE_MINUTE = 60

ONE_HOUR = 3600

ONE_DAY = 86400

ONE_WEEK = 604800

# ============================================================================
# ANALYTICS
# ============================================================================

ENABLE_ANALYTICS = True

ENABLE_PERFORMANCE_MONITORING = True

ENABLE_REQUEST_TRACKING = True

ENABLE_ERROR_TRACKING = True

# ============================================================================
# FEATURE FLAGS
# ============================================================================

ENABLE_QR_SCANNING = True

ENABLE_SMS_ANALYSIS = True

ENABLE_REALTIME_ALERTS = True

ENABLE_HYBRID_INTELLIGENCE = True

ENABLE_BEHAVIOR_ANALYSIS = True

ENABLE_AUTO_BLOCKING = False

# ============================================================================
# AI EXPLANATIONS
# ============================================================================

AI_EXPLANATION_LIMIT = 10

MAX_REASON_LENGTH = 300

# ============================================================================
# COLORS FOR DASHBOARD
# ============================================================================

RISK_COLORS = {

    "SAFE": "#00C853",

    "LOW": "#64DD17",

    "MEDIUM": "#FFD600",

    "HIGH": "#FF6D00",

    "CRITICAL": "#D50000"
}

# ============================================================================
# API TAGS
# ============================================================================

API_TAG_AUTH = "Authentication"

API_TAG_FRAUD = "Fraud Detection"

API_TAG_QR = "QR Intelligence"

API_TAG_SMS = "SMS Intelligence"

API_TAG_HEALTH = "Health Monitoring"

# ============================================================================
# DEFAULT TEST VALUES
# ============================================================================

DEFAULT_TEST_UPI = "rahul123@oksbi"

DEFAULT_TEST_AMOUNT = 500

DEFAULT_TEST_SMS = """

Your payment was successful

"""

# ============================================================================
# EXPORTABLE CONFIG
# ============================================================================

SYSTEM_CONFIG = {

    "app_name":
        APP_NAME,

    "version":
        APP_VERSION,

    "debug":
        DEBUG_MODE,

    "host":
        HOST,

    "port":
        PORT
}

# ============================================================================
# STARTUP BANNER
# ============================================================================

STARTUP_BANNER = """

╔════════════════════════════════════╗
║                                    ║
║        SAFEPAY AI BACKEND          ║
║                                    ║
║   Enterprise Fraud Intelligence    ║
║                                    ║
╚════════════════════════════════════╝

"""

# ============================================================================
# SHUTDOWN MESSAGE
# ============================================================================

SHUTDOWN_MESSAGE = """

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛑 SafePay AI Backend Shutdown
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""

# ============================================================================
# DEBUG
# ============================================================================

if __name__ == "__main__":

    print(STARTUP_BANNER)

    print(

        f"""
🚀 App Name:
{APP_NAME}

📦 Version:
{APP_VERSION}

🌐 API Prefix:
{API_PREFIX}

⚠️ Risk Threshold:
{HIGH_RISK_THRESHOLD}
"""
    )