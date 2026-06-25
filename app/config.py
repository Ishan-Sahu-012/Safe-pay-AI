# app/config.py

"""
==============================================================================
SafePay AI — Central Configuration
==============================================================================

Purpose
-------
Enterprise-grade centralized configuration system.

Features
--------
✅ Environment-based configs
✅ Secure secret management
✅ ML model paths
✅ Database configuration
✅ Redis configuration
✅ Security settings
✅ API configuration
✅ Logging configuration
✅ Production-ready structure
✅ Pydantic validation

Used By
-------
1. main.py
2. database.py
3. auth middleware
4. ML services
5. Redis cache
6. Logging system

Architecture
-------------
.env
   ↓
config.py
   ↓
Entire Backend

==============================================================================
"""

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings

# ============================================================================
# BASE DIRECTORY
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================================
# ENV FILE
# ============================================================================

ENV_PATH = BASE_DIR / ".env"

# ============================================================================
# SETTINGS CLASS
# ============================================================================

class Settings(BaseSettings):

    """
    Central application settings.
    """

    # ========================================================================
    # APPLICATION
    # ========================================================================

    APP_NAME: str = "SafePay AI"

    APP_VERSION: str = "1.0.0"

    DEBUG: bool = True

    API_PREFIX: str = "/api/v1"

    ENVIRONMENT: str = "development"

    # ========================================================================
    # SERVER
    # ========================================================================

    HOST: str = "0.0.0.0"

    PORT: int = 8000

    WORKERS: int = 4

    REQUEST_TIMEOUT: int = 60

    # ========================================================================
    # SECURITY
    # ========================================================================

    SECRET_KEY: str = Field(

        default=
        "CHANGE_THIS_SECRET_IN_PRODUCTION",

        min_length=32
    )

    JWT_SECRET_KEY: str = Field(

        default=
        "CHANGE_THIS_JWT_SECRET_IN_PRODUCTION",

        min_length=32
    )

    JWT_ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    PASSWORD_HASH_ALGORITHM: str = "bcrypt"

    # ========================================================================
    # DATABASE
    # ========================================================================

    DATABASE_URL: str = "sqlite:///./safepay.db"

    DB_POOL_SIZE: int = 20

    DB_MAX_OVERFLOW: int = 10

    DB_POOL_TIMEOUT: int = 30

    DB_ECHO: bool = False

    # ========================================================================
    # SQLITE FALLBACK
    # ========================================================================

    SQLITE_URL: str = "sqlite:///./safepay.db"

    # ========================================================================
    # REDIS
    # ========================================================================

    REDIS_HOST: str = "localhost"

    REDIS_PORT: int = 6379

    REDIS_DB: int = 0

    REDIS_PASSWORD: str | None = None

    REDIS_CACHE_TTL: int = 3600

    # ========================================================================
    # LOGGING
    # ========================================================================

    LOG_LEVEL: str = "INFO"

    LOG_DIR: str = "logs"

    ENABLE_JSON_LOGS: bool = True

    MAX_LOG_FILE_SIZE: int = 10 * 1024 * 1024

    BACKUP_LOG_COUNT: int = 5

    # ========================================================================
    # ML MODELS
    # ========================================================================

    MODEL1_UPI_PATH: str = (

        "app/ml/models/model1_upi.pkl"
    )

    MODEL2_TEXT_PATH: str = (

        "app/ml/models/model2_text.pkl"
    )

    MODEL3_PATH: str = (

        "app/ml/models/model3.pkl"
    )

    MODEL_LOAD_TIMEOUT: int = 20

    MAX_BATCH_SIZE: int = 100

    ML_RANDOM_STATE: int = 42

    # ========================================================================
    # FRAUD THRESHOLDS
    # ========================================================================

    CRITICAL_RISK_THRESHOLD: int = 90

    HIGH_RISK_THRESHOLD: int = 75

    MEDIUM_RISK_THRESHOLD: int = 50

    LOW_RISK_THRESHOLD: int = 25

    # ========================================================================
    # FILE UPLOADS
    # ========================================================================

    MAX_FILE_SIZE_MB: int = 10

    UPLOAD_DIR: str = "uploads"

    TEMP_DIR: str = "temp"

    # ========================================================================
    # QR CONFIG
    # ========================================================================

    QR_SCAN_TIMEOUT: int = 10

    MAX_QR_IMAGE_SIZE_MB: int = 10

    # ========================================================================
    # SMS CONFIG
    # ========================================================================

    MAX_SMS_LENGTH: int = 5000

    BULK_SMS_LIMIT: int = 100

    SMS_ANALYSIS_TIMEOUT: int = 10

    # ========================================================================
    # EMAIL CONFIG
    # ========================================================================

    SMTP_HOST: str = "smtp.gmail.com"

    SMTP_PORT: int = 587

    SMTP_USERNAME: str = "your-email@gmail.com"

    SMTP_PASSWORD: str = "your-password"

    EMAIL_FROM: str = "noreply@safepay.ai"

    # ========================================================================
    # OTP CONFIG
    # ========================================================================

    OTP_EXPIRY_MINUTES: int = 5

    OTP_LENGTH: int = 6

    MAX_OTP_ATTEMPTS: int = 5

    # ========================================================================
    # RATE LIMITING
    # ========================================================================

    RATE_LIMIT_PER_MINUTE: int = 60

    LOGIN_RATE_LIMIT: int = 5

    API_BURST_LIMIT: int = 100

    # ========================================================================
    # FEATURE FLAGS
    # ========================================================================

    ENABLE_QR_SCANNING: bool = True

    ENABLE_SMS_ANALYSIS: bool = True

    ENABLE_REALTIME_ALERTS: bool = True

    ENABLE_HYBRID_INTELLIGENCE: bool = True

    ENABLE_AUTO_BLOCKING: bool = False

    # ========================================================================
    # CORS
    # ========================================================================

    ALLOWED_ORIGINS: list[str] = [

        "http://localhost:3000",

        "http://127.0.0.1:3000",

        "*"
    ]

    # ========================================================================
    # MONITORING
    # ========================================================================

    ENABLE_ANALYTICS: bool = True

    ENABLE_PERFORMANCE_MONITORING: bool = True

    ENABLE_ERROR_TRACKING: bool = True

    # ========================================================================
    # SECURITY HEADERS
    # ========================================================================

    ENABLE_SECURITY_HEADERS: bool = True

    # ========================================================================
    # PYDANTIC CONFIG
    # ========================================================================

    model_config = {

        "env_file": ENV_PATH,

        "case_sensitive": True,

        "extra": "ignore"
    }

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    @property
    def is_production(self):

        return self.ENVIRONMENT.lower() == "production"

    # ------------------------------------------------------------------------

    @property
    def is_development(self):

        return self.ENVIRONMENT.lower() == "development"

    # ------------------------------------------------------------------------

    @property
    def database_url(self):

        """
        Smart DB selection.
        """

        if self.ENVIRONMENT == "testing":

            return self.SQLITE_URL

        return self.DATABASE_URL

    # ------------------------------------------------------------------------

    @property
    def redis_url(self):

        """
        Redis connection string.
        """

        if self.REDIS_PASSWORD:

            return (

                f"redis://:{self.REDIS_PASSWORD}"
                f"@{self.REDIS_HOST}:{self.REDIS_PORT}"
                f"/{self.REDIS_DB}"
            )

        return (

            f"redis://{self.REDIS_HOST}"
            f":{self.REDIS_PORT}"
            f"/{self.REDIS_DB}"
        )

    # ------------------------------------------------------------------------

    @property
    def model_paths(self):

        """
        All ML model paths.
        """

        return {

            "upi_model":
                self.MODEL1_UPI_PATH,

            "text_model":
                self.MODEL2_TEXT_PATH,

            "hybrid_model":
                self.MODEL3_PATH
        }

# ============================================================================
# SETTINGS INSTANCE
# ============================================================================

settings = Settings()

# ============================================================================
# CREATE REQUIRED DIRECTORIES
# ============================================================================

REQUIRED_DIRS = [

    settings.LOG_DIR,

    settings.UPLOAD_DIR,

    settings.TEMP_DIR,

    "app/ml/models",

    "app/ml/plots",

    "logs/errors",

    "logs/security",

    "logs/fraud",

    "logs/access"
]

for directory in REQUIRED_DIRS:

    os.makedirs(

        directory,

        exist_ok=True
    )

# ============================================================================
# STARTUP BANNER
# ============================================================================

STARTUP_BANNER = f"""

╔════════════════════════════════════╗
║                                    ║
║         SAFEPAY AI BACKEND         ║
║                                    ║
║    Enterprise Fraud Intelligence   ║
║                                    ║
╚════════════════════════════════════╝

🚀 Version     : {settings.APP_VERSION}
🌍 Environment : {settings.ENVIRONMENT}
⚡ Debug Mode  : {settings.DEBUG}
🧠 ML Enabled  : True

"""

# ============================================================================
# DEBUG
# ============================================================================

if __name__ == "__main__":

    print(STARTUP_BANNER)

    print(

        f"""
📦 App Name:
{settings.APP_NAME}

🌐 Host:
{settings.HOST}

🚪 Port:
{settings.PORT}

🗄️ Database:
{settings.database_url}

🔴 Redis:
{settings.redis_url}

🤖 Models:
{settings.model_paths}
"""
    )