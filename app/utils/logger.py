# app/utils/logger.py

"""
==============================================================================
SafePay AI — Enterprise Logging Engine
==============================================================================

Purpose
-------
Centralized structured logging system.

Features
--------
✅ Colored console logs
✅ Rotating file logs
✅ JSON logging
✅ Request tracing
✅ Error tracking
✅ Performance logging
✅ Security event logging
✅ Fraud event logging
✅ Async-safe logging
✅ Production-grade formatting

Used By
-------
1. Routes
2. Services
3. ML Models
4. Middleware
5. Database Layer
6. Background Tasks

Architecture
-------------
logger.py
    ↓
Entire Backend

==============================================================================
"""

import json
import logging
import logging.handlers
import os
import sys
import traceback
from datetime import datetime

# Ensure console output uses UTF-8 on Windows terminals to avoid emoji encoding errors.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except AttributeError:
    import io

    try:
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer,
            encoding="utf-8",
            line_buffering=True
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer,
            encoding="utf-8",
            line_buffering=True
        )
    except Exception:
        pass
except Exception:
    pass

# ============================================================================
# LOG DIRECTORIES
# ============================================================================

LOG_DIR = "logs"

ERROR_LOG_DIR = os.path.join(

    LOG_DIR,

    "errors"
)

SECURITY_LOG_DIR = os.path.join(

    LOG_DIR,

    "security"
)

FRAUD_LOG_DIR = os.path.join(

    LOG_DIR,

    "fraud"
)

ACCESS_LOG_DIR = os.path.join(

    LOG_DIR,

    "access"
)

# ============================================================================
# CREATE DIRECTORIES
# ============================================================================

for directory in [

    LOG_DIR,

    ERROR_LOG_DIR,

    SECURITY_LOG_DIR,

    FRAUD_LOG_DIR,

    ACCESS_LOG_DIR
]:

    os.makedirs(

        directory,

        exist_ok=True
    )

# ============================================================================
# COLORS
# ============================================================================

class LogColors:

    RESET = "\033[0m"

    RED = "\033[91m"

    GREEN = "\033[92m"

    YELLOW = "\033[93m"

    BLUE = "\033[94m"

    MAGENTA = "\033[95m"

    CYAN = "\033[96m"

    WHITE = "\033[97m"

# ============================================================================
# COLORED FORMATTER
# ============================================================================

class ColoredFormatter(logging.Formatter):

    """
    Colored terminal formatter.
    """

    LEVEL_COLORS = {

        "DEBUG":
            LogColors.CYAN,

        "INFO":
            LogColors.GREEN,

        "WARNING":
            LogColors.YELLOW,

        "ERROR":
            LogColors.RED,

        "CRITICAL":
            LogColors.MAGENTA
    }

    def format(self, record):

        color = self.LEVEL_COLORS.get(

            record.levelname,

            LogColors.WHITE
        )

        formatted = super().format(record)

        return (

            color

            +

            formatted

            +

            LogColors.RESET
        )

# ============================================================================
# JSON FORMATTER
# ============================================================================

class JSONFormatter(logging.Formatter):

    """
    Structured JSON logging.
    """

    def format(self, record):

        log_object = {

            "timestamp":
                datetime.utcnow().isoformat(),

            "level":
                record.levelname,

            "logger":
                record.name,

            "message":
                record.getMessage(),

            "module":
                record.module,

            "function":
                record.funcName,

            "line":
                record.lineno
        }

        if record.exc_info:

            log_object["traceback"] = (

                self.formatException(
                    record.exc_info
                )
            )

        return json.dumps(log_object)

# ============================================================================
# LOGGER CONFIG
# ============================================================================

LOGGER_NAME = "SafePayAI"

LOG_LEVEL = logging.INFO

MAX_LOG_SIZE = 10 * 1024 * 1024

BACKUP_COUNT = 5

# ============================================================================
# MAIN LOGGER
# ============================================================================

logger = logging.getLogger(
    LOGGER_NAME
)

logger.setLevel(LOG_LEVEL)

logger.propagate = False

# ============================================================================
# REMOVE DUPLICATES
# ============================================================================

if logger.hasHandlers():

    logger.handlers.clear()

# ============================================================================
# CONSOLE HANDLER
# ============================================================================

console_handler = logging.StreamHandler(
    sys.stdout
)

console_handler.setLevel(logging.INFO)

console_formatter = ColoredFormatter(

    """
%(asctime)s
|
%(levelname)s
|
%(name)s
|
%(message)s
""".strip(),

    datefmt="%Y-%m-%d %H:%M:%S"
)

console_handler.setFormatter(
    console_formatter
)

logger.addHandler(
    console_handler
)

# ============================================================================
# FILE HANDLER
# ============================================================================

file_handler = logging.handlers.RotatingFileHandler(

    filename=os.path.join(

        LOG_DIR,

        "application.log"
    ),

    maxBytes=MAX_LOG_SIZE,

    backupCount=BACKUP_COUNT,

    encoding="utf-8"
)

file_handler.setLevel(logging.INFO)

file_formatter = logging.Formatter(

    """
%(asctime)s
|
%(levelname)s
|
%(name)s
|
%(module)s
|
%(funcName)s
|
%(lineno)d
|
%(message)s
""".strip(),

    datefmt="%Y-%m-%d %H:%M:%S"
)

file_handler.setFormatter(
    file_formatter
)

logger.addHandler(
    file_handler
)

# ============================================================================
# ERROR HANDLER
# ============================================================================

error_handler = logging.handlers.RotatingFileHandler(

    filename=os.path.join(

        ERROR_LOG_DIR,

        "errors.log"
    ),

    maxBytes=MAX_LOG_SIZE,

    backupCount=BACKUP_COUNT,

    encoding="utf-8"
)

error_handler.setLevel(logging.ERROR)

error_handler.setFormatter(
    file_formatter
)

logger.addHandler(
    error_handler
)

# ============================================================================
# JSON HANDLER
# ============================================================================

json_handler = logging.handlers.RotatingFileHandler(

    filename=os.path.join(

        LOG_DIR,

        "structured.json"
    ),

    maxBytes=MAX_LOG_SIZE,

    backupCount=BACKUP_COUNT,

    encoding="utf-8"
)

json_handler.setLevel(logging.INFO)

json_handler.setFormatter(
    JSONFormatter()
)

logger.addHandler(
    json_handler
)

# ============================================================================
# SECURITY LOGGER
# ============================================================================

security_logger = logging.getLogger(
    "SafePaySecurity"
)

security_logger.setLevel(logging.INFO)

security_handler = logging.handlers.RotatingFileHandler(

    filename=os.path.join(

        SECURITY_LOG_DIR,

        "security.log"
    ),

    maxBytes=MAX_LOG_SIZE,

    backupCount=BACKUP_COUNT,

    encoding="utf-8"
)

security_handler.setFormatter(
    file_formatter
)

security_logger.addHandler(
    security_handler
)

# ============================================================================
# FRAUD LOGGER
# ============================================================================

fraud_logger = logging.getLogger(
    "SafePayFraud"
)

fraud_logger.setLevel(logging.INFO)

fraud_handler = logging.handlers.RotatingFileHandler(

    filename=os.path.join(

        FRAUD_LOG_DIR,

        "fraud.log"
    ),

    maxBytes=MAX_LOG_SIZE,

    backupCount=BACKUP_COUNT,

    encoding="utf-8"
)

fraud_handler.setFormatter(
    file_formatter
)

fraud_logger.addHandler(
    fraud_handler
)

# ============================================================================
# ACCESS LOGGER
# ============================================================================

access_logger = logging.getLogger(
    "SafePayAccess"
)

access_logger.setLevel(logging.INFO)

access_handler = logging.handlers.RotatingFileHandler(

    filename=os.path.join(

        ACCESS_LOG_DIR,

        "access.log"
    ),

    maxBytes=MAX_LOG_SIZE,

    backupCount=BACKUP_COUNT,

    encoding="utf-8"
)

access_handler.setFormatter(
    file_formatter
)

access_logger.addHandler(
    access_handler
)

# ============================================================================
# REQUEST LOGGER
# ============================================================================

def log_request(

    method: str,

    path: str,

    status_code: int,

    client_ip: str,

    duration_ms: float
):

    """
    API request logging.
    """

    access_logger.info(
        f"""
🌐 API REQUEST

Method:
{method}

Path:
{path}

Status:
{status_code}

Client IP:
{client_ip}

Duration:
{duration_ms} ms
"""
    )

# ============================================================================
# SECURITY EVENT LOGGER
# ============================================================================

def log_security_event(

    event_type: str,

    details: dict
):

    """
    Security audit logs.
    """

    security_logger.warning(
        json.dumps({

            "timestamp":
                datetime.utcnow().isoformat(),

            "event_type":
                event_type,

            "details":
                details
        })
    )

# ============================================================================
# FRAUD EVENT LOGGER
# ============================================================================

def log_fraud_event(

    risk_score: float,

    risk_level: str,

    details: dict
):

    """
    Fraud intelligence logs.
    """

    fraud_logger.warning(
        json.dumps({

            "timestamp":
                datetime.utcnow().isoformat(),

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "details":
                details
        })
    )

# ============================================================================
# EXCEPTION LOGGER
# ============================================================================

def log_exception(

    exception: Exception,

    context: str = ""
):

    """
    Centralized exception tracking.
    """

    logger.error(
        f"""
❌ EXCEPTION OCCURRED

📌 Context:
{context}

🧠 Error:
{str(exception)}

📚 Traceback:
{traceback.format_exc()}
"""
    )

# ============================================================================
# PERFORMANCE LOGGER
# ============================================================================

def log_performance(

    operation: str,

    duration_ms: float
):

    """
    Performance metrics logging.
    """

    logger.info(
        f"""
⏱️ PERFORMANCE METRIC

Operation:
{operation}

Duration:
{duration_ms} ms
"""
    )

# ============================================================================
# STARTUP LOGGER
# ============================================================================

def log_startup():

    """
    Application startup logs.
    """

    logger.info(
        """
╔════════════════════════════════════╗
║                                    ║
║        SAFEPAY AI STARTED          ║
║                                    ║
║    Enterprise Fraud Intelligence   ║
║                                    ║
╚════════════════════════════════════╝
"""
    )

# ============================================================================
# SHUTDOWN LOGGER
# ============================================================================

def log_shutdown():

    """
    Application shutdown logs.
    """

    logger.info(
        """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛑 SAFEPAY AI SHUTDOWN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

# ============================================================================
# HEALTH LOGGER
# ============================================================================

def log_health_check(

    service: str,

    status: str
):

    """
    Health monitoring logs.
    """

    logger.info(
        f"""
💓 HEALTH CHECK

Service:
{service}

Status:
{status}
"""
    )

# ============================================================================
# DEBUG TEST
# ============================================================================

if __name__ == "__main__":

    log_startup()

    logger.info(
        "✅ Main logger operational"
    )

    logger.warning(
        "⚠️ Warning test"
    )

    logger.error(
        "❌ Error test"
    )

    log_request(

        method="POST",

        path="/api/v1/fraud/check-upi",

        status_code=200,

        client_ip="127.0.0.1",

        duration_ms=52.33
    )

    log_security_event(

        event_type="LOGIN_FAILED",

        details={

            "ip": "192.168.1.10",

            "email": "attacker@test.com"
        }
    )

    log_fraud_event(

        risk_score=92,

        risk_level="CRITICAL",

        details={

            "upi_id":
                "pay98234723@fastpay"
        }
    )

    log_shutdown()