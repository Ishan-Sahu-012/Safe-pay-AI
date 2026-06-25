# app/api/routes/health_routes.py

import os
import time
import platform
import psutil
import sqlite3
from datetime import datetime

from fastapi import APIRouter
from sqlalchemy import text

from app.database.db import engine
from app.utils.logger import logger

# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/health",
    tags=["Health Monitoring"]
)

# ============================================================================
# Application Start Time
# ============================================================================

APP_START_TIME = time.time()

# ============================================================================
# BASIC HEALTH CHECK
# ============================================================================

@router.get("/")

async def basic_health_check():

    """
    Lightweight health check.
    Used by:
    - Load balancers
    - Docker
    - Kubernetes
    - Uptime monitors
    """

    return {

        "success": True,

        "service": "SafePay Backend",

        "status": "RUNNING",

        "timestamp": datetime.utcnow()
    }

# ============================================================================
# DATABASE HEALTH CHECK
# ============================================================================

@router.get("/database")

async def database_health():

    try:

        start = time.time()

        with engine.connect() as connection:

            connection.execute(
                text("SELECT 1")
            )

        latency = round(
            (time.time() - start) * 1000,
            2
        )

        return {

            "success": True,

            "database": "CONNECTED",

            "latency_ms": latency
        }

    except Exception as e:

        logger.error(
            f"❌ Database Health Check Failed: {str(e)}"
        )

        return {

            "success": False,

            "database": "DISCONNECTED",

            "error": str(e)
        }

# ============================================================================
# ML MODEL HEALTH CHECK
# ============================================================================

@router.get("/ml")

async def ml_health():

    try:

        model1_exists = os.path.exists(
            "app/ml/models/model1_upi.pkl"
        )

        model2_exists = os.path.exists(
            "app/ml/models/model2_text.pkl"
        )

        return {

            "success": True,

            "models": {

                "upi_model": "LOADED" if model1_exists else "MISSING",

                "text_model": "LOADED" if model2_exists else "MISSING"
            }
        }

    except Exception as e:

        logger.error(
            f"❌ ML Health Check Failed: {str(e)}"
        )

        return {

            "success": False,

            "error": str(e)
        }

# ============================================================================
# SYSTEM METRICS
# ============================================================================

@router.get("/system")

async def system_metrics():

    try:

        cpu_usage = psutil.cpu_percent()

        memory = psutil.virtual_memory()

        disk = psutil.disk_usage("/")

        uptime_seconds = int(
            time.time() - APP_START_TIME
        )

        uptime_hours = round(
            uptime_seconds / 3600,
            2
        )

        return {

            "success": True,

            "system": {

                "platform": platform.system(),

                "platform_version": platform.version(),

                "python_version": platform.python_version(),

                "cpu_usage_percent": cpu_usage,

                "memory": {

                    "total_gb": round(memory.total / (1024**3), 2),

                    "used_gb": round(memory.used / (1024**3), 2),

                    "usage_percent": memory.percent
                },

                "disk": {

                    "total_gb": round(disk.total / (1024**3), 2),

                    "used_gb": round(disk.used / (1024**3), 2),

                    "usage_percent": disk.percent
                },

                "uptime_hours": uptime_hours
            }
        }

    except Exception as e:

        logger.error(
            f"❌ System Metrics Error: {str(e)}"
        )

        return {

            "success": False,

            "error": str(e)
        }

# ============================================================================
# FULL SYSTEM HEALTH REPORT
# ============================================================================

@router.get("/full-report")

async def full_health_report():

    """
    Enterprise-level complete monitoring endpoint.
    """

    try:

        _report_start = time.time()

        # --------------------------------------------------------------------
        # Database Check
        # --------------------------------------------------------------------

        db_status = "CONNECTED"

        try:

            with engine.connect() as connection:

                connection.execute(
                    text("SELECT 1")
                )

        except:

            db_status = "DISCONNECTED"

        # --------------------------------------------------------------------
        # ML Check
        # --------------------------------------------------------------------

        upi_model = os.path.exists(
            "app/ml/models/model1_upi.pkl"
        )

        text_model = os.path.exists(
            "app/ml/models/model2_text.pkl"
        )

        # --------------------------------------------------------------------
        # System Resources
        # --------------------------------------------------------------------

        # interval=0.1 gives a real CPU reading instead of cached 0.0
        cpu = psutil.cpu_percent(interval=0.1)

        memory = psutil.virtual_memory()

        disk = psutil.disk_usage("/")

        # --------------------------------------------------------------------
        # Uptime
        # --------------------------------------------------------------------

        uptime_seconds = int(
            time.time() - APP_START_TIME
        )

        # --------------------------------------------------------------------
        # Response Time (self-diagnostic)
        # --------------------------------------------------------------------

        response_time_ms = round((time.time() - _report_start) * 1000, 2)

        # --------------------------------------------------------------------
        # Overall Status — realistic thresholds
        #   HEALTHY    : normal operation
        #   WARNING    : moderate load (CPU > 80% or memory > 90%)
        #   HIGH_LOAD  : severe load (CPU > 95% or memory > 96%)
        #   CRITICAL   : database disconnected
        # --------------------------------------------------------------------

        overall_status = "HEALTHY"

        if cpu > 80 or memory.percent > 90:
            overall_status = "WARNING"

        if cpu > 95 or memory.percent > 96:
            overall_status = "HIGH_LOAD"

        if db_status == "DISCONNECTED":
            overall_status = "CRITICAL"

        # --------------------------------------------------------------------
        # Logging
        # --------------------------------------------------------------------

        logger.info(
            f"""
📊 HEALTH REPORT GENERATED

🖥️ CPU Usage      : {cpu}%
🧠 Memory Usage   : {memory.percent}%
💾 Disk Usage     : {disk.percent}%
🗄️ Database       : {db_status}
🤖 UPI Model      : {'READY' if upi_model else 'MISSING'}
📩 Text Model     : {'READY' if text_model else 'MISSING'}
⏱️ Response Time  : {response_time_ms}ms
📋 Status         : {overall_status}
"""
        )

        # --------------------------------------------------------------------
        # Response
        # --------------------------------------------------------------------

        return {

            "success": True,

            "overall_status": overall_status,

            "timestamp": datetime.utcnow(),

            "services": {

                "database": db_status,

                "upi_model": "READY" if upi_model else "MISSING",

                "text_model": "READY" if text_model else "MISSING"
            },

            "resources": {

                "cpu_percent": cpu,

                "memory_percent": memory.percent,

                "disk_percent": disk.percent
            },

            "uptime_seconds": uptime_seconds,

            "response_time_ms": response_time_ms
        }

    except Exception as e:

        logger.error(
            f"❌ Full Health Report Error: {str(e)}"
        )

        return {

            "success": False,

            "status": "CRITICAL",

            "error": str(e)
        }

# ============================================================================
# READINESS CHECK
# ============================================================================

@router.get("/ready")

async def readiness_check():

    """
    Checks whether app is ready to serve traffic.
    """

    try:

        # DB check
        with engine.connect() as connection:

            connection.execute(
                text("SELECT 1")
            )

        # Model check
        model_exists = os.path.exists(
            "app/ml/models/model1_upi.pkl"
        )

        if not model_exists:

            return {

                "ready": False,

                "reason": "ML model missing"
            }

        return {

            "ready": True
        }

    except Exception as e:

        return {

            "ready": False,

            "error": str(e)
        }

# ============================================================================
# LIVENESS CHECK
# ============================================================================

@router.get("/live")

async def liveness_check():

    """
    Used by Docker/Kubernetes
    to know app is alive.
    """

    return {

        "alive": True,

        "timestamp": datetime.utcnow()
    }