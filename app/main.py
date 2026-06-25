# app/main.py

"""
==============================================================================
SafePay AI — Main FastAPI Application
==============================================================================

Purpose
-------
Enterprise-grade AI fraud detection backend.

Features
--------
✅ JWT Authentication
✅ Fraud Detection APIs
✅ QR Scam Detection
✅ SMS Scam Detection
✅ ML Hybrid Intelligence
✅ Realtime Logging
✅ Health Monitoring
✅ Security Middleware
✅ CORS Protection
✅ Startup Diagnostics
✅ Global Exception Handling

Architecture
-------------
Client
   ↓
FastAPI App
   ↓
Middleware
   ↓
Routes
   ↓
Services
   ↓
ML Models / Database

Run
---
uvicorn app.main:app --reload

Docs
----
http://127.0.0.1:8000/docs

==============================================================================
"""

import os
import time
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import (

    FastAPI,

    HTTPException,

    Request,

    status
)

from fastapi.exceptions import RequestValidationError

from fastapi.middleware.cors import CORSMiddleware

from fastapi.middleware.gzip import GZipMiddleware

from fastapi.responses import JSONResponse, FileResponse

from fastapi.staticfiles import StaticFiles
# ============================================================================
# CONFIG
# ============================================================================

from app.config import (

    settings,

    STARTUP_BANNER
)

# ============================================================================
# LOGGER
# ============================================================================

from app.utils.logger import (

    logger,

    log_startup,

    log_shutdown,

    log_request,

    log_exception
)

# ============================================================================
# ROUTES
# ============================================================================

from app.api.routes.auth_routes import router as auth_router

from app.api.routes.fraud_routes import router as fraud_router

from app.api.routes.qr_routes import router as qr_router

from app.api.routes.sms_routes import router as sms_router

from app.api.routes.health_routes import router as health_router

from app.api.routes.ws_routes import router as ws_router

# ============================================================================
# MIDDLEWARE
# ============================================================================

from app.api.middleware.logging_middleware import (
    LoggingMiddleware
)

from app.api.middleware.auth_middleware import (
    AuthMiddleware
)

# ============================================================================
# DATABASE
# ============================================================================

from app.database.db import (

    Base,

    engine
)

# ============================================================================
# ML HEALTH
# ============================================================================

from app.ml.inference.upi_predictor import (

    model_health as upi_model_health
)

from app.ml.inference.text_predictor import (

    model_health as text_model_health
)

# ============================================================================
# APP LIFECYCLE
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    """
    Startup + shutdown lifecycle.
    """

    # ------------------------------------------------------------------------
    # STARTUP
    # ------------------------------------------------------------------------

    print(STARTUP_BANNER)

    log_startup()

    logger.info(
        """
🚀 Initializing SafePay AI Backend
"""
    )

    # ------------------------------------------------------------------------
    # CREATE DATABASE TABLES
    # ------------------------------------------------------------------------

    try:

        Base.metadata.create_all(
            bind=engine
        )

        logger.info(
            "✅ Database initialized"
        )

        # ------------------------------------------------------------------------
        # SEED DATABASE REGISTRY
        # ------------------------------------------------------------------------
        from app.database.db import db_session
        from app.database.seeding import seed_database_registry
        with db_session() as db:
            seed_database_registry(db)

    except Exception as e:

        logger.error(
            f"""
❌ Database initialization failed

🧠 Error:
{str(e)}
"""
        )

    # ------------------------------------------------------------------------
    # ML MODEL CHECKS
    # ------------------------------------------------------------------------

    try:

        upi_health = upi_model_health()

        text_health = text_model_health()

        logger.info(
            f"""
🧠 ML MODELS STATUS

UPI Model:
{upi_health}

Text Model:
{text_health}
"""
        )

    except Exception as e:

        logger.error(
            f"""
❌ ML model startup failed

🧠 Error:
{str(e)}
"""
        )

    # ------------------------------------------------------------------------
    # APP READY
    # ------------------------------------------------------------------------

    logger.info(
        """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ SafePay AI Backend Ready
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    yield

    # ------------------------------------------------------------------------
    # SHUTDOWN
    # ------------------------------------------------------------------------

    log_shutdown()

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(

    title=settings.APP_NAME,

    version=settings.APP_VERSION,

    description="""
Enterprise-grade AI fraud detection backend.
""",

    docs_url="/docs",

    redoc_url="/redoc",

    openapi_url="/openapi.json",

    lifespan=lifespan
)

_static_dir = "static"
if os.path.isdir(_static_dir):
    app.mount(
        "/static",
        StaticFiles(directory=_static_dir),
        name="static",
    )

# ============================================================================
# CORS
# ============================================================================

app.add_middleware(

    CORSMiddleware,

    allow_origins=settings.ALLOWED_ORIGINS,

    allow_origin_regex=r"^chrome-extension://.*",

    allow_credentials=False,

    allow_methods=["*"],

    allow_headers=["*"]
)

# ============================================================================
# GZIP
# ============================================================================

app.add_middleware(

    GZipMiddleware,

    minimum_size=1000
)

# ============================================================================
# CUSTOM MIDDLEWARE
# ============================================================================

app.add_middleware(
    LoggingMiddleware
)

app.add_middleware(
    AuthMiddleware
)

# ============================================================================
# REQUEST TIMER
# ============================================================================

@app.middleware("http")
async def request_timer(

    request: Request,

    call_next
):

    """
    Request performance tracker.
    """

    start = time.time()

    response = await call_next(request)

    duration = round(

        (time.time() - start) * 1000,

        2
    )

    response.headers[
        "X-Process-Time"
    ] = str(duration)

    # ------------------------------------------------------------------------
    # LOG REQUEST
    # ------------------------------------------------------------------------

    try:

        log_request(

            method=request.method,

            path=request.url.path,

            status_code=response.status_code,

            client_ip=request.client.host,

            duration_ms=duration
        )

    except:

        pass

    return response

# ============================================================================
# SECURITY HEADERS
# ============================================================================

@app.middleware("http")
async def security_headers(

    request: Request,

    call_next
):

    """
    Add enterprise security headers.
    """

    response = await call_next(request)

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "X-XSS-Protection"
    ] = "1; mode=block"

    response.headers[
        "Strict-Transport-Security"
    ] = "max-age=31536000"

    return response

# ============================================================================
# ROOT ROUTE
# ============================================================================

@app.get("/")

async def root():

    """
    Root endpoint.
    """

    return {

        "success": True,

        "message": "SafePay AI Backend Running",

        "version": settings.APP_VERSION,

        "timestamp": datetime.utcnow(),

        "docs": "/docs",

        "dashboard": "/dashboard",
    }

@app.get("/dashboard")

async def dashboard():

    """
    Serve the SafePay dashboard frontend.
    """

    return FileResponse(
        "static/safepay_updated_dashboard.html",
        media_type="text/html"
    )

# ============================================================================
# SYSTEM INFO
# ============================================================================

@app.get("/system/info")

async def system_info():

    """
    System diagnostics.
    """

    return {

        "app_name":
            settings.APP_NAME,

        "version":
            settings.APP_VERSION,

        "environment":
            settings.ENVIRONMENT,

        "debug":
            settings.DEBUG,

        "ml_enabled":
            True,

        "timestamp":
            datetime.utcnow()
    }

# ============================================================================
# ROUTES
# ============================================================================



    
app.include_router(
    auth_router
)

app.include_router(
    fraud_router
)

app.include_router(
    qr_router
)

app.include_router(
    sms_router
)

app.include_router(
    health_router
)

app.include_router(
    ws_router
)

# ============================================================================
# 404 HANDLER
# ============================================================================

@app.exception_handler(404)

async def not_found_handler(

    request: Request,

    exc
):

    detail = getattr(exc, "detail", None)

    if detail and detail != "Not Found":

        message = detail

    else:

        message = "Endpoint not found"

    return JSONResponse(

        status_code=404,

        content={

            "success": False,

            "message":
                message,

            "path":
                request.url.path
        }
    )

# ============================================================================
# HTTP EXCEPTION HANDLER
# ============================================================================

@app.exception_handler(HTTPException)

async def http_exception_handler(

    request: Request,

    exc: HTTPException
):

    logger.warning(
        f"""
⚠️ HTTP Exception

Path:
{request.url.path}

Status:
{exc.status_code}

Detail:
{exc.detail}
"""
    )

    return JSONResponse(

        status_code=exc.status_code,

        content={

            "success": False,

            "message":
                exc.detail,

            "status_code":
                exc.status_code
        }
    )

# ============================================================================
# VALIDATION ERROR HANDLER
# ============================================================================

@app.exception_handler(
    RequestValidationError
)

async def validation_exception_handler(

    request: Request,

    exc: RequestValidationError
):

    logger.warning(
        f"""
⚠️ Validation Error

Path:
{request.url.path}

Errors:
{exc.errors()}
"""
    )

    return JSONResponse(

        status_code=422,

        content={

            "success": False,

            "message":
                "Validation failed",

            "errors":
                exc.errors()
        }
    )

# ============================================================================
# GLOBAL EXCEPTION HANDLER
# ============================================================================

@app.exception_handler(Exception)

async def global_exception_handler(

    request: Request,

    exc: Exception
):

    log_exception(

        exception=exc,

        context=request.url.path
    )

    content = {

        "success": False,

        "message": "Internal server error",
    }

    request_id = getattr(request.state, "request_id", None)
    if request_id:
        content["request_id"] = request_id

    if settings.DEBUG:
        import traceback
        content["detail"] = str(exc)
        content["traceback"] = traceback.format_exc()

    return JSONResponse(

        status_code=500,

        content=content
    )

# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/ping")

async def ping():

    """
    Quick health endpoint.
    """

    return {

        "status": "alive",

        "timestamp":
            datetime.utcnow()
    }

# ============================================================================
# STARTUP TEST
# ============================================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(

        "app.main:app",

        host=settings.HOST,

        port=settings.PORT,

        reload=settings.DEBUG
    )