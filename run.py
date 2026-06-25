# run.py

"""
==============================================================================
SafePay AI — Backend Runner
==============================================================================

Purpose
-------
Central application launcher.

Features
--------
✅ FastAPI launcher
✅ Environment detection
✅ Production support
✅ Development mode
✅ Colored startup logs
✅ Auto-reload support
✅ System diagnostics
✅ ML model checks
✅ Database checks
✅ Graceful shutdown

Run
---
Development:
python run.py

Production:
python run.py --prod

Custom Port:
python run.py --port 9000

==============================================================================
"""

import argparse
import os
import platform
import socket
import sys
from datetime import datetime

import uvicorn

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

    log_shutdown
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
# DATABASE
# ============================================================================

from app.database.db import engine

# ============================================================================
# COLORS
# ============================================================================

class Colors:

    GREEN = "\033[92m"

    RED = "\033[91m"

    YELLOW = "\033[93m"

    CYAN = "\033[96m"

    RESET = "\033[0m"

# ============================================================================
# SYSTEM INFO
# ============================================================================

def print_system_info():

    """
    Display environment diagnostics.
    """

    print(

        f"""
{Colors.CYAN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🖥️ SYSTEM INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🐍 Python:
{platform.python_version()}

💻 Platform:
{platform.system()} {platform.release()}

🧠 Processor:
{platform.processor()}

🌐 Hostname:
{socket.gethostname()}

📂 Working Directory:
{os.getcwd()}

🕒 Startup Time:
{datetime.utcnow()}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.RESET}
"""
    )

# ============================================================================
# DATABASE CHECK
# ============================================================================

def check_database():

    """
    Verify database connectivity.
    """

    try:

        connection = engine.connect()

        connection.close()

        print(

            f"""
{Colors.GREEN}
✅ Database Connection Successful
{Colors.RESET}
"""
        )

        logger.info(
            "✅ Database connectivity verified"
        )

        return True

    except Exception as e:

        print(

            f"""
{Colors.RED}
❌ Database Connection Failed

🧠 Error:
{str(e)}
{Colors.RESET}
"""
        )

        logger.error(
            f"""
❌ Database check failed

🧠 Error:
{str(e)}
"""
        )

        return False

# ============================================================================
# ML MODEL CHECK
# ============================================================================

def check_models():

    """
    Verify ML models.
    """

    try:

        print(

            f"""
{Colors.YELLOW}
🧠 Checking ML Models...
{Colors.RESET}
"""
        )

        upi_status = upi_model_health()

        text_status = text_model_health()

        print(

            f"""
{Colors.GREEN}
✅ UPI Model:
{upi_status}

✅ Text Model:
{text_status}
{Colors.RESET}
"""
        )

        logger.info(
            "✅ ML model diagnostics complete"
        )

        return True

    except Exception as e:

        print(

            f"""
{Colors.RED}
❌ ML Model Check Failed

🧠 Error:
{str(e)}
{Colors.RESET}
"""
        )

        logger.error(
            f"""
❌ ML model diagnostics failed

🧠 Error:
{str(e)}
"""
        )

        return False

# ============================================================================
# DIRECTORY CHECK
# ============================================================================

def ensure_directories():

    """
    Create required directories.
    """

    required = [

        "logs",

        "logs/errors",

        "logs/security",

        "logs/fraud",

        "logs/access",

        "uploads",

        "temp",

        "app/ml/models",

        "app/ml/plots"
    ]

    for directory in required:

        os.makedirs(

            directory,

            exist_ok=True
        )

    logger.info(
        "✅ Required directories ensured"
    )

# ============================================================================
# ENVIRONMENT DISPLAY
# ============================================================================

def print_environment():

    """
    Display app configuration.
    """

    print(

        f"""
{Colors.CYAN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚙️ APPLICATION CONFIG
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 App Name:
{settings.APP_NAME}

📦 Version:
{settings.APP_VERSION}

🌍 Environment:
{settings.ENVIRONMENT}

🐞 Debug:
{settings.DEBUG}

🌐 Host:
{settings.HOST}

🚪 Port:
{settings.PORT}

🧠 Hybrid Intelligence:
{settings.ENABLE_HYBRID_INTELLIGENCE}

📩 SMS Analysis:
{settings.ENABLE_SMS_ANALYSIS}

📷 QR Analysis:
{settings.ENABLE_QR_SCANNING}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.RESET}
"""
    )

# ============================================================================
# RUN SERVER
# ============================================================================

def run_server(

    host: str,

    port: int,

    reload: bool
):

    """
    Start FastAPI server.
    """

    logger.info(
        f"""
🚀 Starting SafePay AI

🌐 Host:
{host}

🚪 Port:
{port}

🔄 Reload:
{reload}
"""
    )

    uvicorn.run(

        "app.main:app",

        host=host,

        port=port,

        reload=reload,

        workers=1 if reload else settings.WORKERS,

        log_level="info"
    )

# ============================================================================
# MAIN
# ============================================================================

def main():

    """
    Main launcher.
    """

    parser = argparse.ArgumentParser(

        description=
        "SafePay AI Backend Launcher"
    )

    parser.add_argument(

        "--prod",

        action="store_true",

        help="Run in production mode"
    )

    parser.add_argument(

        "--port",

        type=int,

        default=settings.PORT,

        help="Custom server port"
    )

    parser.add_argument(

        "--host",

        type=str,

        default=settings.HOST,

        help="Custom host"
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------------
    # STARTUP
    # ------------------------------------------------------------------------

    print(STARTUP_BANNER)

    log_startup()

    ensure_directories()

    print_system_info()

    print_environment()

    # ------------------------------------------------------------------------
    # CHECKS
    # ------------------------------------------------------------------------

    db_ok = check_database()

    ml_ok = check_models()

    if not db_ok:

        print(

            f"""
{Colors.RED}
❌ Startup aborted due to DB failure
{Colors.RESET}
"""
        )

        sys.exit(1)

    if not ml_ok:

        print(

            f"""
{Colors.YELLOW}
⚠️ ML diagnostics failed

Continuing startup...
{Colors.RESET}
"""
        )

    # ------------------------------------------------------------------------
    # MODE
    # ------------------------------------------------------------------------

    production = args.prod

    reload_mode = not production

    mode = "PRODUCTION" if production else "DEVELOPMENT"

    print(

        f"""
{Colors.GREEN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ SAFEPAY AI READY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔥 Mode:
{mode}

🌐 URL:
http://{args.host}:{args.port}

📘 Swagger Docs:
http://{args.host}:{args.port}/docs

📕 ReDoc:
http://{args.host}:{args.port}/redoc

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.RESET}
"""
    )

    # ------------------------------------------------------------------------
    # START UVICORN
    # ------------------------------------------------------------------------

    try:

        run_server(

            host=args.host,

            port=args.port,

            reload=reload_mode
        )

    except KeyboardInterrupt:

        print(

            f"""
{Colors.YELLOW}
🛑 Shutdown requested
{Colors.RESET}
"""
        )

        log_shutdown()

    except Exception as e:

        print(

            f"""
{Colors.RED}
❌ Server crashed

🧠 Error:
{str(e)}
{Colors.RESET}
"""
        )

        logger.error(
            f"""
❌ SERVER CRASH

🧠 Error:
{str(e)}
"""
        )

# ============================================================================
# ENTRYPOINT
# ============================================================================

if __name__ == "__main__":

    main()