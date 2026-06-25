# app/database/db.py

"""
SafePay AI — Database layer.

This module wraps SQLAlchemy engine creation, session management,
health checks, and schema initialization for SQLite and PostgreSQL.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Callable, Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import QueuePool

from app.config import settings
from app.utils.logger import logger

DATABASE_URL = settings.DATABASE_URL
IS_SQLITE = DATABASE_URL.startswith("sqlite")
DATABASE_TYPE = "SQLite" if IS_SQLITE else "PostgreSQL"


def _build_engine_config() -> dict[str, Any]:
    config: dict[str, Any] = {
        "echo": settings.DB_ECHO,
        "future": True,
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }

    if IS_SQLITE:
        config["connect_args"] = {"check_same_thread": False}
    else:
        config.update({
            "poolclass": QueuePool,
            "pool_size": settings.DB_POOL_SIZE,
            "max_overflow": settings.DB_MAX_OVERFLOW,
            "pool_timeout": settings.DB_POOL_TIMEOUT,
        })

    return config


try:
    engine: Engine = create_engine(DATABASE_URL, **_build_engine_config())
    logger.info("Database engine initialized")
except Exception:
    logger.exception("Engine initialization failed")
    raise

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
    future=True,
)

Base = declarative_base()


def _log_duration(start: float, message: str) -> None:
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    logger.info(f"{message} ({duration_ms} ms)")


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    start = time.perf_counter()

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Database transaction failed")
        raise
    finally:
        db.close()
        _log_duration(start, "Database session closed")


@contextmanager
def db_session() -> Generator[Session, None, None]:
    """Context manager for manual session handling."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db(engine_to_use: Engine = engine) -> None:
    """Create all database tables from SQLAlchemy metadata."""
    try:
        logger.info("Initializing database schema")
        Base.metadata.create_all(bind=engine_to_use)
        logger.info("Database schema created")
    except Exception:
        logger.exception("Database initialization failed")
        raise


def check_database_connection() -> dict[str, Any]:
    """Verify database connectivity and return a result payload."""
    start = time.perf_counter()

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info(f"Database connected ({DATABASE_TYPE}, {latency_ms} ms)")

        return {
            "success": True,
            "database_url": DATABASE_URL,
            "database_type": DATABASE_TYPE,
            "latency_ms": latency_ms,
        }
    except OperationalError:
        logger.exception("Database connection failed")
        return {"success": False, "error": "OperationalError"}


def retry_database_connection(retries: int = 5, delay: int = 2) -> dict[str, Any]:
    """Retry database connectivity checks with a delay."""
    for attempt in range(1, retries + 1):
        logger.info(f"Retrying database connection ({attempt}/{retries})")
        result = check_database_connection()
        if result["success"]:
            return result
        time.sleep(delay)

    return {"success": False, "error": "Max retries exceeded"}


def get_database_stats() -> dict[str, Any]:
    """Return engine pool statistics for monitoring."""
    try:
        pool = engine.pool
        return {
            "pool_size": getattr(pool, "size", lambda: 0)(),
            "checked_in": getattr(pool, "checkedin", lambda: 0)(),
            "checked_out": getattr(pool, "checkedout", lambda: 0)(),
            "overflow": getattr(pool, "overflow", lambda: 0)(),
        }
    except Exception:
        logger.exception("Failed to retrieve database stats")
        return {"success": False, "error": "Unable to fetch pool stats"}


def safe_execute(query_function: Callable[[Session], Any]) -> Any:
    """Execute a callable inside a managed database session."""
    with SessionLocal() as db:
        try:
            result = query_function(db)
            db.commit()
            return result
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Safe execute failed")
            raise


def shutdown_db() -> None:
    """Dispose engine connections cleanly."""
    try:
        logger.info("Disposing database engine")
        engine.dispose()
        logger.info("Database engine disposed")
    except Exception:
        logger.exception("Database shutdown failed")


__all__ = [
    "Base",
    "SessionLocal",
    "engine",
    "get_db",
    "db_session",
    "init_db",
    "check_database_connection",
    "retry_database_connection",
    "get_database_stats",
    "safe_execute",
    "shutdown_db",
]


if __name__ == "__main__":
    print(check_database_connection())
    print(get_database_stats())
