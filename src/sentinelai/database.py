import asyncio
import logging
import time
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinelai.config import get_settings

logger = logging.getLogger("sentinelai.database")

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Get or create singleton async database engine."""
    global _engine, _session_factory
    if _engine is None:
        settings = get_settings()
        is_sqlite = settings.database_url.startswith("sqlite")

        engine_kwargs: dict[str, Any] = {
            "echo": settings.debug and False,
        }

        # PostgreSQL-specific connection pool options
        if not is_sqlite:
            engine_kwargs.update(
                {
                    "pool_size": settings.db_pool_size,
                    "max_overflow": settings.db_max_overflow,
                    "pool_pre_ping": True,
                }
            )

        _engine = create_async_engine(settings.database_url, **engine_kwargs)
        _session_factory = async_sessionmaker(
            bind=_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get or create sessionmaker."""
    if _session_factory is None:
        get_engine()
    assert _session_factory is not None
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for providing an async database session per request."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_db_health(timeout_seconds: float | None = None) -> dict[str, Any]:
    """Lightweight health check probe for database connectivity."""
    settings = get_settings()
    timeout = timeout_seconds or settings.db_timeout_seconds
    engine = get_engine()

    start_time = time.monotonic()
    try:
        async with asyncio.timeout(timeout):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        return {
            "status": "connected",
            "latency_ms": latency_ms,
        }
    except Exception as exc:
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        logger.warning("Database health check failed: %s", str(exc))
        return {
            "status": "unavailable",
            "latency_ms": latency_ms,
            "detail": str(exc),
        }


async def close_db_engine() -> None:
    """Dispose database engine connections gracefully."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Database engine connections closed.")
