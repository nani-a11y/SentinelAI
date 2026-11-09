import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from sentinelai.api.routes.chat import router as chat_router
from sentinelai.api.routes.health import router as health_router
from sentinelai.api.routes.security import router as security_router
from sentinelai.config import get_settings
from sentinelai.database import close_db_engine
from sentinelai.exceptions import register_exception_handlers
from sentinelai.logging import setup_logging

logger = logging.getLogger("sentinelai.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown."""
    settings = get_settings()
    setup_logging(settings.log_level)
    logger.info(
        "Starting %s v%s in %s mode",
        settings.app_name,
        settings.app_version,
        settings.environment,
        extra={"app": settings.app_name, "version": settings.app_version, "env": settings.environment},
    )
    yield
    logger.info("Shutting down %s", settings.app_name)
    await close_db_engine()


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="SentinelAI Foundation Service",
        lifespan=lifespan,
    )

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request logging and execution timing middleware
    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next) -> Response:
        start_time = time.monotonic()
        response: Response = await call_next(request)
        process_time_ms = round((time.monotonic() - start_time) * 1000, 2)
        response.headers["X-Process-Time-Ms"] = str(process_time_ms)

        logger.info(
            "%s %s -> %s (%sms)",
            request.method,
            request.url.path,
            response.status_code,
            process_time_ms,
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": process_time_ms,
            },
        )
        return response

    # Exception Handlers
    register_exception_handlers(app)

    # Routes
    app.include_router(health_router)
    app.include_router(chat_router)
    app.include_router(security_router)

    @app.get("/", tags=["Root"])
    async def root() -> dict[str, str]:
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "status": "running",
            "docs_url": "/docs",
        }

    return app


app = create_app()

if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "sentinelai.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
