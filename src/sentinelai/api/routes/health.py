from typing import Any
from fastapi import APIRouter, status
from pydantic import BaseModel

from sentinelai.config import get_settings
from sentinelai.database import check_db_health

router = APIRouter(tags=["Health"])


class DatabaseHealth(BaseModel):
    status: str
    latency_ms: float | None = None
    detail: str | None = None


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    environment: str
    database: DatabaseHealth


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Service Health Check",
    description="Check application and database connectivity status.",
)
async def get_health() -> dict[str, Any]:
    """Returns overall application health and database connection status."""
    settings = get_settings()
    db_result = await check_db_health()

    overall_status = "healthy" if db_result["status"] == "connected" else "degraded"

    return {
        "status": overall_status,
        "app": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "database": db_result,
    }
