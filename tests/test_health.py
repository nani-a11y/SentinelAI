from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient

from sentinelai.database import check_db_health


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Test root endpoint returns application info."""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "SentinelAI"
    assert data["status"] == "running"
    assert "version" in data


@pytest.mark.asyncio
async def test_health_endpoint_healthy(client: AsyncClient):
    """Test health endpoint when database connectivity is healthy."""
    mock_db_result = {"status": "connected", "latency_ms": 1.25, "detail": None}

    with patch("sentinelai.api.routes.health.check_db_health", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = mock_db_result
        response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "SentinelAI"
    assert data["database"]["status"] == "connected"
    assert data["database"]["latency_ms"] == 1.25


@pytest.mark.asyncio
async def test_health_endpoint_degraded(client: AsyncClient):
    """Test health endpoint reports degraded status when database is unavailable."""
    mock_db_result = {"status": "unavailable", "latency_ms": 3000.0, "detail": "Connection refused"}

    with patch("sentinelai.api.routes.health.check_db_health", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = mock_db_result
        response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    assert data["database"]["status"] == "unavailable"


@pytest.mark.asyncio
async def test_structured_error_handling_404(client: AsyncClient):
    """Test custom error handling returns structured error format on 404."""
    response = await client.get("/non-existent-route")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "HTTP_ERROR"
    assert "Not Found" in data["error"]["message"]


@pytest.mark.asyncio
async def test_check_db_health_live_fallback():
    """Test check_db_health handles real failure gracefully without throwing."""
    # When PostgreSQL is down, check_db_health returns status="unavailable" rather than raising
    result = await check_db_health(timeout_seconds=0.5)
    assert "status" in result
    assert result["status"] in ("connected", "unavailable")
    assert "latency_ms" in result
