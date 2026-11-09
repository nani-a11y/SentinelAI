from collections.abc import AsyncGenerator
import pytest
from httpx import ASGITransport, AsyncClient

from sentinelai.main import create_app


@pytest.fixture
def app():
    """Create a fresh app instance for testing."""
    return create_app()


@pytest.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP test client bound to ASGI transport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
