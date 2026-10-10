import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.infrastructure.db.session import check_db_health
from app.infrastructure.cache.redis import check_redis_health


@pytest.mark.asyncio
async def test_db_health_check_resilience():
    # Verify sqlite/postgres health check executes without crashing
    db_status = await check_db_health()
    assert isinstance(db_status, bool)


@pytest.mark.asyncio
async def test_redis_health_check_resilience():
    # Verify redis health check handles missing redis gracefully (returns False)
    redis_status = await check_redis_health()
    assert isinstance(redis_status, bool)


@pytest.mark.asyncio
async def test_untrusted_host_header_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://evil-host.com") as client:
        response = await client.get("/api/v1/health/live", headers={"Host": "evil-host.com"})
        assert response.status_code == 400
