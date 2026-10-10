from typing import Optional
import redis.asyncio as aioredis
from app.core.config import settings
from app.core.logging import logger

redis_client: Optional[aioredis.Redis] = None


async def get_redis_client() -> aioredis.Redis:
    global redis_client
    if redis_client is None:
        redis_client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=5.0,
            socket_connect_timeout=5.0
        )
    return redis_client


async def close_redis_client():
    global redis_client
    if redis_client is not None:
        await redis_client.close()
        redis_client = None
        logger.info("redis_connection_closed")


async def check_redis_health() -> bool:
    """Verify Redis connection health."""
    try:
        client = await get_redis_client()
        return await client.ping()
    except Exception as exc:
        logger.warning("redis_health_check_failed", error=str(exc))
        return False
