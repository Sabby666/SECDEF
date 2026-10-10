import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import Request, HTTPException, status
from app.infrastructure.cache.redis import get_redis_client
from app.core.logging import logger

_IN_MEMORY_COUNTERS = {}
_IN_MEMORY_CONCURRENCY = {}


async def check_rate_limit(key: str, limit: int, window: int):
    """Basic fixed-window rate limiter using Redis."""
    client = await get_redis_client()
    if not client:
        logger.warning("redis_unavailable_for_rate_limit", key=key)
        return
        
    current_time = int(time.time())
    window_start = current_time // window
    
    redis_key = f"rate_limit:{key}:{window_start}"
    
    try:
        current_count = await client.incr(redis_key)
        if current_count == 1:
            await client.expire(redis_key, window)
            
        if current_count > limit:
            logger.warning("rate_limit_exceeded", key=key, count=current_count, limit=limit)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later."
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("rate_limit_redis_error", error=str(e))
        pass


async def _increment_counter(key: str, window: int) -> int:
    """Helper to increment rate limit counter using Redis with in-memory fallback for testing/resilience."""
    client = await get_redis_client()
    if client:
        try:
            current_time = int(time.time())
            window_start = current_time // window
            redis_key = f"rate_limit:{key}:{window_start}"
            count = await client.incr(redis_key)
            if count == 1:
                await client.expire(redis_key, window)
            return count
        except Exception as e:
            logger.warning("redis_rate_limit_fallback_to_memory", error=str(e))
    
    current_time = int(time.time())
    window_start = current_time // window
    mem_key = f"{key}:{window_start}"
    _IN_MEMORY_COUNTERS[mem_key] = _IN_MEMORY_COUNTERS.get(mem_key, 0) + 1
    return _IN_MEMORY_COUNTERS[mem_key]


async def check_recalculate_rate_limits(user_id: str, org_id: str):
    """Enforce per-user (10 req/min) and per-organization (30 req/min) recalculation rate limits."""
    user_key = f"recalc:user:{user_id}"
    org_key = f"recalc:org:{org_id}"

    user_count = await _increment_counter(user_key, window=60)
    if user_count > 10:
        logger.warning("recalculate_user_rate_limit_exceeded", user_id=user_id, count=user_count)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="User recalculation rate limit exceeded (max 10 requests per minute).",
        )

    org_count = await _increment_counter(org_key, window=60)
    if org_count > 30:
        logger.warning("recalculate_org_rate_limit_exceeded", org_id=org_id, count=org_count)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Organization recalculation rate limit exceeded (max 30 requests per minute).",
        )


@asynccontextmanager
async def acquire_recalculate_concurrency_slot(org_id: str, max_concurrent: int = 2) -> AsyncGenerator[None, None]:
    """Ensure max_concurrent recalculation operations run simultaneously for an organization."""
    client = await get_redis_client()
    key = f"concurrency:recalc:org:{org_id}"
    acquired_redis = False

    if client:
        try:
            count = await client.incr(key)
            if count > max_concurrent:
                await client.decr(key)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Concurrent recalculation limit exceeded for organization (max {max_concurrent} concurrent).",
                )
            acquired_redis = True
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("redis_concurrency_fallback_to_memory", error=str(e))

    if not acquired_redis:
        current_active = _IN_MEMORY_CONCURRENCY.get(org_id, 0)
        if current_active >= max_concurrent:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Concurrent recalculation limit exceeded for organization (max {max_concurrent} concurrent).",
            )
        _IN_MEMORY_CONCURRENCY[org_id] = current_active + 1

    try:
        yield
    finally:
        if acquired_redis and client:
            try:
                await client.decr(key)
            except Exception as e:
                logger.warning("redis_concurrency_decr_failed", error=str(e))
        else:
            _IN_MEMORY_CONCURRENCY[org_id] = max(0, _IN_MEMORY_CONCURRENCY.get(org_id, 1) - 1)


async def check_ai_rate_limits(user_id: str, org_id: str, user_limit: int = 5, org_limit: int = 15, window: int = 60):
    """Enforce per-user (5 req/min) and per-organization (15 req/min) AI request rate limits."""
    user_key = f"ai_query:user:{user_id}"
    org_key = f"ai_query:org:{org_id}"

    user_count = await _increment_counter(user_key, window=window)
    if user_count > user_limit:
        logger.warning("ai_user_rate_limit_exceeded", user_id=user_id, count=user_count)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"User AI query rate limit exceeded (max {user_limit} requests per minute).",
        )

    org_count = await _increment_counter(org_key, window=window)
    if org_count > org_limit:
        logger.warning("ai_org_rate_limit_exceeded", org_id=org_id, count=org_count)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Organization AI query rate limit exceeded (max {org_limit} requests per minute).",
        )


@asynccontextmanager
async def acquire_ai_concurrency_slot(org_id: str, max_concurrent: int = 3) -> AsyncGenerator[None, None]:
    """Ensure max_concurrent AI operations run simultaneously for an organization."""
    client = await get_redis_client()
    key = f"concurrency:ai:org:{org_id}"
    acquired_redis = False

    if client:
        try:
            count = await client.incr(key)
            if count > max_concurrent:
                await client.decr(key)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Concurrent AI request limit exceeded for organization (max {max_concurrent} concurrent).",
                )
            acquired_redis = True
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("redis_ai_concurrency_fallback_to_memory", error=str(e))

    if not acquired_redis:
        current_active = _IN_MEMORY_CONCURRENCY.get(f"ai:{org_id}", 0)
        if current_active >= max_concurrent:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Concurrent AI request limit exceeded for organization (max {max_concurrent} concurrent).",
            )
        _IN_MEMORY_CONCURRENCY[f"ai:{org_id}"] = current_active + 1

    try:
        yield
    finally:
        if acquired_redis and client:
            try:
                await client.decr(key)
            except Exception as e:
                logger.warning("redis_ai_concurrency_decr_failed", error=str(e))
        else:
            _IN_MEMORY_CONCURRENCY[f"ai:{org_id}"] = max(0, _IN_MEMORY_CONCURRENCY.get(f"ai:{org_id}", 1) - 1)

