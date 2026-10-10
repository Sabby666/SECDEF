from datetime import datetime, timezone
from fastapi import APIRouter, Response, status
from shared_contracts import HealthResponse, SystemStatusResponse
from app.infrastructure.db.session import check_db_health
from app.infrastructure.cache.redis import check_redis_health

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=HealthResponse)
async def get_health():
    db_ok = await check_db_health()
    redis_ok = await check_redis_health()
    
    return HealthResponse(
        status="healthy" if (db_ok and redis_ok) else "degraded",
        timestamp=datetime.now(timezone.utc),
        version="1.0.0",
        checks={
            "database": "ok" if db_ok else "failed",
            "redis": "ok" if redis_ok else "failed"
        }
    )


@router.get("/live", status_code=status.HTTP_200_OK)
async def liveness_probe():
    return {"status": "alive"}


@router.get("/ready", status_code=status.HTTP_200_OK)
async def readiness_probe(response: Response):
    db_ok = await check_db_health()
    redis_ok = await check_redis_health()
    
    is_ready = db_ok and redis_ok
    if not is_ready:
        response.status_code = status.HTTP_533_SERVICE_UNAVAILABLE if hasattr(status, 'HTTP_533_SERVICE_UNAVAILABLE') else 503
        return {"status": "not_ready", "database": db_ok, "redis": redis_ok}
    
    return {"status": "ready", "database": db_ok, "redis": redis_ok}
