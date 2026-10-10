from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from shared_contracts import APIErrorDetail

from app.core.config import settings
from app.core.logging import setup_logging, logger
from app.core.security import SecurityHeadersMiddleware, RequestContextMiddleware
from app.api.v1.health import router as health_router
from app.api.v1.domains import router as domains_router
from app.api.v1.scans import router as scans_router
from app.api.v1.assets import router as assets_router
from app.api.v1.changes import router as changes_router
from app.api.v1.context import router as context_router
from app.api.v1.risk import router as risk_router
from app.api.v1.findings import router as findings_router
from app.api.v1.notifications import router as notifications_router
from app.api.v1.discovery import router as discovery_router
from app.api.v1.exposures import router as exposures_router
from app.api.v1.intelligence import router as intelligence_router
from app.api.v1.assistant import router as assistant_router
from app.api.v1.automation import router as automation_router
from app.api.v1.actions import router as actions_router
from app.api.v1.auth import router as auth_router
from app.infrastructure.cache.redis import close_redis_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info(
        "app_startup",
        app_name=settings.APP_NAME,
        environment=settings.APP_ENV
    )
    if settings.APP_ENV == "development":
        try:
            from app.infrastructure.db.session import AsyncSessionLocal
            from app.infrastructure.db.bootstrap import bootstrap_development_data
            async with AsyncSessionLocal() as session:
                await bootstrap_development_data(session)
        except Exception as exc:
            logger.warning("dev_bootstrap_failed", error=str(exc))
    yield
    await close_redis_client()
    logger.info("app_shutdown_complete")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version="1.0.0",
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        lifespan=lifespan
    )

    # Middleware Assembly (Order: Host check -> Request Context -> Security Headers -> CORS)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS + ["testserver", "test"])
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Include Routers
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(domains_router, prefix="/api/v1")
    app.include_router(scans_router, prefix="/api/v1")
    app.include_router(assets_router, prefix="/api/v1")
    app.include_router(changes_router, prefix="/api/v1")
    app.include_router(context_router, prefix="/api/v1")
    app.include_router(risk_router, prefix="/api/v1")
    app.include_router(findings_router, prefix="/api/v1")
    app.include_router(notifications_router, prefix="/api/v1")
    app.include_router(discovery_router, prefix="/api/v1")
    app.include_router(exposures_router, prefix="/api/v1")
    app.include_router(intelligence_router, prefix="/api/v1")
    app.include_router(assistant_router, prefix="/api/v1")
    app.include_router(automation_router, prefix="/api/v1")
    app.include_router(actions_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz():
        return {"status": "ready"}






    # Global Exception Handlers (No secrets or stack traces in production)
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(
            "unhandled_exception",
            error=str(exc),
            path=request.url.path,
            exc_info=settings.is_development
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=APIErrorDetail(
                error="Internal server error",
                code="INTERNAL_SERVER_ERROR",
                details={"message": str(exc)} if settings.is_development else None
            ).model_dump(exclude_none=True)
        )

    return app


app = create_app()
