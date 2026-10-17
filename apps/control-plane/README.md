# Control Plane Application

Modular Monolith backend for SECDEF.

## Features (Phase 0)
- FastAPI async-native framework
- Pydantic Settings configuration (`.env` support)
- Async SQLAlchemy engine (SQLite / PostgreSQL)
- Async Redis client
- Alembic database migration foundation
- Structured JSON logging (`structlog`) with request IDs
- Health (`/api/v1/health`), Liveness (`/api/v1/health/live`), Readiness (`/api/v1/health/ready`)
- Security baseline (Strict Security Headers, CORS, Rate Limiting framework)
