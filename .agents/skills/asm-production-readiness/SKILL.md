---
name: asm-production-readiness
description: ASM Production Readiness & Operational Reliability Guardrails. Governs structured logging, health checks, rate limiting, container security, gracefully failing workers, and deployment readiness for Attack Surface Monitor.
---

# ASM Production Readiness Guardrails (`asm-production-readiness`)

## Purpose
This skill governs operational readiness, structured logging, error handling, rate limiting, health checks, and container security for production deployment of Attack Surface Monitor (ASM).

## Mandatory Production Readiness Rules

### 1. Observability & Logging
- Control plane and worker processes MUST emit structured JSON logs (`app.core.logging`).
- All log events MUST include `timestamp`, `service`, `event_type`, `level`, and request correlation IDs (`request_id`, `org_id`).

### 2. Health & Readiness Probes
- **`/healthz`**: Returns `200 OK` if application process is alive.
- **`/readyz`**: Returns `200 OK` ONLY when database connection pool (`SQLAlchemy`) and Redis/Valkey cache connections are verified healthy.

### 3. Error Handling & Rate Limiting
- Unhandled exceptions MUST NOT leak stack traces, internal database path names, or environment variables to client responses.
- API endpoints MUST enforce rate limiting via Redis bucket counters to prevent resource exhaustion attacks.

### 4. Container & Process Hardening
- Containers MUST run as non-root unprivileged users.
- Worker processes MUST handle SIGTERM gracefully, allowing active scan jobs to save checkpoints or terminate cleanly without data loss.
- **Local Build Rule**: A successful local build or test run does NOT equal production readiness; environment configs, secrets, and deployment manifests must pass production security review.
