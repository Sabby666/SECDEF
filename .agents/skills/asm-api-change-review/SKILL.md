---
name: asm-api-change-review
description: ASM API Contract & Schema Change Review Guardrails. Protects FastAPI contracts, Pydantic v2 schemas, shared DTO contracts, and frontend/backend compatibility for Attack Surface Monitor.
---

# ASM API Change Review Guardrails (`asm-api-change-review`)

## Purpose
This skill protects API contracts, schema compatibility, versioning, and shared data transfer objects (DTOs) across control-plane FastAPI endpoints, worker ingestion contracts, and Next.js frontend clients in Attack Surface Monitor (ASM).

## Mandatory Contract Invariants

### 1. Schema Validation (Pydantic v2)
- All request payloads and response bodies MUST be defined using Pydantic v2 models.
- Endpoint models MUST enforce strict type validation, field constraints, and field descriptions.

### 2. Shared Contracts Boundary (`packages/shared-contracts`)
- `packages/shared-contracts/python/shared_contracts` is reserved EXCLUSIVELY for shared data transfer objects (DTOs), event schemas, and enum definitions.
- **NO Business Logic**: Do NOT place database access, service logic, ORM models, or framework dependencies inside `shared-contracts`.

### 3. Contract Compatibility & Versioning
- **No Breaking Changes**: Modifying existing API endpoint paths, response fields, or parameter types without a formal version bump is STRICTLY PROHIBITED.
- **Frontend Sync**: Whenever a control-plane API schema is updated, the frontend API client (`apps/web-frontend/app/lib/api.ts`) and TypeScript types (`apps/web-frontend/app/lib/types.ts`) MUST be updated in lockstep.
- **No Invented Endpoints**: Frontend redesign work must consume existing backend endpoints. Inventing mock API routes on the frontend without corresponding backend implementation is prohibited.
