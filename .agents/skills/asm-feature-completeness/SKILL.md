---
name: asm-feature-completeness
description: ASM End-to-End Feature Completeness Guardrails. Prohibits fake data, mock business logic, and UI-only features. Enforces 1:1 binding from UI views to real FastAPI domain engines in Attack Surface Monitor.
---

# ASM Feature Completeness Guardrails (`asm-feature-completeness`)

## Purpose
This skill ensures that all functionality presented in the Attack Surface Monitor (ASM) product is backed by real, fully integrated end-to-end domain engines, APIs, and database persistence.

## Mandatory Feature Completeness Chain
A feature is considered COMPLETE ONLY when every link in this chain is fully implemented and verified:
```
UI View
  → Route Handler
  → API Contract (Pydantic v2)
  → Authentication (JWT / Session)
  → RBAC Permission Gate (@require_role)
  → Tenant Scoping (org_id filter)
  → Business Logic Engine
  → Persistence (SQLAlchemy Async ORM / Alembic)
  → Security Audit Emission
  → UI States (Loading, Empty, Error, Permission, Success)
  → Unit & Integration Tests
  → E2E Route Verification
```

## Prohibited Anti-Patterns
- **NO Fake / Mock Data**: Seeding fake production data or mock hardcoded values in UI code to simulate working features is STRICTLY PROHIBITED.
- **NO Simulated Success**: UI buttons returning dummy success toasts without making real API calls are prohibited.
- **NO UI-Only Features**: Creating frontend routes or interactive cards that have no corresponding backend endpoints or services is prohibited.
- **NO Development Metadata in Production UI**: Internal metadata tags (e.g. "Phase 1H Control Plane") MUST NOT appear in customer-facing product views.
- **Honest Empty States**: If an endpoint has no data, render an intentional, clear empty state (e.g. "No assets discovered yet. Add a verified domain to begin.").
