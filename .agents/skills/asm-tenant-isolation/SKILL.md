---
name: asm-tenant-isolation
description: ASM Multi-Tenant Data & Processing Isolation Guardrails. Enforces org_id URL path scoping, mandatory SQLAlchemy ORM query filtering, object ownership validation, and zero cross-tenant data leakage in Attack Surface Monitor.
---

# ASM Multi-Tenant Isolation Guardrails (`asm-tenant-isolation`)

## Purpose
This skill enforces absolute multi-tenant data, memory, and processing boundaries across all control-plane APIs, database models, worker jobs, and UI views in Attack Surface Monitor (ASM).

## Verification Pipeline (Mandatory for Every Request)
```
Request
  → Authentication (JWT / Session)
  → Organization Membership Check (org_id match)
  → RBAC Permission Check (@require_role)
  → Target Authorization (Resource belongs to tenant)
  → Tenant-Scoped ORM Query (.where(Model.org_id == org_id))
  → Object Ownership & Boundary Validation
  → Response Serialization (No leaked tenant fields)
  → Audit Log Emission
```

## Mandatory Tenant Isolation Invariants

### 1. Mandatory `org_id` Scoping
- All API endpoint routes MUST include `/organizations/{org_id}/...` in their path structure.
- The authenticated user MUST be verified as an active member of `{org_id}`.

### 2. Database Query Isolation
- EVERY database query (select, update, delete) MUST include an explicit `.where(Model.org_id == org_id)` clause.
- Implicit or un-scoped queries (e.g. `select(Asset).where(Asset.id == asset_id)`) without `org_id` filtering are STRICTLY PROHIBITED.

### 3. Absolute Cross-Tenant Prohibitions
- **NO Cross-Tenant Reads**: Tenant A must never be able to read assets, findings, scans, or domains belonging to Tenant B.
- **NO Cross-Tenant Writes**: State mutations targeting resources of another tenant must immediately fail with `404 Not Found` or `403 Forbidden`.
- **NO Cross-Tenant Inference / AI Context**: AI investigation sessions, context memory, and threat feeds must be strictly scoped to the requesting tenant's `org_id`.
- **NO Global Rule Mutation**: A tenant-specific security observation must NEVER create a global scanner rule or mutate system-wide configuration affecting other tenants.
