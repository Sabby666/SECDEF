# Phase 1C — Asset Resolution & Relationship Graph Review Report

> **Status:** READY FOR HUMAN SECURITY APPROVAL  
> **Phase:** Phase 1C (Asset Resolution & Relationship Graph)  
> **Date:** 2026-09-06  
> **Author:** Senior Security Architect & ASM Product Engineer  
> **Gate Recommendation:** READY FOR HUMAN SECURITY APPROVAL  

---

## 1. Executive Summary

Phase 1C of the External Attack Surface Management (EASM) platform has been fully implemented, integrated, and verified against all authoritative security, domain, and architectural specifications.

Phase 1C takes raw scan observations emitted by Phase 1B workers and transforms them into a deterministic, tenant-isolated, explainable **Asset Identity Model** and directed **Asset Relationship Graph**.

All 103 automated tests in the full test suite pass cleanly (103 passed, 0 failed, 0 skipped), proving that tenant isolation, canonical identifier normalization, race-safe deduplication, evidence provenance, SAN scope safety, and API RBAC boundaries are strictly enforced.

---

## 2. Implemented Scope

The following Phase 1C capabilities were implemented and locked inside the control plane:

1. **Asset Identity Model**: Core `Asset` database model supporting subdomains, IP addresses, services, and TLS certificates.
2. **Canonical Normalization**: Pure normalization pipeline (`asset_normalizer.py`) for hostnames, IPv4/IPv6 addresses, IPv4-mapped IPv6 unwrapping, ports, and URLs.
3. **Deterministic Identity Resolution**: `AssetResolutionService` in the control plane executing deterministic, tenant-scoped candidate lookup and identity resolution.
4. **Race-Safe Deduplication**: Composite database uniqueness constraints `(org_id, asset_type, identifier)` and `(org_id, source_asset_id, target_asset_id, relationship_type)` combined with atomic `ON CONFLICT DO UPDATE` database upserts.
5. **Directed Relationship Graph**: Explicit relationship edges (`resolves_to`, `runs_service`, `presents_cert`, `associated_with`) connecting assets.
6. **Traceable Evidence & Provenance**: Immutable provenance attached to every relationship edge and observation (`scan_id`, `observation_id`, `observed_at`, reason, confidence).
7. **Ingestion Pipeline Integration**: Direct execution of `AssetResolutionService` inside `IngestionService.ingest_scan_result()` following observation persistence.
8. **Tenant-Isolated API Endpoints**: Read-only REST API endpoints (`/api/v1/organizations/{org_id}/assets` and `/api/v1/organizations/{org_id}/relationships`) protected by AuthAdapter and RBAC permission checks.
9. **Alembic Database Migration**: Version `4e7f6aaa6f92` creating `assets`, `asset_relationships` tables and adding `observations.asset_id`.

---

## 3. Data Model Changes

### Database Tables Created (`apps/control-plane/app/infrastructure/db/models.py`)

#### `assets`
- `id` (VARCHAR 36, PK)
- `org_id` (VARCHAR 36, FK -> `organizations.id`, NOT NULL)
- `domain_id` (VARCHAR 36, FK -> `domains.id`, NULLABLE)
- `asset_type` (VARCHAR 50, NOT NULL: `subdomain`, `ip_address`, `service`, `certificate`)
- `identifier` (TEXT, NOT NULL: canonical identifier string)
- `environment` (VARCHAR 50, DEFAULT `'unknown'`)
- `criticality` (VARCHAR 50, DEFAULT `'medium'`)
- `owner_id` (VARCHAR 36, FK -> `users.id`, NULLABLE)
- `owner_team` (VARCHAR 255, NULLABLE)
- `expected_state` (JSON, NULLABLE)
- `first_seen_at` (TIMESTAMPTZ, NOT NULL)
- `last_seen_at` (TIMESTAMPTZ, NOT NULL)
- `status` (VARCHAR 50, DEFAULT `'active'`)
- **Indexes**: Composite Unique `uix_assets_org_type_ident` `(org_id, asset_type, identifier)`, `idx_assets_org_env`, `idx_assets_org_owner`, `idx_assets_org_type`.

#### `asset_relationships`
- `id` (VARCHAR 36, PK)
- `org_id` (VARCHAR 36, FK -> `organizations.id`, NOT NULL)
- `source_asset_id` (VARCHAR 36, FK -> `assets.id`, NOT NULL)
- `target_asset_id` (VARCHAR 36, FK -> `assets.id`, NOT NULL)
- `relationship_type` (VARCHAR 50, NOT NULL: `resolves_to`, `runs_service`, `presents_cert`, `associated_with`)
- `confidence` (VARCHAR 20, DEFAULT `'HIGH'`: HIGH, MEDIUM, LOW)
- `evidence` (JSON, NULLABLE)
- `first_seen_at` (TIMESTAMPTZ, NOT NULL)
- `last_seen_at` (TIMESTAMPTZ, NOT NULL)
- `status` (VARCHAR 50, DEFAULT `'active'`)
- **Indexes**: Composite Unique `uix_rel_org_src_tgt_type` `(org_id, source_asset_id, target_asset_id, relationship_type)`, `idx_rel_source`, `idx_rel_target`, `idx_rel_org_status`.

#### `observations` (Modified)
- `asset_id` (VARCHAR 36, FK -> `assets.id`, NULLABLE)
- **Index**: `idx_obs_asset_id`.

---

## 4. Asset Identity & Resolution Rules

Matching is strictly deterministic based on canonical identifier comparison:

| Asset Type | Primary Identifier Format | Candidate Lookup Rule |
|---|---|---|
| `subdomain` | Lowercase punycode hostname (e.g. `api.example.com`) | `WHERE org_id = :org AND asset_type = 'subdomain' AND identifier = :ident` |
| `ip_address` | Compressed canonical IPv4/IPv6 (e.g. `93.184.216.34` or `2001:db8::1`) | `WHERE org_id = :org AND asset_type = 'ip_address' AND identifier = :ident` |
| `service` | Canonical `ip:port` (e.g. `93.184.216.34:443`) | `WHERE org_id = :org AND asset_type = 'service' AND identifier = :ident` |
| `certificate` | Lowercase SHA-256 fingerprint (e.g. `sha256:a1b2...`) | `WHERE org_id = :org AND asset_type = 'certificate' AND identifier = :ident` |

> **Conservative Merging Rule**: Fuzzy or probabilistic merging is explicitly forbidden. If confidence is insufficient, separate Asset nodes are created.

---

## 5. Normalization Rules (`app/application/asset_normalizer.py`)

1. **Hostnames**:
   - Whitespace trimmed, lowercased.
   - Terminal dot removed (`example.com.` -> `example.com`).
   - IDN/Unicode hostnames converted to canonical ASCII punycode via `idna.encode().decode('ascii')`.
   - Invalid characters, spaces, or malformed syntax raise `ValueError`.
2. **IP Addresses**:
   - Validated via standard library `ipaddress`.
   - IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1` or `0:0:0:0:0:ffff:192.0.2.1`) unwrapped to canonical IPv4 `192.0.2.1`.
   - Compressed string format returned.
3. **Ports**:
   - Validated integer in range `1..65535`.
4. **URLs**:
   - Scheme and hostname lowercased.
   - Embedded credentials (`username:password@`) stripped to prevent credential leaks.
   - Port normalized to explicit or scheme default.

---

## 6. Deduplication Strategy

Idempotency and race safety are guaranteed via database-level composite unique constraints and atomic upsert operations:

- **Single Observation Processing**: Repeating the exact same scan ingestion executes atomic `ON CONFLICT (org_id, asset_type, identifier) DO UPDATE SET last_seen_at = excluded.last_seen_at`.
- **Concurrent Workers**: Multiple workers resolving the same identifier concurrently hit the atomic database upsert, producing exactly 1 canonical Asset record without race conditions.

---

## 7. Relationship Model & Provenance

Relationships represent verified directed graph edges:

- `Subdomain` ──[`resolves_to`]──► `IPAddress` (Confidence: HIGH, Reason: "Observed DNS A/AAAA record")
- `IPAddress` ──[`runs_service`]──► `Service` (Confidence: HIGH, Reason: "Observed open TCP port")
- `Service` ──[`presents_cert`]──► `Certificate` (Confidence: HIGH, Reason: "TLS certificate presented on service endpoint")
- `Certificate` ──[`associated_with`]──► `Subdomain` (Confidence: MEDIUM, Reason: "Certificate Subject Alternative Name (SAN)")

Every relationship edge contains an `evidence` JSON object storing:
- `scan_id`
- `observation_id`
- `observed_at`
- `reason`

---

## 8. Tenant Isolation & Security Controls

1. **Query Boundary**: All database queries perform candidate lookup with `WHERE org_id = :org_id` FIRST. Global lookup followed by tenant filtering is strictly prohibited.
2. **Foreign Key Safety**: Relationship resolution checks that both `source_asset.org_id == org_id` and `target_asset.org_id == org_id`. Attempting cross-tenant edges raises an explicit validation error.
3. **TLS SAN Scope Boundary**: Certificate SANs create domain assets within tenant scope, but do **NOT** grant scan target authorization (no `Domain` seed records are automatically created).
4. **API Parameter Tampering Protection**: `/api/v1/organizations/{org_id}/assets` verifies `org_id == auth_ctx["org"].id` and returns `403 Forbidden` if a user attempts cross-tenant parameter tampering.

---

## 9. Exact Security Test Matrix

| Security Control Requirement | Test File | Test Function | Result |
|---|---|---|---|
| **Tenant Isolation (Assets)** | `tests/security/test_asset_tenant_isolation.py` | `test_cross_tenant_asset_resolution_isolation` | **PASSED** |
| **Cross-Tenant Relationship Rejection** | `tests/security/test_asset_tenant_isolation.py` | `test_cross_tenant_relationship_rejection` | **PASSED** |
| **API Cross-Tenant Access Rejection** | `tests/security/test_asset_tenant_isolation.py` | `test_api_cross_tenant_asset_access_rejected` | **PASSED** |
| **TLS Certificate SAN Authorization Boundary** | `tests/integration/test_asset_resolution_pipeline.py` | `test_certificate_san_does_not_authorize_scans` | **PASSED** |
| **Concurrent Resolution Deduplication** | `tests/integration/test_asset_concurrency.py` | `test_concurrent_asset_resolution` | **PASSED** |
| **Concurrent Edge Deduplication** | `tests/integration/test_asset_concurrency.py` | `test_concurrent_relationship_creation` | **PASSED** |
| **Hostname Normalization & IDN** | `tests/unit/test_asset_normalizer.py` | `test_hostname_normalization` | **PASSED** |
| **IPv4-Mapped IPv6 Normalization** | `tests/unit/test_asset_normalizer.py` | `test_ip_normalization` | **PASSED** |
| **URL Credential Leakage Prevention** | `tests/unit/test_asset_normalizer.py` | `test_url_normalization` | **PASSED** |
| **Idempotency Invariant (Hostname)** | `tests/unit/test_asset_invariants.py` | `test_hostname_normalization_idempotency` | **PASSED** |
| **Idempotency Invariant (IP)** | `tests/unit/test_asset_invariants.py` | `test_ip_normalization_idempotency` | **PASSED** |
| **Idempotency Invariant (Service)** | `tests/unit/test_asset_invariants.py` | `test_service_endpoint_normalization_idempotency` | **PASSED** |
| **End-to-End Resolution Ingestion** | `tests/integration/test_asset_resolution_pipeline.py` | `test_asset_resolution_pipeline_end_to_end` | **PASSED** |

---

## 10. Test Execution Results

**Execution Command**:
```bash
cd apps/control-plane && source .venv/bin/activate && cd ../.. && PYTHONPATH=apps/control-plane:apps/scanner-worker:packages/shared-contracts/python pytest tests/unit tests/integration tests/worker tests/security apps/control-plane/tests/unit -v
```

**Results**:
- **Total Tests**: 103
- **Passed**: 103
- **Failed**: 0
- **Skipped**: 0
- **Duration**: 33.19 seconds

---

## 11. Files Changed & Added

- `apps/control-plane/app/infrastructure/db/models.py` (Added `Asset`, `AssetRelationship` models, updated `Observation`)
- `apps/control-plane/alembic/versions/20260906_1200_4e7f6aaa6f92_phase_1c_assets_and_relationships.py` (New Alembic migration)
- `apps/control-plane/app/application/asset_normalizer.py` (New canonical normalization helpers)
- `apps/control-plane/app/application/asset_resolution_service.py` (New deterministic resolution service)
- `apps/control-plane/app/application/ingestion_service.py` (Integrated asset resolution pipeline)
- `packages/shared-contracts/python/shared_contracts/schemas.py` (Added DTO schemas)
- `apps/control-plane/app/api/v1/assets.py` (New REST API endpoints for assets & relationships)
- `apps/control-plane/app/main.py` (Registered `assets_router`)
- `tests/unit/test_asset_normalizer.py` (New normalization unit tests)
- `tests/unit/test_asset_invariants.py` (New property & invariant tests)
- `tests/integration/test_asset_resolution_pipeline.py` (New pipeline integration tests)
- `tests/integration/test_asset_concurrency.py` (New race safety tests)
- `tests/security/test_asset_tenant_isolation.py` (New security tenant isolation tests)

---

## 12. Known Limitations & Deferred Items

- **Phase 1D Deferred**: Scan-over-scan change detection (`changes` table), diffing logic, asset added/removed events, change notifications, and expected-state comparisons are deferred to Phase 1D.
- **UI Deferred**: Full Operations Dashboard redesign remains deferred to Phase 1H. Only minimum REST API surface is implemented.

---

## 13. Gate Recommendation

**STATUS**: `READY FOR HUMAN SECURITY APPROVAL`

All Phase 1C objectives are complete, fully verified by automated security and correctness tests, and bounded strictly to Phase 1C requirements without expanding scope into Phase 1D+.
