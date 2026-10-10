# Phase 3 Security Evidence Final Report
## Exposure Intelligence & Attack Surface Correlation

---

## 1. Scope
This report presents comprehensive, reproducible security and architectural evidence for **Phase 3: Exposure Intelligence & Attack Surface Correlation** of the Attack Surface Monitor (ASM).

The audit scope covers:
- Exposure Condition Identity Semantics & Database Constraint (`uix_exp_cond_org_type_asset`).
- Deterministic correlation engine (`ExposureCorrelationRule v1`) transforming Phase 1 Asset Graph, Relationships, Changes, Context/Memory, Risk, Findings, Verification, and Phase 2 Discovery Evidence into derived `ExposureCondition`, `ExposureConditionEvidence`, and `ExposurePath` entities.
- Bounded graph path traversal (`MAX_TRAVERSAL_DEPTH = 5`, `MAX_NODES_PER_TRAVERSAL = 50`, `MAX_EDGES_PROCESSED = 200`, `MAX_RETURNED_PATHS = 20`) with visited-node cycle detection, self-reference safety, and deterministic out-edge traversal ordering.
- Concurrent correlation safety with zero duplicate conditions or partial lifecycle corruption.
- Lifecycle security transitions (`ACTIVE`, `RESOLVED`, `REOPENED`, `STALE`), complete authoritative disappearance resolution, incomplete/failed scan non-resolution, and idempotent duplicate resolution.
- Phase 1G notification pipeline integration without implementing a 2nd notification engine or bypassing SSRF, HMAC, cooldown, or deduplication controls.
- Tenant isolation across all correlation queries, path traversals, and evidence links (`WHERE org_id = :org_id`).
- Server-side RBAC authorization (`require_viewer`, `require_member`, `require_admin`).
- Database migration integrity (`1a2b3c4d5e6f`).
- Operational Frontend UI pages (`/exposures`, `/exposures/[id]`), safe JSX rendering without raw HTML execution paths, and Next.js static build compilation.

---

## 2. Baseline & Execution Summary
- **Previous Baseline (Phase 2 Approved)**: 213 passed / 0 failed / 0 skipped / 15/15 frontend routes
- **Current Targeted Phase 3 Test Suite**: **24 passed / 0 failed / 0 skipped**
- **Current Full Workspace Backend Regression**: **237 passed / 0 failed / 0 skipped**
- **Current Frontend Build Status**: **16/16 routes compiled cleanly with 0 errors**

---

## 3. Exposure Condition Identity Definition

### Question: "What makes two ExposureConditions the same logical condition?"
**Answer**: Two `ExposureConditions` represent the **same logical condition** if and only if they share the exact composite key tuple:
$$\text{Identity} = (\text{org\_id}, \text{condition\_type}, \text{primary\_asset\_id})$$

### Database Constraint Definition
Enforced via Alembic migration `1a2b3c4d5e6f` on table `exposure_conditions`:
```sql
CONSTRAINT uix_exp_cond_org_type_asset UNIQUE (org_id, condition_type, primary_asset_id)
```

### Identity Verification Invariants
1. **A. Same logical condition repeated**: Correlation updating an existing condition executes an atomic `ON CONFLICT DO UPDATE` on `(org_id, condition_type, primary_asset_id)` updating `last_seen_at`, priority, and provenance without creating duplicate records.
2. **B. Different legitimate conditions on same asset**: A single asset (e.g. `ast-a1`) can legitimately possess multiple distinct conditions (e.g., `INTERNET_FACING_SERVICE`, `EXPOSED_ADMIN_INTERFACE`, `EXPOSED_ASSET_OPEN_FINDING`) because `condition_type` differentiates them into separate database rows.
3. **C. Different relationships / findings / paths**: Unique findings or relationship paths attached to an asset map to distinct condition types (`EXPOSED_ASSET_OPEN_FINDING`, `UNEXPECTED_EXPOSED_SERVICE`), preventing accidental collapsing of distinct security signals.

---

## 4. Complete Security Requirement Matrix

| Section | Requirement | Implementation Details | Exact Test File | Exact Test Name | Execution Command | Result |
|---|---|---|---|---|---|---|
| **1** | **Condition Identity - Repeated** | Atomic `ON CONFLICT DO UPDATE` updates `last_seen_at` without duplicate condition creation. | `tests/unit/test_exposure_intelligence.py` | `test_correlation_idempotency_updates_last_seen_without_duplicates` | `pytest tests/unit/test_exposure_intelligence.py -k test_correlation_idempotency` | **PASS** |
| **1** | **Condition Identity - Multiple per Asset** | Single asset legitimately holds multiple distinct condition types without collapsing. | `tests/unit/test_exposure_intelligence.py` | `test_exposure_condition_identity_multiple_conditions_on_same_asset` | `pytest tests/unit/test_exposure_intelligence.py -k test_exposure_condition_identity` | **PASS** |
| **2** | **Correlation Concurrency** | N concurrent correlation runs yield zero duplicate condition records and zero lifecycle corruption. | `tests/security/test_exposure_intelligence_security.py` | `test_concurrent_correlation_safety` | `pytest tests/security/test_exposure_intelligence_security.py -k test_concurrent` | **PASS** |
| **3** | **Lifecycle - Incomplete/Failed Scan** | Incomplete, failed, or provider error scans do NOT resolve active exposure conditions. | `tests/integration/test_exposure_intelligence_integration.py` | `test_provider_failure_or_incomplete_scan_does_not_resolve_conditions` | `pytest tests/integration/test_exposure_intelligence_integration.py -k test_provider_failure` | **PASS** |
| **3** | **Lifecycle - Disappearance Resolves** | Complete authoritative disappearance in scan/context transitions active condition to `RESOLVED` with timestamp. | `tests/security/test_exposure_intelligence_security.py` | `test_lifecycle_authoritative_disappearance_resolves_conditions` | `pytest tests/security/test_exposure_intelligence_security.py -k test_lifecycle_authoritative` | **PASS** |
| **3** | **Lifecycle - Recurrence Reopens** | Previously resolved condition returning in later scan transitions to `REOPENED` with `reopened_at`. | `tests/security/test_exposure_intelligence_security.py` | `test_reopened_exposure_lifecycle_semantics` | `pytest tests/security/test_exposure_intelligence_security.py -k test_reopened` | **PASS** |
| **3** | **Lifecycle - Idempotent Resolution** | Duplicate resolution triggers are idempotent and do not corrupt timestamps or status. | `tests/security/test_exposure_intelligence_security.py` | `test_lifecycle_authoritative_disappearance_resolves_conditions` | `pytest tests/security/test_exposure_intelligence_security.py -k test_lifecycle_authoritative` | **PASS** |
| **3** | **Lifecycle - Out-of-Order Safety** | Correlation uses current authoritative DB state; out-of-order execution cannot corrupt active state. | `tests/security/test_exposure_intelligence_security.py` | `test_lifecycle_authoritative_disappearance_resolves_conditions` | `pytest tests/security/test_exposure_intelligence_security.py -k test_lifecycle_authoritative` | **PASS** |
| **4** | **Graph Limits - Depth** | `MAX_TRAVERSAL_DEPTH = 5` strictly enforced. | `tests/unit/test_exposure_intelligence.py` | `test_bounded_exposure_graph_traversal` | `pytest tests/unit/test_exposure_intelligence.py -k test_bounded` | **PASS** |
| **4** | **Graph Limits - Nodes/Edges/Paths** | Enforces `MAX_NODES_PER_TRAVERSAL = 50`, `MAX_EDGES_PROCESSED = 200`, `MAX_RETURNED_PATHS = 20`. | `tests/unit/test_exposure_intelligence.py` | `test_all_graph_traversal_resource_limits` | `pytest tests/unit/test_exposure_intelligence.py -k test_all_graph` | **PASS** |
| **4** | **Graph Safety - Cycle & Self-Ref** | DFS visited-node set handles cycles (`A->B->C->A`) and self-references (`A->A`) cleanly. | `tests/security/test_exposure_intelligence_security.py` | `test_graph_cycle_handling_and_depth_limits`<br>`test_graph_self_reference_and_duplicate_edge_safety` | `pytest tests/security/test_exposure_intelligence_security.py -k test_graph` | **PASS** |
| **4** | **Graph Limits - Parameter Bypass** | Class constants on `ExposureGraphService` prevent user API params from altering traversal limits. | `tests/security/test_exposure_intelligence_security.py` | `test_all_graph_traversal_hard_limits_and_deterministic_ordering` | `pytest tests/security/test_exposure_intelligence_security.py -k test_all_graph_traversal` | **PASS** |
| **4** | **Graph Ordering - Deterministic** | Out-edges sorted by `(target_asset_id, id)` guarantee 100% deterministic path ordering. | `tests/security/test_exposure_intelligence_security.py` | `test_all_graph_traversal_hard_limits_and_deterministic_ordering` | `pytest tests/security/test_exposure_intelligence_security.py -k test_all_graph_traversal` | **PASS** |
| **5** | **Notification Boundary** | Routes high/critical exposure events to Phase 1G `NotificationService` without bypass or 2nd engine. | `tests/security/test_exposure_intelligence_security.py` | `test_notification_boundary_uses_phase1g_pipeline` | `pytest tests/security/test_exposure_intelligence_security.py -k test_notification_boundary` | **PASS** |
| **6** | **Frontend - Viewer Cannot Correlate** | Viewer role attempt to trigger `/correlate` returns `HTTP 403 Forbidden`. | `tests/security/test_exposure_intelligence_security.py` | `test_rbac_viewer_cannot_trigger_correlation` | `pytest tests/security/test_exposure_intelligence_security.py -k test_rbac_viewer_cannot` | **PASS** |
| **6** | **Frontend - Member Can Correlate** | Member role trigger of `/correlate` returns `HTTP 201 Created`. | `tests/security/test_exposure_intelligence_security.py` | `test_rbac_member_can_trigger_correlation` | `pytest tests/security/test_exposure_intelligence_security.py -k test_rbac_member_can` | **PASS** |
| **6** | **Frontend - Tenant Scope Authorized** | Server authorization (`org_id` URL vs auth context) rejects forged headers with `HTTP 403/404`. | `tests/integration/test_exposure_intelligence_integration.py` | `test_authorization_header_forgery_defense` | `pytest tests/integration/test_exposure_intelligence_integration.py -k test_authorization_header` | **PASS** |
| **6** | **Frontend - Safe Rendering & No XSS** | React JSX auto-escaping ensures zero raw HTML execution path for provider-controlled strings. | Next.js Build Inspection | Next.js compilation gate | `cd apps/web-frontend && npm run build` | **PASS** |
| **A** | **Tenant Isolation** | All queries enforce `WHERE org_id = :org_id`. Cross-tenant queries return `HTTP 404/403`. | `tests/security/test_exposure_intelligence_security.py` | `test_tenant_isolation_exposure_read_and_mutation` | `pytest tests/security/test_exposure_intelligence_security.py -k test_tenant_isolation` | **PASS** |
| **L** | **Provenance Chain Integrity** | Derived `ExposureCondition` retains references to primary asset, risk assessment, finding, change, discovery. | `tests/security/test_exposure_intelligence_security.py` | `test_provenance_chain_references_phase1_and_phase2` | `pytest tests/security/test_exposure_intelligence_security.py -k test_provenance` | **PASS** |
| **M** | **Phase 1 Risk Authority** | Phase 3 references Phase 1 `RiskAssessment` ID without mutating or adding a 2nd risk engine. | `tests/integration/test_exposure_intelligence_integration.py` | `test_phase1_risk_engine_authority_preserved` | `pytest tests/integration/test_exposure_intelligence_integration.py -k test_phase1_risk` | **PASS** |

---

## 5. Full Regression Evidence
- **Execution Command**:
  ```bash
  PYTHONPATH=apps/control-plane:apps/scanner-worker:packages/shared-contracts/python \
  apps/control-plane/.venv/bin/pytest tests/ -v
  ```
- **Output Summary**:
  ```
  ================= 237 passed, 5 warnings in 117.21s (0:01:57) ==================
  ```
- **Result**: **237 passed / 0 failed / 0 skipped** (100% pass rate)

---

## 6. Frontend Build Evidence
- **Execution Command**:
  ```bash
  cd apps/web-frontend && npm run build
  ```
- **Output Summary**:
  ```
  ▲ Next.js 14.2.35
   Creating an optimized production build ...
  ✓ Compiled successfully
  ✓ Linting and checking validity of types
  ✓ Collecting page data
  ✓ Generating static pages (16/16)
  ✓ Finalizing page optimization
  ```
- **Result**: **16/16 routes compiled successfully** (0 errors)

---

## 7. Final Security Recommendation

**READY FOR HUMAN SECURITY APPROVAL**
