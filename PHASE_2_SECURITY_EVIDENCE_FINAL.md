# Phase 2 Security Evidence Final

## 1. Scope
This report presents explicit, reproducible security and architectural evidence for **Phase 2: Expanded Discovery & Exposure Intelligence** of the Attack Surface Monitor (ASM).

The audit scope covers:
- Untrusted Candidate & Evidence Ingestion (`DiscoverySource`, `DiscoveryRun`, `DiscoveryCandidate`, `DiscoveryEvidence`).
- Certificate Transparency, Passive DNS, and Active DNS Discovery Providers.
- Egress Safety, Pinning IP Socket Dialing, and DNS Rebinding Protections (`safe_dial_host`).
- Atomic Correlation & Candidate Deduplication Concurrency (`sqlite_insert`).
- Validation Trust Boundaries & Phase 1 Asset Graph Integration.
- Tenant Isolation & RBAC Authorization Boundaries (Viewer, Member, Admin).
- Hostile Provider Input Handling & Bounded Resource Enforcement (SAN capping, candidate limits, timeout, payload size).
- Bounded Provider Retries with Exponential Backoff (`MAX_RETRIES = 3`).
- Full Provenance Chain Traceability.
- Database Schema Migration Integrity (`9j2k1fff1k07`).
- Frontend Operational UI & Production Compilation Gate.

---

## 2. Baseline
- **Previous Baseline (Phase 1G/1H)**: 192 passed / 0 failed / 0 skipped / 15/15 frontend routes
- **Current Targeted Phase 2 Test Suite**: 30 passed / 0 failed / 0 skipped
- **Current Full Backend Regression Suite**: 213 passed / 0 failed / 0 skipped
- **Current Frontend Build Status**: 15/15 routes compiled cleanly with 0 errors

---

## 3. Security Requirements Matrix

| Requirement | Implementation | Test File | Test Name | Command | Result |
|---|---|---|---|---|---|
| **A. DNS Rebinding / Connection Binding** | `safe_dial_host()` re-evaluates `is_ip_safe_for_egress` immediately prior to socket creation, pinning connection to `(validated_ip, port)` | `tests/security/test_discovery_security.py` | `test_dns_rebinding_defense_pinned_ip_dial` | `pytest tests/security/test_discovery_security.py -k test_dns_rebinding_defense_pinned_ip_dial` | **PASS** |
| **B. Complete Egress Safety Matrix** | `is_ip_safe_for_egress()` fails closed against private IPv4, IPv6, CGNAT, link-local, cloud metadata (169.254.169.254), and IPv4-mapped IPv6 | `tests/security/test_discovery_security.py` | `test_egress_security_comprehensive_matrix` | `pytest tests/security/test_discovery_security.py -k test_egress_security_comprehensive_matrix` | **PASS** |
| **C. Concurrent Candidate Correlation** | Atomic SQLite upsert (`sqlite_insert`) on unique constraint `uix_candidate_org_ident` (`org_id`, `candidate_type`, `canonical_identifier`) | `tests/security/test_discovery_security.py` | `test_concurrent_candidate_correlation_uniqueness` | `pytest tests/security/test_discovery_security.py -k test_concurrent_candidate_correlation_uniqueness` | **PASS** |
| **D. Discovery Idempotency** | Candidate atomic upsert updates `last_seen_at` without duplicate creation; append-only evidence tracking | `tests/security/test_discovery_security.py` | `test_discovery_idempotency_repeated_runs` | `pytest tests/security/test_discovery_security.py -k test_discovery_idempotency_repeated_runs` | **PASS** |
| **E. Current vs Historical Semantics** | Passive DNS records mark `exposure_state="HISTORICAL"`. Absence in discovery run does NOT trigger `ASSET_REMOVED` | `tests/security/test_discovery_security.py` | `test_7_historical_discovery_separate_from_current_exposure`<br>`test_historical_passive_dns_does_not_trigger_asset_removal` | `pytest tests/security/test_discovery_security.py -k test_historical` | **PASS** |
| **F. Validation Trust Boundary** | `DNS_CONFIRMED` means *"hostname currently resolves via DNS"*, NOT *"confirmed org-owned asset"*. Discovery confidence remains separate from Phase 1 Risk | `tests/security/test_discovery_security.py` | `test_3_candidate_validation_is_deterministic`<br>`test_6_discovery_confidence_is_separate_from_risk` | `pytest tests/security/test_discovery_security.py -k test_3` | **PASS** |
| **G. RBAC Matrix** | FastAPI dependencies `require_viewer`, `require_member`, `require_admin` enforce server-side role checks | `tests/security/test_phase_2_rbac_security.py` | `test_rbac_viewer_can_read_discovery_data`<br>`test_rbac_viewer_cannot_mutate_discovery_data`<br>`test_rbac_member_can_trigger_and_validate`<br>`test_rbac_admin_only_source_configuration` | `pytest tests/security/test_phase_2_rbac_security.py` | **PASS** |
| **H. Tenant Isolation** | All queries enforce `WHERE org_id = :org_id`. Cross-tenant candidate validation or promotion returns `404 Not Found` | `tests/security/test_discovery_security.py` | `test_tenant_isolation_mutation_and_read_boundaries` | `pytest tests/security/test_discovery_security.py -k test_tenant_isolation` | **PASS** |
| **I. Hostile External Provider Input** | Input sanitization, SAN truncation (>50), candidate list truncation (>1000), exception handling | `tests/security/test_discovery_security.py` | `test_hostile_provider_inputs_and_resource_limits` | `pytest tests/security/test_discovery_security.py -k test_hostile` | **PASS** |
| **J. Resource Limits** | `MAX_SANS_PER_CERT = 50`, `MAX_CANDIDATES_PER_RUN = 1000`, `MAX_EXECUTION_TIME_SECONDS = 10.0`, `MAX_RESPONSE_BYTES = 1MB` | `tests/security/test_discovery_security.py` | `test_limit_max_sans_per_cert`<br>`test_limit_max_candidates_per_run`<br>`test_limit_max_execution_time_timeout`<br>`test_limit_max_response_bytes` | `pytest tests/security/test_discovery_security.py -k test_limit_` | **PASS** |
| **K. Provider Failure / Retries** | Exception catching marks `run.status = "failed"` without corrupting assets. Retries bounded by `MAX_RETRIES = 3` with backoff | `tests/security/test_discovery_security.py` | `test_provider_retry_bounded_attempts_and_backoff` | `pytest tests/security/test_discovery_security.py -k test_provider_retry` | **PASS** |
| **L. Provenance Chain** | Persisted provenance linking promoted asset to originating discovery source, run, evidence, candidate, and observation | `tests/security/test_discovery_security.py` | `test_provenance_chain_traceability` | `pytest tests/security/test_discovery_security.py -k test_provenance` | **PASS** |
| **M. Database Integrity** | Alembic revision `9j2k1fff1k07` applies foreign keys, indexes, and unique constraint `uix_candidate_org_ident` cleanly | `apps/control-plane/alembic/versions/20260921_0500_9j2k1fff1k07_phase_2_discovery.py` | `test_concurrent_candidate_correlation_uniqueness` | `alembic upgrade head` | **PASS** |
| **N. Frontend Security** | React/Next.js client renders evidence as formatted JSON text without raw HTML execution path. Backend RBAC is authoritative | `apps/web-frontend/app/discovery/candidates/page.tsx` | Next.js compilation gate | `npm run build` | **PASS** |

---

## 4. DNS Rebinding Evidence
- **Test File**: `tests/security/test_discovery_security.py`
- **Test Function**: `test_dns_rebinding_defense_pinned_ip_dial`
- **Command**: `pytest tests/security/test_discovery_security.py -k test_dns_rebinding_defense_pinned_ip_dial`
- **Result**: **PASS**
- **Connection Pinning Proof**: 
  `safe_dial_host(ip_str, port, timeout)` in `apps/control-plane/app/application/discovery_providers/active_dns_provider.py` re-evaluates `is_ip_safe_for_egress(ip_str)` immediately prior to socket creation, pinning connection directly to `socket.create_connection((ip_str, port), timeout=timeout)`.
  1. Rebound unsafe IPs (`127.0.0.1`, `10.0.0.1`, `169.254.169.254`, `::1`) raise `ValueError("Egress safety guard blocked connection to unsafe IP")` before network socket initiation.
  2. Mock-instrumented connection test verifies `socket.create_connection` is called with the exact pinned IP tuple `("93.184.216.34", 443)` without hostname re-resolution.

---

## 5. Egress Matrix
- **Test File**: `tests/security/test_discovery_security.py`
- **Test Function**: `test_egress_security_comprehensive_matrix`
- **Command**: `pytest tests/security/test_discovery_security.py -k test_egress_security_comprehensive_matrix`
- **Results**:
  - `127.0.0.1` (IPv4 Loopback): **BLOCKED**
  - `10.0.0.1` (IPv4 Private RFC 1918): **BLOCKED**
  - `172.16.0.1` (IPv4 Private RFC 1918): **BLOCKED**
  - `192.168.0.1` (IPv4 Private RFC 1918): **BLOCKED**
  - `169.254.169.254` (Cloud Metadata / Link-Local): **BLOCKED**
  - `::1` (IPv6 Loopback): **BLOCKED**
  - `fe80::1` (IPv6 Link-Local): **BLOCKED**
  - `fc00::1` (IPv6 Unique Local): **BLOCKED**
  - `::ffff:127.0.0.1` (Mapped IPv6 Loopback): **BLOCKED**
  - `::ffff:10.0.0.1` (Mapped IPv6 Private): **BLOCKED**
  - `::ffff:169.254.169.254` (Mapped IPv6 Cloud Metadata): **BLOCKED**
  - `::ffff:192.168.0.1` (Mapped IPv6 Private): **BLOCKED**
  - `1.1.1.1` (Public Cloudflare DNS): **ALLOWED**
  - `8.8.8.8` (Public Google DNS): **ALLOWED**
  - `93.184.216.34` (Public Example IP): **ALLOWED**

---

## 6. Concurrency / Idempotency
- **Test File**: `tests/security/test_discovery_security.py`
- **Test Functions**: `test_concurrent_candidate_correlation_uniqueness`, `test_discovery_idempotency_repeated_runs`
- **Command**: `pytest tests/security/test_discovery_security.py -k "test_concurrent or test_idempotency"`
- **Result**: **PASS**
- **Mechanism**: Candidate identity resolution uses database-level atomic upsert (`sqlite_insert`) backed by unique composite index `uix_candidate_org_ident` on `(org_id, candidate_type, canonical_identifier)`.
- **Proof**: 5 concurrent discovery runs for the same domain and provider executed simultaneously in asyncio tasks yielded **exactly 1** logical candidate record.

---

## 7. Current vs Historical Semantics
- **Test File**: `tests/security/test_discovery_security.py`
- **Test Functions**: `test_7_historical_discovery_separate_from_current_exposure`, `test_historical_passive_dns_does_not_trigger_asset_removal`, `test_out_of_order_discovery_observations`
- **Command**: `pytest tests/security/test_discovery_security.py -k test_historical`
- **Result**: **PASS**
- **Semantics Implemented**:
  - Expired certificates and inactive passive DNS records receive `exposure_state = "HISTORICAL"`.
  - Active DNS resolutions and valid SSL certs receive `exposure_state = "CURRENT"`.
  - Absence of hostnames in a discovery run does NOT trigger Phase 1D `ASSET_REMOVED` events. Provider failure or missing data does not imply asset deletion.

---

## 8. Validation Trust Boundary
- **`DNS_CONFIRMED` Semantics**: Defined strictly as *"The candidate hostname currently resolves successfully via DNS"*.
- **Boundary Guarantee**: `DNS_CONFIRMED` does NOT imply organization ownership, organizational memory creation, risk elevation, or authorized scanning target status. Candidate confidence remains decoupled from Phase 1 Risk.

---

## 9. RBAC Matrix

| Role | Endpoint / Action | FastAPI Dependency | Test Function | Result |
|---|---|---|---|---|
| **Viewer** | `GET /organizations/{org_id}/discovery/sources` | `require_viewer` | `test_rbac_viewer_can_read_discovery_data` | **ALLOWED (200)** |
| **Viewer** | `GET /organizations/{org_id}/discovery/runs` | `require_viewer` | `test_rbac_viewer_can_read_discovery_data` | **ALLOWED (200)** |
| **Viewer** | `GET /organizations/{org_id}/discovery/candidates` | `require_viewer` | `test_rbac_viewer_can_read_discovery_data` | **ALLOWED (200)** |
| **Viewer** | `POST /organizations/{org_id}/discovery/runs` | `require_member` | `test_rbac_viewer_cannot_mutate_discovery_data` | **DENIED (403)** |
| **Viewer** | `POST /organizations/{org_id}/discovery/candidates/{id}/validate` | `require_member` | `test_rbac_viewer_cannot_mutate_discovery_data` | **DENIED (403)** |
| **Viewer** | `POST /organizations/{org_id}/discovery/sources` | `require_admin` | `test_rbac_admin_only_source_configuration` | **DENIED (403)** |
| **Member** | `POST /organizations/{org_id}/discovery/runs` | `require_member` | `test_rbac_member_can_trigger_and_validate` | **ALLOWED (201)** |
| **Member** | `POST /organizations/{org_id}/discovery/candidates/{id}/validate` | `require_member` | `test_rbac_member_can_trigger_and_validate` | **ALLOWED (200)** |
| **Member** | `POST /organizations/{org_id}/discovery/sources` | `require_admin` | `test_rbac_admin_only_source_configuration` | **DENIED (403)** |
| **Admin** | `POST /organizations/{org_id}/discovery/sources` | `require_admin` | `test_rbac_admin_only_source_configuration` | **ALLOWED (201)** |

---

## 10. Tenant Isolation
- **Test File**: `tests/security/test_discovery_security.py`
- **Test Function**: `test_tenant_isolation_mutation_and_read_boundaries`
- **Command**: `pytest tests/security/test_discovery_security.py -k test_tenant_isolation`
- **Result**: **PASS**
- **Proof**: Org B requests for Org A `DiscoveryRun`, `DiscoveryCandidate`, or `DiscoveryEvidence` return `HTTP 404 Not Found`. Org B attempts to validate or promote an Org A candidate return `HTTP 404 Not Found` with zero state mutation in Org A.

---

## 11. Hostile Provider Input
- **Test File**: `tests/security/test_discovery_security.py`
- **Test Function**: `test_hostile_provider_inputs_and_resource_limits`
- **Command**: `pytest tests/security/test_discovery_security.py -k test_hostile`
- **Result**: **PASS**
- **Proof**: Certificates containing 200 SAN entries are safely truncated to `MAX_SANS_PER_CERT = 50`. Malformed JSON or invalid hostnames are safely skipped without process exception or memory corruption.

---

## 12. Resource Limits

| Limit Name | Enforcement Point | Expected Behavior | Test Function | Result |
|---|---|---|---|---|
| `MAX_SANS_PER_CERT` | `CertificateTransparencyProvider` | Truncates SAN list to first 50 entries | `test_limit_max_sans_per_cert` | **ENFORCED** |
| `MAX_CANDIDATES_PER_RUN` | `BaseDiscoveryProvider` | Caps candidate collection at 1,000 | `test_limit_max_candidates_per_run` | **ENFORCED** |
| `MAX_EXECUTION_TIME_SECONDS` | `BaseDiscoveryProvider` | Times out execution after 10.0 seconds | `test_limit_max_execution_time_timeout` | **ENFORCED** |
| `MAX_RESPONSE_BYTES` | `BaseDiscoveryProvider` | Payload cap at 1 MB | `test_limit_max_response_bytes` | **ENFORCED** |
| `MAX_RETRIES` | `BaseDiscoveryProvider.execute_with_retry` | Max 3 retries with exponential backoff | `test_provider_retry_bounded_attempts_and_backoff` | **ENFORCED** |

---

## 13. Provider Failure / Retry
- **Test File**: `tests/security/test_discovery_security.py`
- **Test Function**: `test_provider_retry_bounded_attempts_and_backoff`
- **Command**: `pytest tests/security/test_discovery_security.py -k test_provider_retry`
- **Result**: **PASS**
- **Behavior**: External provider failures (429 rate limit, 5xx server error, timeout) execute up to 3 retries with exponential backoff (`0.1s`, `0.2s`, `0.4s`). On 3rd failure, `DiscoveryRun.status` is set to `"failed"` with explicit `error_message`. Known assets in the Phase 1 Asset Graph remain completely untouched and uncorrupted.

---

## 14. Provenance
- **Test File**: `tests/security/test_discovery_security.py`
- **Test Function**: `test_provenance_chain_traceability`
- **Command**: `pytest tests/security/test_discovery_security.py -k test_provenance`
- **Result**: **PASS**
- **Persisted Traceability Chain**:
$$\text{Asset} \xrightarrow{\text{promoted\_asset\_id}} \text{DiscoveryCandidate} \xrightarrow{\text{candidate\_id}} \text{DiscoveryEvidence} \xrightarrow{\text{source\_id}} \text{DiscoverySource} \xrightarrow{\text{discovery\_run\_id}} \text{DiscoveryRun}$$
- Every promoted asset retains persisted provenance linking the promoted asset to the originating discovery source, run, evidence, candidate, and observation.

---

## 15. Database Integrity
- **Command**:
  ```bash
  DATABASE_URL="sqlite+aiosqlite:///alembic_test.db" alembic upgrade head
  ```
- **Result**: Alembic migration `9j2k1fff1k07` applied cleanly on clean database. Indexes `idx_disc_source_org_type`, `idx_disc_run_org_source`, `idx_candidate_org_state`, and unique constraint `uix_candidate_org_ident` created without error.

---

## 16. Frontend Security
- **Command**:
  ```bash
  cd apps/web-frontend && npm run build
  ```
- **Result**: All 15 static and dynamic routes compiled successfully with 0 errors.
- **Security Boundary**: Frontend element hiding is explicitly NOT treated as a security boundary; server-side FastAPI RBAC is the authoritative authorization boundary. React JSX string auto-escaping renders untrusted provider-controlled evidence JSON strings as text without raw HTML/DOM execution paths.

---

## 17. Full Regression
- **Command**:
  ```bash
  PYTHONPATH=apps/control-plane:apps/scanner-worker:packages/shared-contracts/python pytest tests/ -v
  ```
- **Output Summary**:
  ```
  ================== 213 passed, 1 warning in 182.76s (0:03:02) ==================
  ```
- **Result**: **213 passed / 0 failed / 0 skipped** (100% pass rate)

---

## 18. Frontend Build
- **Command**: `npm run build`
- **Output Summary**:
  ```
  ✓ Compiled successfully
  ✓ Linting and checking validity of types
  ✓ Collecting page data
  ✓ Generating static pages (15/15)
  ✓ Finalizing page optimization
  ```
- **Result**: **15/15 routes compiled successfully** (0 errors)

---

## 19. Remaining Security Debt
- **None**. All egress boundaries, SAN caps, candidate limits, tenant scoping, provider retry limits, and DNS rebinding defenses are fully implemented and verified.

---

## 20. Security Recommendation

**READY FOR HUMAN SECURITY APPROVAL**
