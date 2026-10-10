# Attack Surface Monitor — Implementation Architecture & Repository Design Document

> **Status:** DRAFT — Pending Human Review (NO-CODE PHASE J)
> **Last Updated:** 2026-08-27
> **Parent Documents:** ProductConstitution.md, PRD.md, Phases.md, Architecture.md, TechSpec.md, Schema.md, SecurityChecklist.md
> **Document Type:** Comprehensive Implementation Architecture & Repository Design Specification

---

## 1. Proposed Repository Structure

The proposed codebase architecture uses a **modular monolith monorepo** structure. It separates the control plane application, isolated scanner worker pool, shared contracts, and documentation, while keeping domain modules strictly decoupled inside the control plane.

> **IMPORTANT:** This directory tree is a DOCUMENTED PROPOSAL ONLY. No physical directories or code files are created during this phase.

```
attack-surface-monitor/
├── apps/
│   ├── control-plane/             # FastAPI Control Plane Application
│   │   ├── app/
│   │   │   ├── api/               # API Controllers (REST Endpoints)
│   │   │   │   └── v1/            # API v1 Versioned Route Handlers
│   │   │   ├── application/       # Use Cases, Application Services & Workflows
│   │   │   ├── domain/            # Pure Domain Models, Business Rules, Value Objects
│   │   │   │   ├── identity/
│   │   │   │   ├── organizations/
│   │   │   │   ├── domains/
│   │   │   │   ├── assets/
│   │   │   │   ├── observations/
│   │   │   │   ├── changes/
│   │   │   │   ├── context/
│   │   │   │   ├── risk/
│   │   │   │   ├── findings/
│   │   │   │   ├── decisions/
│   │   │   │   ├── memory/
│   │   │   │   └── notifications/
│   │   │   ├── infrastructure/    # Database Repositories, Redis, S3, Adapters
│   │   │   │   ├── db/            # SQLAlchemy ORM Models & Alembic Migrations
│   │   │   │   ├── cache/         # Redis Cache & Lock Providers
│   │   │   │   ├── storage/       # S3 Evidence Storage Providers
│   │   │   │   ├── queue/         # Queue Producers & Job Dispatchers
│   │   │   │   └── auth/          # AuthAdapter Implementations
│   │   │   └── main.py            # FastAPI Entry Point & Middleware Assembly
│   │   └── pyproject.toml
│   │
│   ├── web-frontend/              # Next.js App Router Application
│   │   ├── app/                   # App Router Pages & Layouts
│   │   ├── components/            # UI Components (Radix + Custom CSS Modules)
│   │   ├── lib/                   # API Client, Auth Hooks, Formatting
│   │   ├── styles/                # CSS Tokens, Global Styles (Black & White Theme)
│   │   └── package.json
│   │
│   └── scanner-worker/            # Isolated Discovery Worker Application
│       ├── worker/
│       │   ├── engine/            # Discovery Pipeline (Subdomain, DNS, Port, Cert, Tech)
│       │   ├── safety/            # Egress Safety, DNS TOCTOU Guard, Redirect Checker
│       │   └── runner.py          # Worker Loop (Dequeues jobs from Redis, executes, returns)
│       └── pyproject.toml
│
├── packages/
│   └── shared-contracts/          # Shared Pydantic Schemas, Constants, Event Definitions
│       └── python/
│           ├── events.py          # Queue Event Payload Definitions
│           ├── enums.py           # Shared Enums (Severity, AssetType, FindingStatus)
│           └── schemas.py         # Shared Request/Response DTOs
│
├── tests/
│   ├── unit/                      # Fast Pure Domain & Utility Unit Tests
│   ├── integration/               # API & Database Integration Tests
│   ├── security/                  # Auth, RBAC, Tenant Isolation & SSRF Security Tests
│   ├── worker/                    # Scanner Worker & Egress Safety Tests
│   └── e2e/                       # Playwright End-to-End User Flow Tests
│
├── infrastructure/
│   ├── docker/                    # Docker Compose Local Dev Specifications
│   └── deployments/               # Staging & Production Container Specifications
│
└── docs/                          # Source Documentation Set (13 Mandatory Docs)
```

---

## 2. Directory Policies & Boundaries

| Directory | Purpose | Owner Team | Allowed Content | Forbidden Content | Allowed Dependencies |
|---|---|---|---|---|---|
| `apps/control-plane` | Business logic, REST API, orchestration, data persistence | Backend / Core | FastAPI routes, domain models, use cases, DB repositories, queue producers | Direct scanner execution code, raw network socket scanners | `packages/shared-contracts` |
| `apps/web-frontend` | User interface dashboard & operations UI | Frontend | React components, Next.js pages, CSS modules, API fetch client | Business logic, direct DB access, scanner code | `packages/shared-contracts` (via API schemas) |
| `apps/scanner-worker` | Hostile target network discovery worker | Security / Infra | Port scanners, DNS lookup wrappers, TLS parsers, egress safety checks | Control plane DB access, secret manager keys, user auth logic | `packages/shared-contracts` |
| `packages/shared-contracts` | Shared data contracts & DTO interfaces ONLY | Core / Shared | Pydantic DTOs, event payload schemas, shared enums, serialization contracts, versioned message interfaces | Business logic, DB models, repositories, service calls, auth logic, risk logic, scanner code | Pure Python standard library + Pydantic (Dependency-light, framework-independent) |
| `tests/security` | Automated security assertion suite | Security | SSRF tests, RBAC bypass tests, tenant isolation assertions | Production secrets, external live network targets | All apps & packages |

### 2.1 Shared Contracts Strict Boundary Rules

`packages/shared-contracts` is strictly a **Data Contracts Only** package:

- **ALLOWED:**
  - Data Transfer Objects (DTOs) for API request/response validation
  - Event payload schemas for Redis queue messages (`schema_version: "1.0"`)
  - Shared domain enums (`Severity`, `AssetType`, `FindingStatus`, `ChangeType`, `Environment`)
  - JSON serialization / deserialization helpers
- **FORBIDDEN (STRICTLY PROHIBITED):**
  - Business logic, domain rules, or risk calculation functions
  - SQLAlchemy ORM models or database repository interfaces
  - API route handlers or controller logic
  - Authentication functions, token generation, or RBAC permission checks
  - Scanner worker code, socket routines, or DNS resolvers
- **DEPENDENCY CONSTRAINTS:**
  - Must remain framework-independent (no FastAPI, SQLAlchemy, Next.js, or Redis runtime dependencies)
  - Must depend ONLY on standard Python library and Pydantic for validation

---

## 3. Backend Module Architecture

The control plane backend is organized as a **modular monolith** with clean layer boundaries:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        API LAYER (Controllers)                         │
│     FastAPI Routers, Request Validation, Response Encoding             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Calls Use Cases
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER (Use Cases)                       │
│     Workflow Orchestration, Transaction Boundaries, Security Checks     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Uses Domain Models
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        DOMAIN LAYER (Pure Core)                        │
│     Business Rules, Value Objects, Risk Scoring, Memory Logic          │
└───────────────────────────────────▲────────────────────────────────────┘
                                    │ Implements Repositories / Interfaces
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                    INFRASTRUCTURE LAYER (Adapters)                     │
│     SQLAlchemy Repositories, Redis Cache, S3 Storage, AuthAdapters     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Module Responsibility Matrix

| Module Name | Primary Responsibility | Owns Entities | Reads | Writes | Key Dependencies | Forbidden Dependencies | Security Boundary | Future Extraction |
|---|---|---|---|---|---|---|---|---|
| **Identity & Auth** | User registration, authentication, sessions, MFA | `users`, `sessions` | `users`, `sessions` | `users`, `sessions` | `passlib`, `pyotp` | Asset/Finding models | High (Auth boundary) | Identity Service |
| **Organizations** | Tenants, memberships, RBAC rules | `organizations`, `memberships` | `organizations`, `memberships`, `users` | `organizations`, `memberships` | Auth Module | Discovery code | High (Tenant boundary) | Org Service |
| **Domains** | Seed domain registration & TXT ownership verification | `domains` | `domains` | `domains` | `dnspython` | Scanner execution | High (Target Auth) | Domain Service |
| **Assets & Graph** | Asset inventory, resolution, relationship mapping | `assets`, `asset_relationships` | `assets`, `asset_relationships`, `observations` | `assets`, `asset_relationships` | Organizations | Direct Scanner socket | Medium | Asset Service |
| **Observations** | Raw scan data ingestion and provenance tracking | `observations` | `observations`, `scans` | `observations` | S3 Storage | Business Decision logic | High (Hostile data) | Ingestion Service |
| **Scan Orchestrator**| Scheduling scan jobs & dispatching to queue | `scans` | `domains`, `assets`, `scans` | `scans` | Redis Queue | Control plane DB access in worker | High (Worker interface)| Scheduler Service |
| **Change Engine** | Scan-over-scan diffing & change detection | `changes` | `observations`, `assets`, `changes` | `changes` | Observations Module | User UI logic | Medium | Analytics Service |
| **Context & Memory**| Ownership, environment, criticality, expected state | `expected_states`, `organization_rules` | `assets`, `expected_states`, `decisions` | `expected_states`, `organization_rules` | Assets Module | Scanner code | High (Decision memory)| Context Service |
| **Risk Engine** | Contextualized risk scoring calculation | None (Computes score) | `assets`, `changes`, `expected_states`, `decisions` | Updates `findings.contextual_risk_score` | Context Module | Raw scanner scores | Medium | Risk Service |
| **Findings & Evidence**| Finding lifecycle and traceable evidence chains | `findings`, `evidence` | `findings`, `evidence`, `observations` | `findings`, `evidence` | Observations, S3 | Scanner code | High (Auditability) | Finding Service |
| **Decisions** | Human risk acceptance, false positives, expected marking | `decisions` | `findings`, `assets`, `decisions` | `decisions` | Audit Module | Unassisted AI scripts | High (Human authority)| Governance Service |
| **Verification** | Re-scanning & confirming remediation completion | `verifications` | `findings`, `verifications` | `verifications` | Scan Orchestrator | Direct scanner code | High (Validation) | Verification Service |
| **Notifications** | Change-aware alert dispatch (In-app, Email) | `notifications` | `notifications`, `changes`, `findings` | `notifications` | Mail Provider | Third-party ad trackers | Medium | Alerting Service |
| **Audit** | Immutable security event logging | `audit_events` | `audit_events` | `audit_events` | DB Adapter | UPDATE/DELETE queries | High (Immutable) | Audit Service |

---

## 5. Data Ownership Matrix

| Entity | Owner Module | Allowed Readers | Allowed Writers | Tenant Scoped (`org_id`)? | Audit Required? | Retention Strategy |
|---|---|---|---|---|---|---|
| `organizations` | Organizations | All Control Plane Modules | Organizations Module | No (Is Root) | Yes | Indefinite |
| `users` | Identity & Auth | All Control Plane Modules | Identity & Auth | No (Global user) | Yes | Indefinite |
| `memberships` | Organizations | All Control Plane Modules | Organizations Module | Yes (`org_id`) | Yes | Indefinite |
| `sessions` | Identity & Auth | Identity & Auth | Identity & Auth | Yes (`org_id`) | Yes | Hard delete on expiry + 7 days |
| `domains` | Domains | Domains, Scan Orchestrator | Domains Module | Yes (`org_id`) | Yes | Indefinite (Soft delete) |
| `assets` | Assets & Graph | All Control Plane Modules | Assets Module | Yes (`org_id`) | Yes | Indefinite (Soft delete) |
| `asset_relationships`| Assets & Graph | Assets, Risk, UI | Assets Module | Yes (`org_id`) | No | Historical status flag |
| `scans` | Scan Orchestrator | Orchestrator, Worker Ingestion | Orchestrator Module | Yes (`org_id`) | Yes | 1 Year |
| `observations` | Observations | Change Engine, Evidence | Observations Module | Yes (`org_id`) | No | 90 Days raw -> Rollup archive |
| `changes` | Change Engine | Risk, Notifications, UI | Change Engine Module | Yes (`org_id`) | No | Indefinite |
| `findings` | Findings & Evidence| Risk, Decisions, UI | Findings Module | Yes (`org_id`) | Yes | Indefinite |
| `evidence` | Findings & Evidence| Findings, Audit, UI | Findings Module | Yes (`org_id`) | No | Same as parent finding |
| `expected_states` | Context & Memory | Risk, Change Engine, UI | Context & Memory | Yes (`org_id`) | Yes | Indefinite |
| `decisions` | Decisions | Risk, Change Engine, UI | Decisions Module | Yes (`org_id`) | Yes | Indefinite (Append-only) |
| `verifications` | Verification | Verification, UI | Verification Module | Yes (`org_id`) | Yes | Indefinite |
| `notifications` | Notifications | Notifications, UI | Notifications Module | Yes (`org_id`) | No | 90 Days |
| `audit_events` | Audit | Audit, Admin UI | Audit Module | Yes (`org_id` nullable) | Yes | Minimum 1 Year (Immutable) |

---

## 6. Core Data Pipeline Architecture

```
1. SCAN SCHEDULING (Scan Orchestrator)
   - Checks domain.status == 'verified'
   - Generates scan job payload with domain_id, org_id, target_domain
   - Enqueues job to Redis `scan_jobs` queue
        │
        ▼
2. WORKER EXECUTION (Scanner Worker Pool)
   - Dequeues job from Redis
   - Enforces Dual-Layer Validation (Target Auth check + Destination Safety check)
   - Executes pipeline: Subdomain Enum → DNS Resolution → Port Scan → Cert Extraction → Tech ID
   - Applies DNS TOCTOU Guard & Redirect Hop Validation
   - Returns raw observation payload to Redis `scan_results` queue
        │
        ▼
3. OBSERVATION INGESTION (Observations Module)
   - Dequeues raw result payload from Redis
   - Validates JSON schema & sanitizes input
   - Persists raw snapshots into `observations` table (and large artifacts to S3)
        │
        ▼
4. ASSET & RELATIONSHIP RESOLUTION (Assets Module)
   - Extracts subdomains, IPs, services, certificates from observations
   - Merges & deduplicates entities into `assets` table
   - Updates directional links in `asset_relationships` table
        │
        ▼
5. CHANGE DETECTION (Change Engine)
   - Fetches previous observation snapshot for affected assets
   - Performs scan-over-scan diffing
   - Emits `changes` records (e.g. `new_service`, `cert_changed`, `ip_changed`)
        │
        ▼
6. CONTEXT & EXPECTATION MATCHING (Context Module)
   - Checks asset environment, ownership, criticality, and `expected_states`
   - Evaluates whether change violates expected state (e.g. unexpected open port)
        │
        ▼
7. RISK CALCULATION & FINDINGS GENERATION (Risk & Findings Modules)
   - Computes `contextual_risk_score` = f(severity, criticality, environment, expected_state, decision_status)
   - Creates or updates `findings` records with linked `evidence` chains
        │
        ▼
8. DECISION MEMORY EVALUATION (Decisions Module)
   - Checks active `decisions` (accepted risk, false positive, expected state)
   - If active unexpired decision exists: adjusts finding status / suppresses notification
   - If no decision exists: leaves finding as `new`
        │
        ▼
9. NOTIFICATION DISPATCH (Notifications Module)
   - Filters changes & findings against organization alert rules
   - Dispatches in-app notifications and queues digest emails
        │
        ▼
10. REMEDIATION & VERIFICATION (Verification Module)
    - User clicks "Verify Remediation" on finding
    - Orchestrator enqueues single-target verification job to Redis
    - Worker executes target check -> Control plane confirms port closed -> Updates finding status to `verified`
```

---

## 7. Observation vs. Business Decision & Scanner Trust Boundary

### 7.1 Scanner Result Trust Pipeline

Scanner output MUST ALWAYS be treated as **UNTRUSTED INPUT**, even when generated by our own scanner worker infrastructure, because workers process arbitrary responses from hostile Internet hosts.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   UNTRUSTED SCANNER OUTPUT INGESTION                   │
├────────────────────────────────────────────────────────────────────────┤
│ 1. UNTRUSTED SCANNER OUTPUT                                            │
│    - Raw banner / DNS / TLS response payload produced by worker        │
├────────────────────────────────────────────────────────────────────────┤
│ 2. AUTHENTICATED QUEUE MESSAGE                                         │
│    - Payload signed with worker HMAC secret & enqueued to Redis        │
│    - Control plane verifies HMAC signature & timestamp window          │
├────────────────────────────────────────────────────────────────────────┤
│ 3. PAYLOAD SIZE VALIDATION                                             │
│    - Hard cap check: Maximum 50 MB per queue message payload           │
│    - Abort ingestion immediately if payload size exceeds limit         │
├────────────────────────────────────────────────────────────────────────┤
│ 4. MESSAGE / SCHEMA VALIDATION                                         │
│    - Enforce Pydantic schema validation (`schema_version: "1.0"`)     │
│    - Reject malformed, truncated, or un-versioned payloads             │
├────────────────────────────────────────────────────────────────────────┤
│ 5. SANITIZATION & NORMALIZATION                                        │
│    - Strip control characters (`\x00`, `\r`) from text banners         │
│    - Escape/normalize HTML and raw response payloads                   │
│    - Deduplicate repeated headers                                      │
├────────────────────────────────────────────────────────────────────────┤
│ 6. PROVENANCE ASSIGNMENT                                               │
│    - Inject immutable provenance metadata (`scan_id`, `worker_id`,     │
│      `observed_at`, `source_ip`, `target_domain`)                      │
├────────────────────────────────────────────────────────────────────────┤
│ 7. DOMAIN PROCESSING                                                   │
│    - Pass sanitized payload to Asset Resolution & Change Engine        │
├────────────────────────────────────────────────────────────────────────┤
│ 8. PERSISTENCE                                                         │
│    - Store raw snapshot in `observations` table (or S3 for large blobs)│
└────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Ingestion Security Controls

| Concern | Control | Failure Behavior |
|---|---|---|
| **Queue Authentication** | Worker signs payload with shared HMAC secret + timestamp | Reject payload, log security alert, increment `auth_failures` |
| **Payload Size Limit** | 50 MB hard cap per Redis queue message | Reject message immediately, move to `result_dlq` |
| **Schema Versioning** | Payload MUST contain explicit `schema_version: "1.0"` | Reject un-versioned message, move to `result_dlq` |
| **Malformed Messages** | Pydantic schema validation at control plane boundary | Log validation errors, discard invalid fields, DLQ if invalid root |
| **Replay / Idempotency**| Unique `scan_id` + `job_nonce` checked against Redis key store | Ignore duplicate execution result, log idempotent drop |
| **Provenance Integrity**| Ingestor injects immutable `scan_id`, `worker_id`, `timestamp` | Rejection if missing required provenance metadata |
| **Dead-Letter Policy** | Failed payloads move to `result_dlq` after 3 retries | Alert ops team, retain failed message payload for 7 days |

---

## 8. Organizational Memory Architecture & Scoping Rules

Memory is governed by 10 formal concepts and explicit inheritance boundaries:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MEMORY INHERITANCE RULES                        │
├───────────────────────┬────────────────────┬───────────────────────────┤
│ Scope Level           │ Applies To         │ Excluded From             │
├───────────────────────┼────────────────────┼───────────────────────────┤
│ Organization          │ Org-wide policies  │ Specific asset exceptions │
│ Domain (`domain_id`)  │ Subdomains of host │ Unrelated domains         │
│ Asset (`asset_id`)    │ Target asset only  │ Other assets / IP neighbors│
│ Service (`port`)      │ Specific port only │ Other ports on same asset │
│ Finding (`finding_id`)│ Exact finding ID   │ Similar findings elsewhere│
└───────────────────────┴────────────────────┴───────────────────────────┘
```

### Invariants:
1. **Explicit Scope Matching:** A human decision marking `port 8443` as expected on `staging.example.com` creates an entry in `expected_states` scoped to `(asset_id, port=8443)`. It DOES NOT apply to `prod.example.com` or `staging.example.com:22`.
2. **No Automatic Wildcard Rules:** Human decisions on single assets NEVER auto-generate global or wildcard pattern rules. Wildcard rules require explicit creation in `organization_rules` by an Admin.
3. **Audit Provenance:** Every decision record links to the exact `actor_id`, `timestamp`, `reason`, and `evidence_snapshot`.

---

## 9. Asset Graph Architecture

### Nodes & Edge Types

- **Nodes:** `Domain`, `Subdomain`, `IPAddress`, `Service`, `Certificate`.
- **Edges (`relationship_type`):**
  - `Domain` ──[`has_subdomain`]──► `Subdomain`
  - `Subdomain` ──[`resolves_to`]──► `IPAddress`
  - `Subdomain` ──[`cname_to`]──► `Subdomain`
  - `IPAddress` ──[`runs_service`]──► `Service`
  - `Service` ──[`presents_cert`]──► `Certificate`

### Graph Invariants & Provenance
- Every edge includes `first_seen_at`, `last_seen_at`, `status` (`active` vs `historical`), and a reference to the `observation_id` that proved the connection.
- No edge exists without backing observation evidence. Graph relationships are deterministic projections of verified observations.

---

## 10. API Architecture & Boundary Map

### API Boundary Specifications

| API Group | Endpoint Prefix | Primary Role | Authorization Required | Tenant Isolation (`org_id`) | Audit Event Triggered? |
|---|---|---|---|---|---|
| **Auth** | `/api/v1/auth` | User login, MFA, sessions | Public / Authenticated | N/A (Global / User context) | Yes (Login/MFA/Logout) |
| **Organizations** | `/api/v1/organizations` | Org creation, member management | Authenticated (`owner`/`admin`) | Enforced | Yes (Member changes) |
| **Domains** | `/api/v1/organizations/{org_id}/domains` | Domain onboarding & TXT verify | Authenticated (`admin`+) | Enforced (`org_id` path match) | Yes (Domain add/verify) |
| **Assets** | `/api/v1/organizations/{org_id}/assets` | Asset explorer, context editing | Authenticated (`member`+) | Enforced | Yes (Context edits) |
| **Changes** | `/api/v1/organizations/{org_id}/changes` | Change feed query | Authenticated (`viewer`+) | Enforced | No |
| **Findings** | `/api/v1/organizations/{org_id}/findings` | Triage & finding detail | Authenticated (`viewer`+) | Enforced | No |
| **Decisions** | `/api/v1/organizations/{org_id}/decisions` | Risk accept, false positive | Authenticated (`member`+) | Enforced | Yes (Decision created) |
| **Verifications** | `/api/v1/organizations/{org_id}/verifications` | Trigger re-check | Authenticated (`member`+) | Enforced | Yes (Verification requested) |
| **Notifications** | `/api/v1/organizations/{org_id}/notifications` | Notification feed & mark-read | Authenticated (`viewer`+) | Enforced | No |
| **Audit Logs** | `/api/v1/organizations/{org_id}/audit-log` | Audit history view | Authenticated (`admin`+) | Enforced | No |

---

## 11. Queue Contract & Job Architecture

Asynchronous background jobs operate over Redis using `arq`.

| Job Name | Producer Module | Consumer Module | Payload Schema | Idempotency Key | Max Retries | Hard Timeout | Dead Letter Policy |
|---|---|---|---|---|---|---|---|
| `scan.execute_domain` | Scan Orchestrator | Scanner Worker | `{scan_id, org_id, domain_name}` | `scan:{scan_id}` | 2 | 5 mins | Move to `scan_dlq`, mark scan `failed` |
| `scan.process_results` | Scanner Worker | Observations Module | `{scan_id, org_id, raw_results_s3_key}` | `result:{scan_id}` | 3 | 2 mins | Move to `result_dlq`, alert ops |
| `asset.resolve_graph` | Observations Module | Assets Module | `{scan_id, org_id}` | `graph:{scan_id}` | 3 | 3 mins | Move to `graph_dlq` |
| `change.detect_diff` | Assets Module | Change Engine | `{scan_id, org_id}` | `diff:{scan_id}` | 3 | 2 mins | Move to `diff_dlq` |
| `notification.dispatch`| Risk / Findings | Notifications Module | `{org_id, notification_id}` | `notif:{notification_id}` | 5 | 1 min | Log failure, retain notification record |
| `scan.verify_finding` | Verification Module| Scanner Worker | `{verification_id, org_id, target, port}` | `verify:{verification_id}` | 1 | 2 mins | Mark verification `failed` |

---

## 12. Scanner Worker Architecture & Security Dual-Boundary

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SCANNER WORKER CONTAINER                        │
├────────────────────────────────────────────────────────────────────────┤
│ 1. TARGET AUTHORIZATION GATEWAY                                        │
│    - Verifies domain ownership status == 'verified' in job payload     │
├────────────────────────────────────────────────────────────────────────┤
│ 2. NETWORK DESTINATION SAFETY GATEWAY                                  │
│    - Resolves DNS hostname to IP address                               │
│    - Validates IP against Denylist (RFC 1918/4193, 127.0.0.1, 169.254.x)  │
│    - ABORTS if IP is private or link-local                             │
├────────────────────────────────────────────────────────────────────────┤
│ 3. SOCKET-LEVEL TOCTOU GUARD                                           │
│    - Passes validated IP directly to TCP connect socket API            │
│    - Hostname passed ONLY in HTTP Host header & TLS SNI extension      │
├────────────────────────────────────────────────────────────────────────┤
│ 4. REDIRECT HOP VALIDATOR                                              │
│    - Intercepts 301/302/307 redirects                                  │
│    - Resolves & validates EVERY intermediate redirect IP (max 5 hops)  │
│    - ABORTS redirect if hop target is private/internal                 │
├────────────────────────────────────────────────────────────────────────┤
│ 5. STREAMING RESOURCE CAP                                              │
│    - Enforces 10 MB maximum body size limit                            │
│    - Enforces 20:1 maximum streaming decompression ratio (zip bomb)    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 13. Security & Trust Boundaries Map

```
[ UNTRUSTED INTERNET ] ──(Raw Responses)──► [ SCANNER WORKER (Container Sandbox) ]
                                                        │
                                          (Sanitized JSON Payload)
                                                        ▼
[ CONTROL PLANE API ] ◄──(HTTPS API)────── [ REDIS JOB QUEUE ]
         │
  (Scoped Queries)
         ▼
[ POSTGRESQL DB ] ◄──(TLS)─────────────── [ S3 EVIDENCE STORE ]
```

- **Control Plane DB Protection:** Scanner workers have ZERO credentials to PostgreSQL or S3. Workers write output payloads exclusively to Redis result queues.
- **API Defense:** Control plane API validates and sanitizes all worker outputs before inserting into database tables.

---

## 14. Authentication & Authorization Architecture

### AuthAdapter Pattern

To allow seamless Option B/C (SAML/SSO or Auth0) integration in V2 without changing business logic, authentication is wrapped behind an abstract interface:

```python
class AuthAdapter(ABC):
    @abstractmethod
    async def authenticate_credentials(self, email: str, password: str) -> UserSession: ...
    @abstractmethod
    async def verify_mfa_code(self, session_id: str, code: str) -> bool: ...
    @abstractmethod
    async def revoke_session(self, session_token: str) -> None: ...
```

- **V1 Provider:** `SelfBuiltAuthAdapter` using `passlib[bcrypt]`, `pyotp`, and PostgreSQL opaque session storage.
- **Server-Side Authorization:** Default Deny. Authorization middleware verifies `org_id` match and required role (`owner` | `admin` | `member` | `viewer`) on every non-public endpoint.

---

## 15. Tenant Isolation Invariants

1. **Database Queries:** Every query MUST contain `WHERE org_id = :org_id`. Enforced via repository base class.
2. **Cache Keys:** Formatted as `org:{org_id}:{entity}:{id}`.
3. **Redis Queues:** All job payloads include `org_id`. Workers isolate execution context per job.
4. **S3 Storage Keys:** Prefixed as `s3://asm-evidence/{org_id}/{scan_id}/{artifact_id}`.
5. **Logs & Audit Events:** `org_id` recorded as structured JSON field in all log records.

---

## 16. Evidence & Provenance Hierarchy

Every claim in the system maintains a explicit evidence type:

```
OBSERVED (Direct scan banner / DNS record)
    > CONNECTED SYSTEM (Cloud API / Certificate Transparency log)
    > HISTORICAL (Previous scan comparison)
    > HUMAN CONFIRMED (Explicit user tag / expected state entry)
    > STATISTICAL INFERENCE (Pattern heuristic)
    > AI REASONING (Future LLM suggestion — Never standalone evidence)
```

---

## 17. Future AI Architecture Boundary

When AI is introduced in Phase 3+:
- AI models operate strictly as read-only advisors.
- AI suggestions generate `RECOMMENDATIONS` requiring human confirmation.
- AI NEVER auto-accepts risk, NEVER modifies `expected_states`, and NEVER creates `organization_rules` without explicit human authorization.
- AI prompt contexts are strictly scoped to a single tenant's data (`org_id`).

---

## 18. Frontend Architecture & Design Language

- **Framework:** Next.js App Router + TypeScript.
- **Visual Palette:** **BLACK & WHITE PRIMARY PALETTE** (`hsl(222, 25%, 10%)` / `hsl(220, 20%, 98%)`).
- **Semantic Colors Used Sparingly:**
  - Red (`hsl(0, 72%, 51%)`): Critical severity & destructive actions
  - Orange (`hsl(20, 85%, 52%)`): High severity
  - Yellow (`hsl(38, 90%, 50%)`): Medium severity & warnings
  - Blue (`hsl(200, 70%, 50%)`): Low severity & informational
  - Green (`hsl(145, 65%, 42%)`): Verified & success states
- **Typography:** Inter (Primary UI) + JetBrains Mono (Technical IDs, IPs, Banners).

---

## 19. Google Stitch Integration Strategy

- Google Stitch (via MCP server) is a **prototyping and design exploration tool**.
- Stitch generated components or visual mockups serve as design references only.
- NO runtime dependencies on Stitch are introduced into the web-frontend or control-plane applications.

---

## 20. Testing Architecture

| Test Suite | Scope | Target Coverage | Security Focus |
|---|---|---|---|
| **Unit Tests** | Domain models, risk scoring, memory rules | > 85% | Pure business logic validation |
| **Integration Tests** | FastAPI endpoints, DB queries, Redis queue | > 75% | Tenant isolation, RBAC checks |
| **Security Tests** | Auth bypass, SSRF, DNS TOCTOU, CORS, Headers | 100% of auth/authz paths | Hardened security invariants |
| **Worker Tests** | Egress guards, redirect validator, zip bomb check | 100% of safety code | Destination safety validation |
| **E2E Tests** | Playwright user flows (Register → Onboard → Triage) | Core user journeys | UX validation & integration |

---

## 21. Observability Architecture

- **Structured Logs:** `structlog` producing JSON format with mandatory `request_id`, `org_id`, `user_id`.
- **Metrics (Prometheus):** `http_requests_total`, `scan_jobs_total`, `queue_depth`, `active_sessions`, `ssrf_blocks_total`.
- **Forbidden Log Data:** NEVER log passwords, session tokens, TOTP secrets, reset tokens, or raw credentials.

---

## 22. Local Development & Production Topology

```
LOCAL DEV TOPOLOGY (Docker Compose):
[ Next.js Frontend (Port 3000) ] ──► [ FastAPI Control Plane (Port 8000) ]
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
            [ PostgreSQL 16 ]            [ Redis 7 ]             [ MinIO S3 ]
                                              ▲
                                              │ Queue Jobs
                                    [ Scanner Worker ]

PRODUCTION TOPOLOGY:
[ Cloud Load Balancer / WAF ] ──► [ Control Plane API Pool (2+ Instances) ]
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
            [ Managed Postgres HA ]      [ Managed Redis ]        [ Cloud S3 ]
                                              ▲
                                              │ Private Subnet
                                    [ Isolated Worker Pool ]
```

---

## 23. Scalability Strategy & Service Extraction Points

1. **Phase 1 Monolith:** Modular monolith handles up to 1,000 active organizations.
2. **Horizontal Scaling:** Control plane API servers and scanner workers scale horizontally behind load balancers and queue consumers.
3. **Future Extraction Points (If Scale Demands):**
   - Extract `apps/scanner-worker` into a dedicated pool across multiple cloud regions.
   - Extract `Observations Ingestion` into a dedicated async pipeline if result ingestion saturates API workers.
   - Database read replicas for heavy asset query workloads.

---

## 24. Recommended Implementation Order

To prove the core thesis early without getting bogged down in scanner breadth:

```
1. PHASE 0: Infrastructure & Core Identity (Org, User, Auth, RBAC, Tenant Middleware)
2. PHASE 1A: Domain Onboarding & Verification (DNS TXT validation)
3. PHASE 1B: Isolated Scanner Worker Baseline (Target Auth + Destination Safety + Subdomain/Port/Cert scanner)
4. PHASE 1C: Asset & Relationship Engine (Deduplication, inventory, graph links)
5. PHASE 1D: Change Detection Engine (Scan-over-scan diffing)
6. PHASE 1E: Context, Expected State & Decision Memory (Ownership, env, expected state, decision storage)
7. PHASE 1F: Contextual Risk Engine & Traceable Evidence (Score calculation, evidence links)
8. PHASE 1G: Remediation Verification & Notifications (Re-scan verification trigger, alert dispatch)
9. PHASE 1H: Frontend Operations Dashboard (Next.js App Router UI)
```

---

## 25. Architectural Decision Records (ADRs)

### ADR-J-01: Modular Monolith Monorepo Architecture
- **Decision:** Structure codebase as a monorepo with `apps/control-plane`, `apps/web-frontend`, `apps/scanner-worker`, and `packages/shared-contracts`.
- **Reason:** Keeps control plane modular while enforcing a hard deployment boundary for scanner workers.
- **Consequences:** Simple developer workflow; clean trust boundaries.

### ADR-J-02: Strict Dual-Layer Scanner Validation
- **Decision:** Separate Target Authorization (DNS TXT verification) from Network Destination Safety (IP egress validation).
- **Reason:** Domain ownership does not grant permission to scan private networks or cloud metadata.
- **Consequences:** Eliminates SSRF and cloud metadata exposure risks.

### ADR-J-03: Scope-Limited Decision Memory
- **Decision:** Human decisions on assets apply strictly to explicit asset/port combinations.
- **Reason:** Prevents single-asset decisions from creating unassisted wildcard rules or global risk suppressions.
- **Consequences:** Deterministic, auditable, and safe organizational memory.
