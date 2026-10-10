# Attack Surface Monitor — Architecture

> **Status:** DRAFT — Pending Human Review
> **Last Updated:** 2026-08-27
> **Parent Document:** ProductConstitution.md, PRD.md, Phases.md
> **Document Type:** Conceptual Architecture

---

## 1. Architectural Philosophy

The system follows a **modular monolith** architecture for V1, with clear module boundaries that enable future service extraction when proven necessary by actual scaling bottlenecks — not theoretical concerns.

### Guiding Principles

1. **Multi-tenant from day one.** Tenant isolation is an architectural invariant, not a retrofit.
2. **Modular, not micro.** Clear module boundaries within a single deployable unit, with the scanner as the only separately-deployed component.
3. **Security boundaries are deployment boundaries.** The scanner worker is the only component that touches hostile Internet targets — it is deployed and networked separately from the control plane.
4. **Observe, then optimize.** Build observability first; scale based on measured bottlenecks.
5. **Stateless API, stateful storage.** API servers are horizontally scalable. State lives in PostgreSQL and Redis.

---

## 2. System Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INTERNET / USERS                             │
└────────────────────────────┬────────────────────────────────────────┘
                             │ HTTPS (TLS 1.2+)
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      EDGE / LOAD BALANCER                            │
│              (Rate Limiting, TLS Termination, WAF)                    │
└────────────────────────────┬────────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                              ▼
┌──────────────────────┐        ┌──────────────────────────┐
│    FRONTEND (SPA)     │        │       API SERVER          │
│   React / Next.js     │        │   (Control Plane API)     │
│   Static Assets CDN   │        │   FastAPI / Python        │
└──────────────────────┘        └─────────┬────────────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    ▼                     ▼                     ▼
          ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
          │  PostgreSQL   │     │    Redis      │     │ Object Store │
          │  (Primary DB) │     │ (Cache/Queue) │     │  (Evidence)  │
          └──────────────┘     └───────┬──────┘     └──────────────┘
                                       │
                                       │ Job Queue
                                       ▼
                         ┌─────────────────────────┐
                         │     SCAN ORCHESTRATOR     │
                         │  (Job Scheduling/Mgmt)    │
                         └────────────┬──────────────┘
                                      │
        ┌─────────────────────────────┼────────────────────────────┐
        ▼                             ▼                            ▼
┌──────────────┐           ┌──────────────┐            ┌──────────────┐
│ SCAN WORKER 1│           │ SCAN WORKER 2│            │ SCAN WORKER N│
│ (Isolated)   │           │ (Isolated)   │            │ (Isolated)   │
└──────┬───────┘           └──────┬───────┘            └──────┬───────┘
       │                          │                           │
       ▼                          ▼                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SCAN TARGETS (INTERNET)                            │
│            ⚠️  HOSTILE — Treat all responses as untrusted             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Trust Boundaries

### TB-1: User ↔ Platform
- **Boundary:** HTTPS with TLS 1.2+ termination at load balancer
- **Trust:** Users are authenticated but not fully trusted. Input validation on all API endpoints. Authorization checked on every request.

### TB-2: Control Plane ↔ Data Stores
- **Boundary:** Private network, encrypted connections
- **Trust:** Data stores trust the control plane API for authorized writes. All queries include tenant scoping.

### TB-3: Control Plane ↔ Scanner Workers
- **Boundary:** Job queue (Redis). No direct database or network connectivity.
- **Trust:** Control plane trusts scanner workers to execute scan jobs and return results. Workers do NOT have access to the control plane database, customer secrets, or internal APIs. Communication is exclusively through the job queue.
- **DECISION:** This is the most critical trust boundary. Scanner workers process responses from arbitrary hostile Internet hosts. A compromised worker must not be able to access control plane data.
- **ALTERNATIVES CONSIDERED:** (1) Direct database access for workers — rejected due to scanner compromise risk. (2) Shared network — rejected for same reason. (3) Separate cloud account for workers — considered for V2, unnecessary complexity for V1.
- **TRADEOFF:** Job queue indirection adds latency (seconds) to result delivery. Acceptable for security improvement.

### TB-4: Scanner Workers ↔ Internet
- **Boundary:** Outbound-only network access. No inbound connections.
- **Trust:** ZERO TRUST. All scan targets and responses are treated as hostile. All input is validated and sanitized before processing.

---

## 3.1 Scanner Threat Model & Security Invariants

### Critical Distinction: Target Authorization vs Network Destination Safety

```
┌────────────────────────────────────────────────────────────────────────┐
│                   DUAL-LAYER SCANNER VALIDATION MODEL                  │
├──────────────────────────────────┬─────────────────────────────────────┤
│ 1. TARGET AUTHORIZATION          │ 2. NETWORK DESTINATION SAFETY       │
│ (Domain Ownership)               │ (Egress Risk Control)               │
├──────────────────────────────────┼─────────────────────────────────────┤
│ • Validates org owns domain      │ • Validates IP is safe for egress   │
│ • Enforced via DNS TXT verification│ • Blocks RFC 1918 / 4193 / Loopback │
│ • Prevents unauthorized scans    │ • Blocks Cloud Metadata (169.254.x) │
│ • Legal & ethical compliance     │ • Prevents SSRF / Internal Scanning │
└──────────────────────────────────┴─────────────────────────────────────┘
```

A verified domain does NOT grant permission to scan internal networks, private IPs, or cloud metadata services pointed to by DNS or HTTP redirects.

### Scanner Security Invariants

1. **DNS Resolution TOCTOU Protection (DNS Rebinding Defense):**
   - Scanner worker MUST resolve hostname to IP address prior to connection.
   - Worker MUST validate the resolved IP against Network Destination Safety rules.
   - Worker MUST initiate TCP connection directly to the validated IP address (passing IP to socket API), using the original hostname ONLY in the HTTP `Host` header or TLS SNI extension.
   - Worker MUST NOT allow socket APIs to perform secondary un-validated DNS lookups.

2. **Strict Egress Destination Denylist:**
   - IPv4 Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - IPv4 Loopback & Special: `127.0.0.0/8`, `0.0.0.0/8`, `100.64.0.0/10` (CGNAT)
   - IPv4 Link-Local / Cloud Metadata: `169.254.0.0/16` (including `169.254.169.254`)
   - IPv6 Equivalent Ranges: `::1/128`, `fe80::/10` (link-local), `fc00::/7` (unique local)
   - Localhost Aliases: `localhost`, `*.localhost`, `*.local`

3. **HTTP Redirect Chain Safety:**
   - Maximum 5 redirects permitted.
   - EVERY intermediate redirect URL MUST be parsed, resolved, and validated against Network Destination Safety BEFORE following the hop.
   - If a redirect points to a private IP, loopback, or cloud metadata endpoint, the scanner MUST abort the redirect and record a `REDIRECT_BLOCKED_UNSAFE_DESTINATION` observation.

4. **Resource & Decompression Exhaustion Defenses:**
   - **Response Body Limit:** Hard ceiling of 10 MB per response. Connection aborted immediately if exceeded.
   - **Decompression Bomb Protection:** Decompression (gzip/deflate) MUST operate with a streaming ratio check. If uncompressed data exceeds 10 MB or a 20:1 compression ratio, decompression terminates immediately.
   - **Timeout Ceiling:** Connection timeout: 10s; Read timeout: 30s; Total scan job hard timeout: 5 minutes.
   - **Worker Container Caps:** Docker cgroups limit worker containers to 1 vCPU and 1 GB RAM with `read-only` root filesystem.

5. **Result & Queue Poisoning Protections:**
   - Control plane API validates schema and sanitizes all scan payloads returned via Redis queue before writing to PostgreSQL.
   - Scanner workers have NO database credentials, NO write keys to control plane APIs, and NO internal network routing.

### 4.1 Control Plane

The control plane is the core application handling all business logic, user interactions, and data management.

#### API Server

- **WHAT:** RESTful API serving the frontend and future integrations
- **WHY:** Central orchestration point for all business logic
- **ALTERNATIVES:** GraphQL (rejected — unnecessary complexity for V1; REST is simpler for a CRUD-heavy API with clear resource models)
- **TRADEOFFS:** REST is less flexible for complex nested queries but simpler to secure, cache, and document
- **CONSEQUENCES:** API versioning required for backward compatibility in V2

#### Authentication Module

- **WHAT:** User registration, login, MFA, session management, password reset
- **WHY:** Security foundation for all access control
- **ALTERNATIVES:** Auth-as-a-service (Auth0, Clerk) vs. self-built
- **DECISION:** Self-built authentication for V1
- **WHY:** (1) Security platform must fully control its own auth stack. (2) Avoids vendor dependency on critical security path. (3) MFA enforcement and session policies require deep control. (4) Cost control for early-stage product.
- **TRADEOFFS:** Higher implementation effort; must implement MFA, brute-force protection, and session management from scratch
- **CONSEQUENCES:** Requires thorough security review; authentication bugs are critical

#### Authorization Module (RBAC)

- **WHAT:** Role-based access control enforced on all API endpoints
- **WHY:** Tenant isolation and permission management
- **ALTERNATIVES:** ABAC (attribute-based) — rejected for V1 complexity; RBAC sufficient for 4-role model
- **CONSEQUENCES:** Must be enforced server-side on every request; middleware-based implementation

#### Organization & Tenant Management

- **WHAT:** Organization lifecycle, membership, domain management
- **WHY:** Multi-tenancy foundation
- **CONSEQUENCES:** Every data query must include `org_id` scoping

#### Domain Verification

- **WHAT:** DNS TXT record-based domain ownership proof
- **WHY:** Legal and ethical requirement — only scan domains the user controls
- **ALTERNATIVES:** HTTP-based verification (file upload) — deferred to V2 for simplicity
- **TRADEOFFS:** DNS verification requires DNS control, which some users may not have immediately
- **CONSEQUENCES:** Periodic re-verification required; failed re-verification pauses scanning

### 4.2 Discovery Engine

#### Scan Orchestrator

- **WHAT:** Job scheduling, distribution, and lifecycle management for scan operations
- **WHY:** Decouples scan scheduling from scan execution; enables horizontal worker scaling
- **ALTERNATIVES:** Cron-based scheduling (rejected — not dynamic enough), event-driven triggers (considered for V2)
- **CONSEQUENCES:** Requires reliable job queue infrastructure; job idempotency for retry safety

#### Discovery Pipeline

The discovery process follows a directed pipeline:

```
Domain Verification Check
         ↓
Subdomain Discovery          Certificate Transparency
         ↓                            ↓
DNS Resolution              ←── Merge & Deduplicate
         ↓
IP Resolution & Tracking
         ↓
Service/Port Discovery
         ↓
Banner Grabbing & Technology Identification
         ↓
Certificate Extraction
         ↓
DNS Record Collection (A, AAAA, CNAME, MX, TXT, NS, SOA)
         ↓
Results Assembly & Validation
         ↓
Return via Job Queue
```

#### Scan Workers

- **WHAT:** Isolated processes that execute scan jobs against Internet targets
- **WHY:** Security isolation from control plane; horizontal scaling
- **ALTERNATIVES:** In-process scanning (rejected — unacceptable security risk)
- **TRADEOFFS:** Queue-based communication adds latency; worker management adds operational complexity
- **CONSEQUENCES:** Workers need their own deployment, monitoring, and scaling infrastructure

#### Scanner Safety Controls

Workers MUST implement:

| Control | Description |
|---|---|
| **Target validation** | Only scan domains/IPs from verified, authorized organizations |
| **Private IP blocking** | Never scan RFC 1918/4193, loopback, link-local addresses |
| **Cloud metadata blocking** | Block requests to 169.254.169.254 and equivalent cloud metadata endpoints |
| **DNS rebinding protection** | Re-resolve DNS after initial resolution; block if IP changes to private range |
| **Redirect following limits** | Maximum 5 redirects; block redirects to private IPs |
| **Response size limits** | Maximum 10MB response body |
| **Timeout enforcement** | Connection: 10s, Read: 30s, Total job: 5 minutes |
| **Rate limiting** | Configurable per-target rate limit to avoid disruption |
| **Resource limits** | CPU, memory, and process limits per worker |

### 4.3 Data Processing Layer

#### Asset Resolution Engine

- **WHAT:** Processes raw scan results into the unified asset model
- **WHY:** Raw scan data needs deduplication, normalization, and relationship mapping
- **CONSEQUENCES:** This is a complex data pipeline — must handle duplicates, conflicting data, and partial results gracefully

#### Change Detection Engine

- **WHAT:** Compares current scan results against previous observations to identify changes
- **WHY:** Core product differentiator
- **ALTERNATIVES:** Event-sourced change detection (rejected for V1 — too complex; scan comparison is sufficient)
- **TRADEOFFS:** Scan comparison requires storing full observation snapshots; grows linearly with scan frequency and asset count
- **CONSEQUENCES:** Database design must optimize for scan-over-scan queries; observation table will be largest table

#### Risk Engine

- **WHAT:** Calculates contextualized risk scores for findings
- **WHY:** Organizational context transforms raw severity into business-relevant priority
- **INPUTS:** Finding severity, asset criticality, environment, ownership, expected state, confidence, exposure duration
- **ALTERNATIVES:** Simple CVSS pass-through (rejected — table stakes, not differentiating)
- **CONSEQUENCES:** Risk must recalculate when context changes; eventual consistency is acceptable

#### Decision Engine

- **WHAT:** Manages the lifecycle of human security decisions (accept risk, false positive, expected state)
- **WHY:** Core product differentiator — decisions persist and influence future processing
- **CONSEQUENCES:** Decision records are append-only; they influence risk calculation and alert suppression

### 4.4 Notification System

- **WHAT:** Multi-channel notification delivery based on change significance
- **WHY:** Users need timely notification of meaningful changes
- **CHANNELS (V1):** In-app notifications, Email
- **ALTERNATIVES:** Push notifications (rejected for V1 — no mobile app), SMS (rejected — cost, not necessary)
- **CONSEQUENCES:** Email delivery requires transactional email service (SendGrid, SES, or similar)

### 4.5 Observability Layer

- **WHAT:** Structured logging, metrics, health checks, request tracing
- **WHY:** Cannot optimize or debug what you cannot measure
- **CONSEQUENCES:** Must be implemented from Phase 0; retrofitting observability is painful

---

## 5. Data Flow Architecture

### 5.1 Scan Data Flow

```
1. SCHEDULE     Scan Orchestrator creates job for verified domain
                    ↓
2. ENQUEUE      Job placed on Redis scan queue
                    ↓
3. DEQUEUE      Available Scanner Worker picks up job
                    ↓
4. VALIDATE     Worker validates target is authorized (verified domain, not private IP)
                    ↓
5. EXECUTE      Worker performs discovery pipeline (subdomain → DNS → port → cert → tech)
                    ↓
6. SANITIZE     Worker validates and sanitizes all responses from hostile targets
                    ↓
7. RETURN       Worker places results on Redis results queue
                    ↓
8. PROCESS      Control Plane processes results:
                  a. Asset Resolution — update/create assets
                  b. Change Detection — compare with previous observations
                  c. Risk Calculation — compute contextualized risk
                  d. Notification — alert on meaningful changes
                    ↓
9. STORE        Results persisted to PostgreSQL; evidence to Object Store
```

### 5.2 User Decision Flow

```
1. VIEW         User views finding with evidence
                    ↓
2. DECIDE       User makes decision (accept risk, false positive, mark expected)
                    ↓
3. VALIDATE     API validates decision (required fields, authorization)
                    ↓
4. STORE        Decision stored (append-only) with actor, timestamp, reason, evidence
                    ↓
5. RECALCULATE  Risk Engine recalculates affected finding scores
                    ↓
6. UPDATE       Alert suppression rules updated based on decision
                    ↓
7. AUDIT        Decision recorded in audit log
```

---

## 6. Tenant Isolation Architecture

### Data Layer Isolation

All data queries are scoped by `org_id`. This is enforced at multiple levels:

| Level | Mechanism |
|---|---|
| **API Middleware** | Every authenticated request resolves the user's organization; injects `org_id` into request context |
| **Service Layer** | All data access methods require `org_id` parameter; no method fetches data without tenant scoping |
| **Database Query** | Every query on tenant-scoped tables includes `WHERE org_id = ?`; enforced by repository layer |
| **Database Index** | All primary query paths include `org_id` in the index for both security and performance |

### Cache Isolation

All cache keys include `org_id` prefix: `org:{org_id}:resource:{resource_id}`

### Queue Isolation

Job queue messages include `org_id`. Workers validate `org_id` before processing.

### Logging Isolation

All log entries include `org_id` as structured field. Log aggregation supports per-tenant filtering. Sensitive data never logged (see SecurityChecklist).

### AI Context Isolation (V2+)

When AI is introduced, all AI context (prompts, embeddings, model inputs) must be scoped to a single tenant. No cross-tenant training data.

---

## 7. Failure Boundaries

### Principle: Partial Failure is Normal

The system is designed to degrade gracefully, not fail completely.

| Failure Scenario | Impact | Handling |
|---|---|---|
| **Scanner worker crash** | Single scan job fails | Job requeued with retry (max 3 retries); other jobs unaffected |
| **Scan target unreachable** | No results for specific target | Recorded as "scan failed" with reason; previous observation preserved |
| **Redis unavailable** | Scan scheduling stops; cache miss | API continues with database reads; scan orchestrator waits for reconnection |
| **PostgreSQL unavailable** | Full platform degradation | Return 503; no data writes; health check fails; alert operations team |
| **Email service unavailable** | Notifications delayed | Queue email deliveries; retry with exponential backoff |
| **External DNS API unavailable** | Partial discovery results | Use available sources; record partial scan with reason |
| **Rate limit exceeded (external API)** | Throttled discovery | Exponential backoff; complete scan with available data |
| **Worker resource exhaustion** | Worker killed | OOM-killed worker restarts; job requeued |

### Circuit Breaker Pattern

External dependencies (email service, DNS APIs, Certificate Transparency APIs) use circuit breakers:

- **Closed:** Normal operation
- **Open:** Too many failures; stop calling; use fallback
- **Half-Open:** Periodically test; close if recovered

---

## 8. Scalability Architecture

### V1 Scaling Model

| Component | Scaling Strategy | Trigger |
|---|---|---|
| **API Server** | Horizontal (add instances behind LB) | CPU > 70% or response time > 500ms P95 |
| **Scanner Workers** | Horizontal (add workers) | Queue depth > 100 jobs or scan latency > target |
| **PostgreSQL** | Vertical (larger instance) + read replicas | Connection saturation or query latency |
| **Redis** | Vertical (larger instance) | Memory usage > 70% or connection saturation |

### Future Scaling (V2+)

| Concern | Strategy |
|---|---|
| Observation data growth | Table partitioning by `org_id` + time range |
| Multi-region | Read replicas in additional regions; write to primary |
| Worker pool management | Auto-scaling based on queue depth |
| Large organizations | Dedicated scan scheduling with throttling |

---

## 9. Future ARES Integration Architecture

### Integration Model

```
┌─────────────────────┐                    ┌─────────────────────┐
│  ATTACK SURFACE      │                    │       ARES           │
│  MONITOR             │                    │                      │
│                      │   Validation       │                      │
│  Risk Engine ────────┼───Request────────►│  Policy Agent         │
│                      │   (API)            │       ↓               │
│                      │                    │  Recon Agent          │
│                      │                    │       ↓               │
│                      │   Validation       │  Analyzer Agent       │
│  OSM Update ◄────────┼───Result──────────│       ↓               │
│       ↓              │   (Webhook/API)    │  Validation Agent     │
│  Risk Recalculation  │                    │       ↓               │
│       ↓              │                    │  Report               │
│  Evidence Update     │                    │                      │
└─────────────────────┘                    └─────────────────────┘
```

### Integration Boundaries

1. **Communication:** REST API + webhook callbacks. No shared databases.
2. **Authorization:** ASM provides scoped API token per validation request. ARES validates only targets authorized in that token.
3. **Scope:** ASM controls *what* to validate (which finding, which target). ARES controls *how* (which techniques, which tools).
4. **Results:** ARES returns structured validation results. ASM treats these as evidence within its evidence hierarchy.
5. **Failure:** ARES unavailability does not affect ASM core functionality. Validation requests are queued and retried.

**Classification:** DECISION — ARES integration is V2+ scope. The architecture supports clean integration through well-defined API boundaries without requiring shared infrastructure.

---

## 10. Disaster Recovery Concepts

### Backup Strategy (V1)

| Component | Backup Method | Frequency | Retention |
|---|---|---|---|
| **PostgreSQL** | Automated snapshots + WAL archiving | Daily snapshots, continuous WAL | 30 days |
| **Redis** | RDB snapshots | Every 6 hours | 7 days |
| **Object Store (Evidence)** | Cross-region replication | Continuous | Same as primary |
| **Configuration/Secrets** | Version-controlled (encrypted) | On change | Git history |

### Recovery Objectives

| Metric | V1 Target |
|---|---|
| **RPO** (Recovery Point Objective) | < 1 hour |
| **RTO** (Recovery Time Objective) | < 4 hours |

### Disaster Scenarios

| Scenario | Recovery |
|---|---|
| Database corruption | Restore from latest snapshot + WAL replay |
| Availability zone failure | Failover to standby (if provisioned) or restore in alternate AZ |
| Complete region failure | Restore from cross-region backups in alternate region |
| Accidental data deletion | Point-in-time recovery from WAL |
| Secret compromise | Rotate all secrets; invalidate all sessions; audit access |

---

## 11. Architectural Decision Log

| Decision | Reason | Alternatives Considered | Consequences |
|---|---|---|---|
| **Modular monolith for V1** | Reduces operational complexity; single deployment; clear module boundaries sufficient | Microservices (rejected — premature for team size and scale) | Must maintain module boundaries; extract services if proven necessary |
| **Separate scanner deployment** | Security requirement — scanner touches hostile targets | In-process scanning (rejected — security risk) | Requires job queue; adds deployment complexity |
| **REST API** | Simpler to secure, cache, document; sufficient for CRUD-heavy domain | GraphQL (rejected — complexity); gRPC (rejected — browser support) | Must plan for API versioning |
| **Self-built auth** | Full control over security-critical path; vendor independence | Auth0/Clerk (rejected — dependency on external service for security product) | Higher implementation effort; requires thorough security review |
| **PostgreSQL** | Mature, reliable, excellent for relational data; strong JSON support | MongoDB (rejected — tenant isolation harder; eventual consistency issues) | Must plan for observation table growth |
| **Redis for cache + queue** | Single technology for two needs; mature; low operational overhead | RabbitMQ for queue (considered — more features but more operational burden) | Redis persistence config important for queue reliability |
| **Job queue for scanner communication** | Decouples control plane from workers; enables horizontal scaling; security boundary | Direct API calls to workers (rejected — requires worker to be addressable) | Adds latency; requires idempotent job design |
| **DNS-only domain verification** | More secure than HTTP; proves DNS control | HTTP verification (deferred — easier but less secure); email verification (rejected — doesn't prove infrastructure control) | May frustrate users without direct DNS access |
