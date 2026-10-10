# Attack Surface Monitor — Technical Specification

> **Status:** DRAFT — Pending Human Review
> **Last Updated:** 2026-08-27
> **Parent Document:** Architecture.md
> **Document Type:** Technology Decisions

---

## 1. Technology Stack Summary

| Layer | Technology | Version / Notes |
|---|---|---|
| **Frontend** | Next.js (React) + TypeScript | App Router, SSR for initial load, SPA for interactions |
| **Backend** | Python + FastAPI | Python 3.12+, async-first |
| **Database** | PostgreSQL | 16+ |
| **Cache / Queue** | Redis | 7+ (with persistence for queue reliability) |
| **Object Storage** | S3-compatible | AWS S3, MinIO (local dev), or equivalent |
| **Authentication** | Self-built (bcrypt + TOTP) | No external auth provider |
| **Email** | Transactional email service | SendGrid, AWS SES, or Resend |
| **Scanner** | Python workers | Custom discovery pipeline |
| **Observability** | Structured logging + Prometheus + Grafana | OpenTelemetry for tracing |
| **CI/CD** | GitHub Actions | Lint, test, build, deploy |
| **Containers** | Docker | Docker Compose (dev), single orchestrator (prod) |
| **Infrastructure** | Cloud VM / managed services | AWS or equivalent; no Kubernetes for V1 |

---

## 2. Frontend

### Framework: Next.js + TypeScript

**DECISION:** Next.js with App Router

**WHY:**
1. React ecosystem provides the richest component library ecosystem for complex dashboards
2. Next.js provides SSR for initial page loads (SEO for public pages, fast dashboard load)
3. TypeScript provides type safety for a complex data model
4. App Router provides modern React patterns (server components, streaming)
5. Large community and hiring pool

**ALTERNATIVES CONSIDERED:**
- **Vite + React SPA:** Simpler, but no SSR; dashboard-first apps benefit from SSR for initial load
- **SvelteKit:** Excellent performance, but smaller ecosystem; harder to hire for
- **Angular:** Overkill for the team size; heavier framework

**TRADEOFFS:**
- Next.js introduces server/client component complexity
- Larger bundle than pure SPA, but mitigated by code splitting
- Vercel-originated but deployable anywhere (Docker, self-hosted)

**CONSEQUENCES:**
- Must maintain clear server/client component boundaries
- Image optimization and static asset handling handled by Next.js
- API calls from client components to backend API (not Next.js API routes for core logic)

### UI Libraries

| Concern | Choice | Reason |
|---|---|---|
| **Component Library** | Radix UI (headless) + custom styling | Accessible primitives; full design control; no opinionated styling |
| **CSS** | CSS Modules + design tokens | Scoped styles; maintainable; no runtime CSS-in-JS overhead |
| **Charts** | Recharts or Nivo | React-native charting; good for dashboards |
| **Icons** | Lucide Icons | Consistent, open-source, tree-shakeable |
| **Forms** | React Hook Form + Zod | Performant form handling with schema validation |
| **Data Tables** | TanStack Table | Headless, flexible, supports sorting/filtering/pagination |
| **State Management** | React Query (TanStack Query) + React Context | Server state via React Query; minimal client state |
| **Routing** | Next.js App Router | Built-in file-system routing |

### Frontend Security

- All API calls use HttpOnly cookies (no localStorage for tokens)
- CSP headers configured to prevent XSS
- No `dangerouslySetInnerHTML` without sanitization
- Form inputs validated client-side (Zod) AND server-side
- CSRF protection via SameSite cookies + CSRF token for state-changing requests

---

## 3. Backend

### Framework: Python + FastAPI

**DECISION:** Python 3.12+ with FastAPI

**WHY:**
1. FastAPI is mature, async-native, and has excellent Pydantic validation
2. Python has the richest ecosystem for security tooling (DNS libraries, network scanning, cert parsing)
3. Security engineers (target users and contributors) are most likely Python-proficient
4. Pydantic v2 provides fast, type-safe request/response validation
5. Async support enables concurrent I/O operations (critical for scan orchestration)

**ALTERNATIVES CONSIDERED:**
- **Go:** Better raw performance, but slower development velocity; weaker security tooling ecosystem
- **Node.js/TypeScript:** Full-stack TypeScript appealing, but weaker security/networking libraries
- **Rust:** Excellent performance/safety, but dramatically slower development; overkill for API server

**TRADEOFFS:**
- Python is slower than Go/Rust for CPU-bound tasks (mitigated: scanning is I/O-bound)
- GIL limits true multi-threading (mitigated: async + multi-process workers)
- Type safety weaker than Go/Rust (mitigated: Pydantic + mypy)

**CONSEQUENCES:**
- Must use async patterns consistently (no blocking I/O in async handlers)
- Workers run as separate processes (not threads)
- Consider Go or Rust for performance-critical scanner components in V2 if needed

### Backend Libraries

| Concern | Choice | Reason |
|---|---|---|
| **Web Framework** | FastAPI | Async-native, Pydantic validation, OpenAPI auto-gen |
| **ORM** | SQLAlchemy 2.0 (async) | Mature, flexible, async support, type-safe queries |
| **Migrations** | Alembic | Standard SQLAlchemy migration tool |
| **Validation** | Pydantic v2 | Fast, type-safe, integrates with FastAPI |
| **Password Hashing** | bcrypt (via passlib) | Industry standard; configurable work factor |
| **TOTP** | pyotp | TOTP generation and verification |
| **JWT** | PyJWT (for specific tokens only) | Session tokens are opaque; JWT only for short-lived tokens (email verification, password reset) |
| **HTTP Client** | httpx | Async HTTP client for external API calls |
| **DNS** | dnspython | Comprehensive DNS query library |
| **Task Queue** | arq (or custom Redis queue) | Lightweight async job queue built on Redis |
| **Rate Limiting** | slowapi or custom middleware | Per-IP and per-user rate limiting |
| **Logging** | structlog | Structured JSON logging |
| **Testing** | pytest + pytest-asyncio + httpx | Async test support |

### Session Management

**DECISION:** Server-side sessions with opaque tokens (NOT JWTs for user sessions)

**WHY:**
1. Server-side sessions are revocable (instant logout, instant session invalidation on password change)
2. JWT sessions cannot be truly revoked without a blocklist (which negates the benefit of JWTs)
3. For a security platform, session revocability is a hard requirement
4. Opaque session tokens in HttpOnly cookies are simpler and more secure than JWT + refresh token flows

**IMPLEMENTATION:**
- Session stored in PostgreSQL (session ID, user ID, org ID, created_at, expires_at, last_active, IP, user_agent)
- Session token: cryptographically random 256-bit value, base64url-encoded
- Cookie: HttpOnly, Secure, SameSite=Strict, Path=/
- Idle timeout: 30 minutes (configurable)
- Absolute timeout: 8 hours (configurable)
- Session rotation on privilege change (role change, MFA completion)

**ALTERNATIVES CONSIDERED:**
- **JWT sessions:** Cannot be truly revoked; requires token blocklist for security
- **JWT + refresh token:** Complex; refresh token rotation adds failure modes
- **Redis sessions:** Faster but volatile; PostgreSQL is durable and queryable

---

## 4. Database

### Primary Database: PostgreSQL 16+

**DECISION:** PostgreSQL as the single primary data store for V1

**WHY:**
1. Mature, reliable, battle-tested for multi-tenant SaaS
2. Excellent support for complex queries, joins, and aggregations required by asset graph
3. Strong JSONB support for semi-structured scan data and evidence
4. Row-level security and schemas available for future tenant isolation options
5. Extensive indexing options (B-tree, GIN, GiST) for diverse query patterns
6. Point-in-time recovery via WAL archiving

**ALTERNATIVES CONSIDERED:**
- **MongoDB:** Flexible schema, but tenant isolation harder to enforce; eventual consistency complicates audit logs
- **CockroachDB:** Distributed PostgreSQL-compatible, but operational complexity for V1 scale
- **SQLite:** Unsuitable for multi-tenant SaaS

**TRADEOFFS:**
- Single database for V1 means all data in one place (simplicity)
- Observation table will grow large — requires indexing strategy and future partitioning
- No built-in full-text search comparable to Elasticsearch (acceptable for V1; add search index later if needed)

**CONSEQUENCES:**
- Must plan database growth (observation table will be largest)
- Must implement connection pooling (PgBouncer or built-in)
- Must configure automated backups and WAL archiving from day 1

### Connection Pooling

- Use SQLAlchemy async connection pool (built-in)
- Pool size: 20 connections per API server instance (configurable)
- Max overflow: 10 (configurable)
- Connection timeout: 30 seconds

### Indexing Strategy

- Every tenant-scoped table has `org_id` in its primary query index
- Composite indexes: `(org_id, created_at)`, `(org_id, asset_type)`, `(org_id, status)`
- GIN indexes on JSONB columns for metadata queries
- Partial indexes for active records (`WHERE status != 'archived'`)

---

## 5. Cache

### Redis 7+

**DECISION:** Redis for both caching and job queue

**WHY:**
1. Single technology for two concerns (cache + queue) reduces operational overhead
2. Mature, fast, well-understood
3. Persistence options (RDB + AOF) provide queue durability
4. Pub/sub for real-time notifications (V2)

**CONFIGURATION:**
- Caching: Default TTL 5 minutes; per-key TTL configurable
- Queue: AOF persistence enabled for job durability
- Max memory: configured with eviction policy `allkeys-lru` for cache; queue data in separate database number (no eviction)

**CACHE KEY FORMAT:**
```
org:{org_id}:resource_type:{resource_id}
org:{org_id}:list:assets:page:{page}:filter:{hash}
rate:ip:{ip_address}
rate:user:{user_id}
session:{session_token_hash}
```

All cache keys include `org_id` for tenant isolation.

---

## 6. Object Storage

### S3-Compatible Object Storage

**DECISION:** S3-compatible storage for evidence and large scan artifacts

**WHY:**
1. Scan evidence (raw responses, banners, certificates) can be large
2. Object storage is cheaper than database storage for large blobs
3. S3 API is the de facto standard; works with AWS S3, MinIO, DigitalOcean Spaces, etc.
4. Vendor-neutral; supports local development (MinIO)

**STRUCTURE:**
```
/{org_id}/evidence/{scan_id}/{finding_id}/{artifact_type}
/{org_id}/reports/{report_id}/{filename}
/{org_id}/certificates/{cert_hash}
```

**SECURITY:**
- Bucket-level access control (no public access)
- Pre-signed URLs for time-limited access from frontend
- Encryption at rest (S3-managed or KMS)
- Lifecycle policies for retention management

---

## 7. Scanner Infrastructure

### Scanner Worker Architecture

**DECISION:** Python-based scanner workers running as separate processes

**WHY:**
1. Same language as control plane (code reuse for data models, validation)
2. Python has excellent DNS, HTTP, and TLS libraries
3. Workers are I/O-bound (network scanning), not CPU-bound; Python's async is sufficient

**SCANNER TOOLING:**

| Capability | Implementation | Notes |
|---|---|---|
| **Subdomain discovery** | Certificate Transparency (crt.sh API), DNS brute-force (dnspython), passive DNS APIs | Multiple sources for completeness |
| **DNS resolution** | dnspython | Direct DNS queries; support for all record types |
| **Port scanning** | asyncio TCP connect scanner (custom) | Top 1,000 ports; configurable; async for throughput |
| **Banner grabbing** | httpx (HTTP/S), custom protocol handlers | Protocol-specific banner extraction |
| **TLS/Certificate** | ssl module + cryptography library | Certificate chain extraction and validation |
| **Technology ID** | Rule-based matching (custom, inspired by Wappalyzer) | HTTP headers + HTML content analysis |

**ALTERNATIVES CONSIDERED:**
- **Nmap integration:** Powerful but heavy; complicates containerization; excess capabilities
- **Masscan:** Very fast but requires raw sockets (root/CAP_NET_RAW); security concern in containerized environment
- **Nuclei integration:** Template-based scanning; considered for V2; overkill for V1 discovery

**TRADEOFFS:**
- Custom scanner is less feature-rich than nmap but safer and more controllable
- Async TCP connect scanning is slower than SYN scanning but doesn't require raw sockets
- Multiple subdomain sources add complexity but improve discovery completeness

**CONSEQUENCES:**
- Scanner performance limited by async TCP connect (not SYN); acceptable for V1 scale
- May need to evaluate Go/Rust scanner for V2 if throughput becomes bottleneck
- Each discovery source requires separate error handling and retry logic

### Worker Isolation

| Isolation Layer | Mechanism |
|---|---|
| **Network** | Workers in separate network segment; no access to control plane database or internal services |
| **Process** | Each worker runs in its own container with resource limits |
| **Filesystem** | Read-only filesystem except for temporary working directory (tmpfs) |
| **CPU/Memory** | Container resource limits (configurable; default 1 CPU, 1GB RAM per worker) |
| **Egress** | Outbound Internet access only; no access to private network |
| **Credentials** | Workers have NO database credentials, NO API keys for control plane, NO cloud credentials |

---

## 8. Authentication Architecture

### 8.1 Option Analysis & Architectural Decision

A formal decision analysis was conducted evaluating three authentication options:

| Criterion | Option A: Self-Built (Recommended V1) | Option B: SaaS Provider (Auth0/Clerk) | Option C: Self-Hosted IdP (Keycloak) |
|---|---|---|---|
| **Security Risk** | Moderate (mitigated by standard libs) | Low (managed service) | Low-Moderate |
| **Implementation Effort** | 3–5 dev days | 1–2 dev days | 2–4 dev days |
| **Tenant Isolation** | 100% native schema control | Requires sync/webhook mapping | Requires token claim mapping |
| **Session Control** | Instant, server-side DB revocation | Dependent on vendor API/JWT refresh | Managed via Keycloak API |
| **Vendor Dependency** | ZERO vendor lock-in | High vendor lock-in on auth path | Low (self-hosted open source) |
| **V1 Cost** | $0 | Scale-dependent pricing ($100s+/mo) | $0 license, additional RAM overhead |
| **Enterprise Readiness** | Requires SAML/SSO addition in V2 | Pre-built SAML/SSO | Pre-built SAML/SSO |

**RECOMMENDED DECISION FOR V1: OPTION A (Self-Built with Strict Library Constraints)**

**JUSTIFICATION:**
1. For a cybersecurity platform, delegating core authentication to a third-party SaaS introduces external dependency on the critical authentication path.
2. Direct database control over sessions allows instant, server-side session revocation without JWT refresh latency or vendor API rate limits.
3. Native schema multi-tenancy ensures `org_id` and RBAC roles are verified in-process without sync webhooks.

**STRICT IMPLEMENTATION CONSTRAINTS (What MUST NOT be custom-built):**
- MUST use `passlib` with `bcrypt` (work factor 12) for password hashing. NO custom hashing functions.
- MUST use `pyotp` (RFC 6238) for TOTP generation/validation. NO custom TOTP algorithms.
- MUST use Python `secrets` module for token generation (`secrets.token_urlsafe(32)`). NO `random` or pseudo-random generators.
- MUST implement an `AuthAdapter` interface in the backend code so that Option B/C (e.g. SAML/SSO or Auth0) can be added as a provider in V2 without refactoring core business logic.

### 8.2 Password Handling

- **Hashing:** bcrypt with work factor 12 (configurable)
- **Minimum password length:** 12 characters
- **Complexity:** At least 1 uppercase, 1 lowercase, 1 digit, 1 special character
- **Breach check:** V2 (check against HaveIBeenPwned API)

### 8.3 MFA (TOTP)

- **Algorithm:** SHA-1 TOTP (RFC 6238) — standard compatible with all authenticator apps
- **Period:** 30 seconds
- **Digits:** 6
- **Recovery codes:** 10 codes, 16 characters each, cryptographically random
- **Storage:** TOTP secret encrypted at rest; recovery codes hashed (bcrypt)

### 8.4 Token Security

| Token Type | Method | Lifetime | Notes |
|---|---|---|---|
| **Session token** | Opaque, cryptographically random, 256-bit | 8h absolute, 30min idle | HttpOnly cookie |
| **Email verification** | JWT (signed, not encrypted) | 24 hours | Single-use; invalidated on use |
| **Password reset** | JWT (signed, not encrypted) | 1 hour | Single-use; invalidated on use or new request |
| **Domain verification** | Cryptographically random string | 72 hours | Stored in DB; verified via DNS lookup |
| **API key (V2)** | Opaque, cryptographically random, 256-bit | Configurable | Hashed in DB; shown once on creation |

---

## 9. API Architecture

### API Design Principles

1. **RESTful resource design** — resources map to domain entities
2. **Consistent error format** — all errors return `{error: string, code: string, details?: object}`
3. **Pagination** — cursor-based pagination for lists (offset-based acceptable for V1 simplicity)
4. **Filtering** — query parameter-based filtering
5. **Versioning** — URL prefix versioning (`/api/v1/...`)
6. **OpenAPI** — auto-generated from FastAPI; serves as API documentation

### API Security

| Control | Implementation |
|---|---|
| **Authentication** | Session cookie on all protected endpoints |
| **Authorization** | RBAC middleware; org membership + role checked per request |
| **Input validation** | Pydantic models on all request bodies; query param validation |
| **Output encoding** | JSON serialization via Pydantic; no HTML in API responses |
| **Rate limiting** | Per-IP (public endpoints) + per-user (authenticated endpoints) |
| **CORS** | Allow only known frontend origins |
| **CSRF** | SameSite=Strict cookies + CSRF token for state-changing requests |
| **Security headers** | Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, CSP |

### Core API Routes (V1)

```
POST   /api/v1/auth/register
POST   /api/v1/auth/verify-email
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
POST   /api/v1/auth/password-reset/request
POST   /api/v1/auth/password-reset/confirm
POST   /api/v1/auth/mfa/enroll
POST   /api/v1/auth/mfa/verify
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{session_id}

POST   /api/v1/organizations
GET    /api/v1/organizations/{org_id}
PATCH  /api/v1/organizations/{org_id}
GET    /api/v1/organizations/{org_id}/members
POST   /api/v1/organizations/{org_id}/members/invite
PATCH  /api/v1/organizations/{org_id}/members/{member_id}
DELETE /api/v1/organizations/{org_id}/members/{member_id}

POST   /api/v1/organizations/{org_id}/domains
GET    /api/v1/organizations/{org_id}/domains
POST   /api/v1/organizations/{org_id}/domains/{domain_id}/verify
DELETE /api/v1/organizations/{org_id}/domains/{domain_id}

GET    /api/v1/organizations/{org_id}/assets
GET    /api/v1/organizations/{org_id}/assets/{asset_id}
PATCH  /api/v1/organizations/{org_id}/assets/{asset_id}
GET    /api/v1/organizations/{org_id}/assets/{asset_id}/history
GET    /api/v1/organizations/{org_id}/assets/{asset_id}/relationships

GET    /api/v1/organizations/{org_id}/findings
GET    /api/v1/organizations/{org_id}/findings/{finding_id}
PATCH  /api/v1/organizations/{org_id}/findings/{finding_id}
GET    /api/v1/organizations/{org_id}/findings/{finding_id}/evidence

POST   /api/v1/organizations/{org_id}/decisions
GET    /api/v1/organizations/{org_id}/decisions

GET    /api/v1/organizations/{org_id}/changes
GET    /api/v1/organizations/{org_id}/scans
GET    /api/v1/organizations/{org_id}/scans/{scan_id}

GET    /api/v1/organizations/{org_id}/notifications
PATCH  /api/v1/organizations/{org_id}/notifications/{notification_id}

GET    /api/v1/organizations/{org_id}/audit-log

GET    /api/v1/health
```

---

## 10. Observability

### Logging

- **Format:** Structured JSON (structlog)
- **Fields:** timestamp, level, message, request_id, user_id, org_id, service, module
- **Sensitive data:** NEVER log passwords, tokens, secrets, API keys, session tokens
- **Log levels:** DEBUG (development only), INFO (normal operations), WARNING (degraded), ERROR (failures), CRITICAL (system-level)

### Metrics (Prometheus)

| Metric | Type | Description |
|---|---|---|
| `http_requests_total` | Counter | Total HTTP requests by method, path, status |
| `http_request_duration_seconds` | Histogram | Request latency by endpoint |
| `scan_jobs_total` | Counter | Scan jobs created/completed/failed |
| `scan_job_duration_seconds` | Histogram | Scan job execution time |
| `queue_depth` | Gauge | Current job queue depth |
| `active_sessions` | Gauge | Current active sessions |
| `assets_total` | Gauge | Total assets per organization |
| `findings_total` | Gauge | Total findings by severity |
| `auth_failures_total` | Counter | Authentication failures |

### Health Checks

```
GET /api/v1/health         → {"status": "healthy", "checks": {...}}
GET /api/v1/health/ready   → {"ready": true}   (load balancer readiness)
GET /api/v1/health/live    → {"alive": true}    (liveness probe)
```

Health checks verify: database connectivity, Redis connectivity, disk space.

---

## 11. Development Environment

### Local Development

- **Docker Compose:** PostgreSQL, Redis, MinIO (S3-compatible), MailHog (email testing)
- **Frontend:** `npm run dev` with hot reload
- **Backend:** `uvicorn app.main:app --reload`
- **Database migrations:** Alembic auto-generate and apply

### Environment Variables

All configuration via environment variables (12-factor app). Loaded via Pydantic Settings.

| Variable | Description | Default (Dev) |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://asm:asm@localhost:5432/asm` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `S3_ENDPOINT` | Object storage endpoint | `http://localhost:9000` |
| `S3_BUCKET` | Evidence bucket name | `asm-evidence` |
| `S3_ACCESS_KEY` | Object storage access key | `minioadmin` |
| `S3_SECRET_KEY` | Object storage secret key | `minioadmin` |
| `SESSION_SECRET` | Session token signing key | Generated |
| `MFA_ENCRYPTION_KEY` | Key for encrypting TOTP secrets | Generated |
| `FRONTEND_URL` | Frontend origin for CORS | `http://localhost:3000` |
| `EMAIL_PROVIDER` | Email service (mailhog/sendgrid/ses) | `mailhog` |
| `APP_ENV` | Environment (development/staging/production) | `development` |
| `LOG_LEVEL` | Logging level | `DEBUG` |

---

## 12. Testing Strategy

### Testing Pyramid

| Level | Scope | Tools | Target Coverage |
|---|---|---|---|
| **Unit** | Individual functions, validators, utilities | pytest | > 80% |
| **Integration** | API endpoints, database queries, auth flows | pytest + httpx + test DB | > 70% |
| **Security** | Auth bypass, RBAC enforcement, IDOR, input validation | pytest (custom security suite) | 100% of auth/authz paths |
| **E2E** | Critical user flows (signup → verify → login → discover) | Playwright | Key happy paths + failure paths |

### Security Test Requirements

| Test Category | What It Tests |
|---|---|
| **Auth bypass** | Every endpoint returns 401 without session |
| **RBAC enforcement** | Each role's permissions enforced; lower roles cannot access higher-role endpoints |
| **Tenant isolation** | User in org A cannot access org B data via any API path |
| **IDOR/BOLA** | Resource access validates user belongs to the resource's organization |
| **Input validation** | SQL injection, XSS, path traversal attempts return errors, not results |
| **Rate limiting** | Excessive requests are throttled |
| **Session security** | Expired sessions rejected; logout invalidates session; idle timeout works |

---

## 13. CI/CD Pipeline

### Pipeline Stages

```
1. LINT          Python (ruff, mypy), TypeScript (eslint), Security (bandit)
2. TEST          Unit tests, Integration tests, Security tests
3. BUILD         Docker images (backend, frontend, scanner-worker)
4. SCAN          Container image scanning (Trivy), dependency audit
5. DEPLOY (STG)  Deploy to staging environment
6. SMOKE TEST    Health checks + critical path verification on staging
7. DEPLOY (PRD)  Deploy to production (manual approval gate)
```

### Security Gates in CI

| Gate | Tool | Block on Failure |
|---|---|---|
| **SAST** | Bandit (Python), ESLint security rules | Yes (high/critical) |
| **Dependency audit** | pip-audit, npm audit | Yes (high/critical) |
| **Secret scanning** | gitleaks | Yes (any detection) |
| **Container scanning** | Trivy | Yes (high/critical) |
| **Security tests** | Custom pytest suite | Yes (any failure) |

---

## 14. Deployment Architecture (V1)

### Production Deployment

**DECISION:** Docker Compose on cloud VMs (V1), with clear path to container orchestration (V2)

**WHY:**
1. V1 scale (< 100 organizations) does not require Kubernetes
2. Docker Compose is simpler to operate, debug, and maintain for small team
3. Clear migration path: Docker Compose → Docker Swarm or Kubernetes when scale demands
4. Managed database (RDS or equivalent) handles database operations

**TRADEOFFS:**
- Limited auto-scaling (add VMs manually or via cloud auto-scaling groups)
- No built-in service mesh or advanced networking
- Simpler but less resilient than Kubernetes

**INFRASTRUCTURE:**

| Component | Deployment | Notes |
|---|---|---|
| **Frontend** | CDN + static hosting (Vercel, CloudFront) or Docker container | Static assets served from CDN |
| **API Server** | Docker container on VM, behind load balancer | 2+ instances for HA |
| **Scanner Workers** | Docker containers on separate VM(s) | Separate network segment |
| **PostgreSQL** | Managed database service (RDS, Cloud SQL) | Automated backups, HA |
| **Redis** | Managed Redis service (ElastiCache, Memorystore) | Persistence enabled |
| **Object Storage** | Managed S3 service | Cross-region replication |
| **Load Balancer** | Cloud load balancer (ALB, Cloud LB) | TLS termination, health checks |

---

## 15. Technology Decision Log

| Decision | Reason | Risk | Mitigation |
|---|---|---|---|
| **Next.js** | SSR + React ecosystem + TypeScript | Framework complexity; Vercel dependency perception | Deploy via Docker; avoid Vercel-only features |
| **Python + FastAPI** | Security tooling ecosystem; async; developer familiarity | Performance ceiling for CPU-bound work | Scanner workers are I/O-bound; extract CPU-intensive parts to Go if needed |
| **PostgreSQL** | Reliability; relational model fits domain; multi-tenant isolation | Observation table growth | Partitioning strategy; archive old observations |
| **Redis** | Cache + queue in one; low overhead | Single point of failure if not HA | Managed Redis with replicas; graceful degradation on Redis failure |
| **Self-built auth** | Full control; no external dependency for security-critical path | Implementation bugs | Thorough security testing; follow OWASP guidelines |
| **Docker Compose (prod V1)** | Simplicity for small team | Limited auto-scaling | Cloud auto-scaling groups; migrate to K8s for V2 if needed |
| **Custom port scanner** | Safer than nmap/masscan; no raw sockets needed | Slower than SYN scanning | Acceptable for V1 scale; evaluate Go scanner for V2 |
| **arq (Redis job queue)** | Lightweight; Python-native; async | Less mature than Celery | Simple requirements for V1; migrate if reliability issues |
