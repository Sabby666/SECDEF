# Attack Surface Monitor — Living Memory & Decision Log

> **Status:** ACTIVE — Living Knowledge Base
> **Last Updated:** 2026-08-27
> **Document Type:** Project Memory & Decision Log

---

## 1. Strategic Decisions Log

### DECISION 001: Modular Monolith for Control Plane
- **DECISION:** Use a modular monolith architecture for the control plane (FastAPI + PostgreSQL), separating only the scanner worker nodes.
- **REASON:** Avoids premature microservice complexity while maintaining strict domain separation and worker isolation.
- **ALTERNATIVES:** Microservices architecture.
- **CONSEQUENCES:** Easy local development via Docker Compose; simple deployment.
- **DATE:** 2026-08-27

### DECISION 002: Self-Built Authentication Infrastructure
- **DECISION:** Implement self-built authentication using `bcrypt`, server-side opaque sessions in PostgreSQL/Redis, and `pyotp` for TOTP MFA.
- **REASON:** Maintain 100% control over security-critical authentication logic, session revocation, and multi-tenant isolation without external SaaS vendor lock-in.
- **ALTERNATIVES:** Auth0, Clerk, Keycloak.
- **CONSEQUENCES:** Higher initial implementation effort; requires strict adherence to `SecurityChecklist.md`.
- **DATE:** 2026-08-27

### DECISION 004: 10-Level Learning Taxonomy & Scope-Limited Inheritance
- **DECISION:** Formally define the 10-level learning taxonomy (Observation, Context, Expectation, Decision, Memory, Rule, Baseline, Feedback, Learning, Verification) and enforce explicit scope-limited inheritance.
- **REASON:** Prevents ambiguous "AI learning" claims and prevents single-asset decisions from creating unassisted global or wildcard rules.
- **ALTERNATIVES:** Autonomous AI learning / unconstrained rule propagation.
- **CONSEQUENCES:** V1 decision memory remains 100% deterministic, explainable, and auditable.
- **DATE:** 2026-08-27

### DECISION 005: Dual-Layer Scanner Validation & DNS TOCTOU Defense
- **DECISION:** Enforce strict separation between Target Authorization (Domain DNS TXT verification) and Network Destination Safety (IP egress validation). Implement DNS TOCTOU rebinding protection by resolving DNS first and passing validated IP directly to socket APIs. Validate all HTTP redirect hops.
- **REASON:** Domain ownership verification does NOT grant permission to scan private IPs, loopback, or cloud metadata endpoints (`169.254.169.254`).
- **ALTERNATIVES:** Naive HTTP client library redirect following.
- **CONSEQUENCES:** Scanner workers prevent SSRF and DNS rebinding attacks at the socket layer.
- **DATE:** 2026-08-27

### DECISION 007: Modular Monolith Monorepo Structure (Phase J)
- **DECISION:** Organize the codebase into `apps/control-plane`, `apps/web-frontend`, `apps/scanner-worker`, and `packages/shared-contracts`.
- **REASON:** Maintains clean domain module separation inside a single deployable control plane while isolating scanner workers behind a distinct deployment and trust boundary.
- **ALTERNATIVES:** Microservices architecture; single mixed repository.
- **CONSEQUENCES:** Clean trust boundaries; simple local development; future service extraction points preserved.
- **DATE:** 2026-08-27

### DECISION 009: Data-Contracts-Only Rule for Shared Packages (Phase J Hardening)
- **DECISION:** Explicitly restrict `packages/shared-contracts` to pure Data Transfer Objects (DTOs), versioned event payload schemas (`schema_version: "1.0"`), shared enums, and serialization contracts.
- **REASON:** Prevents business logic, database models, repositories, or scanner code from leaking into shared contracts. Ensures framework-independent, dependency-light shared interfaces.
- **ALTERNATIVES:** Shared domain logic library across frontend/backend/worker.
- **CONSEQUENCES:** Clean decoupling; pure type definitions; zero framework lock-in.
- **DATE:** 2026-08-27

### DECISION 011: Phase 0 Foundation Execution (Phase 0)
- **DECISION:** Built foundational modular-monolith monorepo: `apps/control-plane`, `apps/web-frontend`, `apps/scanner-worker`, `packages/shared-contracts`, `tests/`, `infrastructure/`.
- **REASON:** Establishes secure, multi-tenant backend foundation with structlog, security headers middleware, async SQLAlchemy + Alembic, async Redis client, Next.js App Router UI shell, and worker safety sandbox.
- **ALTERNATIVES:** Microservices architecture; monolithic mixed repo.
- **CONSEQUENCES:** Clean domain module boundaries; zero scanner worker access to control-plane DB; passing security test suite.
- **DATE:** 2026-08-27

---

## 2. Product Discoveries & Market Insights

- **Market Trend (2026):** EASM is consolidating into Continuous Threat Exposure Management (CTEM) and Exposure Assessment Platforms. Pure asset listing is commoditized.
- **Key Differentiation:** Competitors excel at internet-wide raw data (Censys, Shodan) or automated penetration testing (Hadrian, CyCognito), but lack *organizational context memory* (ownership, expected state, decision audit history).
- **Core Wedge:** Context-aware change intelligence + decision memory.

---

## 3. Rejected Approaches

- **REJECTED:** Autonomous exploit payload execution in V1. (Deferred to ARES integration in V2+ to avoid security and liability risks).
- **REJECTED:** Seedless discovery in V1. (Requires heavy ML infrastructure; domain-seeded discovery is sufficient for V1 target ICP).
- **REJECTED:** In-process scanning inside the main API server. (Violates trust boundary; scanner workers must be isolated).
- **REJECTED:** Automatic global/wildcard rule generation from single-asset decisions. (Violates scope-limited inheritance safety invariant).
- **REJECTED:** Microservices architecture for control plane in V1. (Premature complexity; modular monolith handles initial scale cleanly).
- **REJECTED:** Placing business or database logic inside `packages/shared-contracts`. (Violates clean data contracts boundary).

---

## 4. Unresolved Questions & Technical Debt

- **QUESTION:** Optimal scan frequency default for V1 (Daily vs Hourly). *Currently assumed Daily default with manual trigger.*
- **QUESTION:** Strategy for handling shared CDN/Anycast IP attribution. *Currently assumed hostnames map to CDN IPs, but IP ownership is flagged as shared.*
