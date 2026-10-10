# Attack Surface Monitor — Implementation Plan

> **Status:** DRAFT — Execution Plan (No Code Phase)
> **Last Updated:** 2026-08-27
> **Parent Document:** All Prior Documentation Set
> **Document Type:** Structured Engineering Task Breakdown & Release Plan

---

## 1. Implementation Philosophy

This plan outlines the sequential engineering phases required to build the Attack Surface Monitor.

- **NO CODE RULE:** This document details implementation tasks but DOES NOT write source code or create codebase folders during the documentation phase.
- **Phase-Gated Execution:** Phase 0 (Foundation) must complete and pass all security gates before Phase 1 (V1 Product) begins.
- **Test-Driven Security:** Security tests and tenant isolation assertions are written alongside feature logic.

---

## 2. Phase 0 — Foundation Implementation Plan

### Group 0.1: Project Setup & Core Infrastructure
- [ ] Task 0.1.1: Design final application folder structure (Deferred to post-doc approval).
- [ ] Task 0.1.2: Configure `docker-compose.yml` for local development (PostgreSQL 16, Redis 7, MinIO, MailHog).
- [ ] Task 0.1.3: Initialize FastAPI backend framework with Pydantic v2 settings & CORS configuration.
- [ ] Task 0.1.4: Initialize Next.js App Router frontend with TypeScript, Radix UI primitives, and CSS modules.
- [ ] Task 0.1.5: Setup Alembic database migration environment.

### Group 0.2: Database & Identity Core
- [ ] Task 0.2.1: Implement SQLAlchemy schemas for `organizations`, `users`, `memberships`, `sessions`.
- [ ] Task 0.2.2: Implement password hashing utilities using `bcrypt` (work factor 12).
- [ ] Task 0.2.3: Build session management service (opaque token generation, storage, validation, revocation).
- [ ] Task 0.2.4: Implement TOTP MFA utilities (`pyotp`, recovery code generation, AES secret encryption).
- [ ] Task 0.2.5: Implement append-only `audit_events` logging module.

### Group 0.3: API & Authentication Endpoints
- [ ] Task 0.3.1: Build `POST /api/v1/auth/register` with email verification token generation.
- [ ] Task 0.3.2: Build `POST /api/v1/auth/verify-email` endpoint.
- [ ] Task 0.3.3: Build `POST /api/v1/auth/login` with brute-force rate limiting and MFA challenge logic.
- [ ] Task 0.3.4: Build `POST /api/v1/auth/mfa/enroll` and `verify` endpoints.
- [ ] Task 0.3.5: Build `POST /api/v1/auth/logout` and session revocation endpoints.
- [ ] Task 0.3.6: Build `POST /api/v1/auth/password-reset` request & confirm endpoints.

### Group 0.4: Authorization & Tenant Isolation
- [ ] Task 0.4.1: Implement FastAPI HTTP Bearer / Cookie authentication middleware.
- [ ] Task 0.4.2: Implement tenant context middleware to extract and enforce `org_id`.
- [ ] Task 0.4.3: Implement RBAC authorization dependency (`require_role('owner'|'admin'|'member'|'viewer')`).
- [ ] Task 0.4.4: Write comprehensive security test suite for auth bypass and cross-tenant isolation.

---

## 3. Phase 1 — V1 Core Feature Implementation Plan

### Group 1.1: Domain Management & Verification
- [ ] Task 1.1.1: Implement `domains` database schema and API endpoints (`POST`, `GET`, `DELETE`).
- [ ] Task 1.1.2: Build DNS TXT record verification service (`dnspython` integration).
- [ ] Task 1.1.3: Build periodic domain re-verification background task.

### Group 1.2: Scanner Worker & Job Queue Infrastructure
- [ ] Task 1.2.1: Configure Redis-backed `arq` job queue worker pool.
- [ ] Task 1.2.2: Implement worker security sandbox (private IP blocking, 169.254.169.254 egress filtering, target allowlist check).
- [ ] Task 1.2.3: Build Subdomain Discovery worker module (CT logs `crt.sh`, DNS wordlist brute-forcing).
- [ ] Task 1.2.4: Build DNS Resolution & IP tracking worker module.
- [ ] Task 1.2.5: Build Service/Port Discovery worker module (Top 1,000 TCP connect scanner).
- [ ] Task 1.2.6: Build TLS Certificate Extraction worker module.
- [ ] Task 1.2.7: Build Technology Identification worker module (header & content signature matching).

### Group 1.3: Data Resolution & Asset Inventory
- [ ] Task 1.3.1: Implement `assets` and `asset_relationships` database schemas.
- [ ] Task 1.3.2: Build Asset Resolution Engine to ingest worker payloads and merge deduplicated assets.
- [ ] Task 1.3.3: Build Asset Explorer API endpoints (`GET /assets`, `GET /assets/{id}`, `PATCH /assets/{id}`).
- [ ] Task 1.3.4: Build organizational context endpoints (assign owner, environment, criticality, expected state).

### Group 1.4: Change Detection & Risk Engine
- [ ] Task 1.4.1: Implement `scans`, `observations`, and `changes` database schemas.
- [ ] Task 1.4.2: Build Change Detection Engine (scan-over-scan comparison logic).
- [ ] Task 1.4.3: Build Risk Engine to calculate `contextual_risk_score` based on asset metadata and finding severity.
- [ ] Task 1.4.4: Implement `findings` and `evidence` schemas and API endpoints.

### Group 1.5: Human Decisions & Remediation Verification
- [ ] Task 1.5.1: Implement `decisions` schema and API endpoints (`accept_risk`, `false_positive`, `mark_expected`).
- [ ] Task 1.5.2: Build decision suppression logic in Change & Risk engines.
- [ ] Task 1.5.3: Implement `verifications` schema and manual re-check trigger API.

### Group 1.6: Frontend User Experience
- [ ] Task 1.6.1: Build Auth UI (Login, Register, MFA Enroll, Password Reset).
- [ ] Task 1.6.2: Build Onboarding UI (Domain addition & DNS TXT verification wizard).
- [ ] Task 1.6.3: Build Dashboard UI (Posture metrics, recent change feed, top findings).
- [ ] Task 1.6.4: Build Asset Explorer UI (Filterable data table, asset detail drawer, relationship tree).
- [ ] Task 1.6.5: Build Findings & Decision UI (Finding detail drawer, risk acceptance modal, evidence view).

---

## 4. Phase Release & Verification Criteria

| Phase Gate | Verification Steps | Required Approvals |
|---|---|---|
| **Phase 0 Gate** | Pass all Security Gates in `SecurityChecklist.md`. 100% test pass on Auth & RBAC. | Lead Architect & Security Lead |
| **Phase 1 Alpha Gate**| Successful end-to-end domain verification and scan discovery against staging domain. | Lead Engineer |
| **Phase 1 Beta Gate** | Change detection correctly flags new port/subdomain in 2nd scan; decision memory suppresses accepted risk. | Product Lead |
| **Phase 1 GA Gate** | Final consistency audit pass; load test 10,000 assets; zero security regressions. | Full Senior Team |
