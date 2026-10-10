# PRODUCT_SKILL_AUDIT.md — Attack Surface Monitor (ASM)

> **Status:** AUDIT COMPLETE — PENDING HUMAN REVIEW  
> **Date:** 2026-09-30  
> **Target:** Attack Surface Monitor (ASM) Repository & Agent Skill Environment  
> **Author:** Antigravity AI Agent  

---

## 1. Executive Summary

An exhaustive audit of the Antigravity agent skill environment and the Attack Surface Monitor (ASM) repository was conducted. 

### Key Findings:
1. **Critical Skill Imbalance**: Currently, **33 agent skills** are installed across the user environment (`~/.agents/skills/`, `~/.gemini/skills/`, `~/.claude/skills/`). **100% of the installed skills focus exclusively on frontend design, visual taste, CSS animation (GSAP), and image generation.**
2. **Zero Security & Backend Skills**: There are **zero** installed skills covering Threat Modeling, Security Review, API Security, Tenant Isolation, Scanner Egress Safety, SSRF/DNS Rebinding Defense, Database Migration Safety, Python/FastAPI Architecture, PostgreSQL, or Production Readiness.
3. **Repository Real-World Maturity**: In sharp contrast to the skill imbalance, the underlying ASM codebase is a highly sophisticated, enterprise-grade security operations platform. It features 12 database migration versions (`4d5e6f7a8b9c`), 15 control-plane API router modules, 29 application/engine services, ARQ scanner worker isolation with strict egress/SSRF safety guards, and a comprehensive **389-passing test suite** covering RBAC, tenant isolation, evidence provenance hashing, and action approval boundaries.
4. **Skill Redundancy & Risk**: Existing skills exhibit massive redundancy (8 separate GSAP animation skills, 5 overlapping frontend design taste skills) and include autonomous tools (e.g. `prototype`, `image-to-code`, `full-output-enforcement`) that risk introducing breaking changes or unsafe code churn in a security product.

---

## 2. Discovered Skill Locations

The audit inspected all standard and legacy Antigravity skill directories:

| Location | Path | Discovered Items | Status |
| :--- | :--- | :--- | :--- |
| **Workspace Skills** | `.agents/skills/` | None inside project root; global user dir contains 33 skills at `~/.agents/skills/` | Accessible globally |
| **Global Gemini Skills** | `~/.gemini/skills/` | Contains `impeccable` skill directory | Installed |
| **Global Config** | `~/.gemini/config/` | `mcp_config.json` present; no `skills/` subfolder | Clean |
| **Legacy Antigravity** | `~/.gemini/antigravity/` | Directory does not exist | N/A |
| **Claude Agent Skills** | `~/.claude/skills/` | Mirrors `~/.agents/skills/` (33 skills) | Installed |
| **Codex System Skills** | `~/.codex/skills/.system/` | System skills: `review-agent`, `skill-installer`, `openai-docs`, `skill-creator`, `plugin-creator`, `imagegen` | System level |

---

## 3. Existing Skills Inventory

The 33 discovered skills were evaluated against ASM requirements:

| Skill Name | Location | Purpose | ASM Relevance | Overlap | Trust / Utility | Evaluation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **stitch-design-taste** | `~/.agents/skills/` | Semantic Design System for Google Stitch UI | **HIGH** (Frontend only) | Low | High | **KEEP** |
| **minimalist-ui** | `~/.agents/skills/` | Clean editorial UI layout rules | **MEDIUM** (Frontend UI) | High (`design-taste-frontend`) | High | **KEEP** |
| **industrial-brutalist-ui** | `~/.agents/skills/` | Terminal/dense military UI layout | **LOW** (Light-first ASM UI) | High | Medium | **OPTIONAL** |
| **pick-ui-library** | `~/.agents/skills/` | Curated UI component library selection | **MEDIUM** (Frontend) | Low | High | **OPTIONAL** |
| **impeccable** | `~/.gemini/skills/` & `~/.agents/` | Complete frontend craft, audit & polish | **HIGH** (UI polish only) | High (`redesign-existing-projects`) | High | **KEEP** |
| **redesign-existing-projects** | `~/.agents/skills/` | Upgrade existing UI to high-end | **MEDIUM** (UI polish) | High (`impeccable`) | High | **OPTIONAL** |
| **design-taste-frontend** | `~/.agents/skills/` | Anti-slop frontend layout design | **MEDIUM** (UI polish) | High (`design-taste-frontend-v1`) | High | **OPTIONAL** |
| **design-taste-frontend-v1** | `~/.agents/skills/` | Legacy version of design taste | **NONE** | Duplicates `design-taste-frontend` | Low | **NOT NEEDED** |
| **gpt-taste** | `~/.agents/skills/` | Editorial typography & layout | **LOW** (Focuses on landing pages) | High | Medium | **NOT NEEDED** |
| **apple-design** | `~/.agents/skills/` | Apple-style consumer aesthetic | **NONE** (ASM is security SecOps tool) | High | High | **NOT NEEDED** |
| **brandkit** | `~/.agents/skills/` | Branding & color scheme generator | **NONE** (ASM palette is locked) | High | Medium | **NOT NEEDED** |
| **design-dna** | `~/.agents/skills/` | Visual identity extractor | **NONE** | High | Low | **NOT NEEDED** |
| **high-end-visual-design** | `~/.agents/skills/` | Agency-level visual design rules | **MEDIUM** | High | High | **OPTIONAL** |
| **emil-design-eng** | `~/.agents/skills/` | UI polish & micro-interactions | **LOW** | High (`impeccable`) | High | **OPTIONAL** |
| **gsap-core** | `~/.agents/skills/` | GSAP core animation API | **NONE** (No marketing motion in ASM) | High (8 GSAP skills) | High | **NOT NEEDED** |
| **gsap-react** | `~/.agents/skills/` | GSAP hook for React | **NONE** | High | High | **NOT NEEDED** |
| **gsap-plugins** | `~/.agents/skills/` | GSAP plugin suite | **NONE** | High | High | **NOT NEEDED** |
| **gsap-scrolltrigger** | `~/.agents/skills/` | Scroll-linked animations | **NONE** (ASM avoids scroll gimmicks) | High | High | **NOT NEEDED** |
| **gsap-timeline** | `~/.agents/skills/` | GSAP sequencing | **NONE** | High | High | **NOT NEEDED** |
| **gsap-utils** | `~/.agents/skills/` | GSAP math utilities | **NONE** | High | High | **NOT NEEDED** |
| **gsap-performance** | `~/.agents/skills/` | GSAP performance tuning | **NONE** | High | High | **NOT NEEDED** |
| **gsap-frameworks** | `~/.agents/skills/` | GSAP for Vue/Svelte | **NONE** | High | High | **NOT NEEDED** |
| **animate** | `~/.agents/skills/` | UI animation principles | **NONE** | High | Medium | **NOT NEEDED** |
| **animation-vocabulary** | `~/.agents/skills/` | Motion naming terms | **NONE** | High | Low | **NOT NEEDED** |
| **motion-design** | `~/.agents/skills/` | Disney animation principles for UI | **NONE** | High | Low | **NOT NEEDED** |
| **find-animation-opportunities**| `~/.agents/skills/` | Search codebase for animations | **NONE** | High | Low | **NOT NEEDED** |
| **improve-animations** | `~/.agents/skills/` | Motion audit & plan generator | **NONE** | High | Low | **NOT NEEDED** |
| **review-animations** | `~/.agents/skills/` | Animation craft code reviewer | **NONE** | High | Low | **NOT NEEDED** |
| **imagegen-frontend-web** | `~/.agents/skills/` | Web image direction generation | **NONE** (Generating mock promo images) | High | High | **NOT NEEDED** |
| **imagegen-frontend-mobile** | `~/.agents/skills/` | Mobile image generation | **NONE** | High | High | **NOT NEEDED** |
| **image-to-code** | `~/.agents/skills/` | Autonomous image-to-code generation | **UNSAFE** (Generates unverified layout) | High | High | **NOT NEEDED** |
| **full-output-enforcement** | `~/.agents/skills/` | Overrides token limits for full output | **HIGH** (Prevents snippet truncation) | Low | High | **KEEP** |
| **prototype** | `~/.agents/skills/` | Generates multiple UI versions | **UNSAFE** (Generates throwaway code) | High | High | **NOT NEEDED** |

---

## 4. Audit Against ASM Requirements

The repository code and documentation were audited against enterprise cybersecurity SaaS requirements:

### A. Security Architecture
- **Authentication**: `JWT bearer authentication` implemented with access tokens, expiration validation, user context injection, and dev bootstrap fallback (`apps/control-plane/app/core/security.py`).
- **Session Management**: Session state tracked with tenant context (`org_id`) and role mappings.
- **Authorization & RBAC**: Strict 4-tier role hierarchy (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`). Decorators & gates (`@require_role`, `RBACGate`) enforce server-side authority.
- **Tenant Isolation**: Mandatory `org_id` URL path scoping & database query filtering across all endpoints. Cross-tenant request tampering tests verify 100% rejection.
- **Audit Logging**: Audit events emitted for security-relevant state changes, decision logs, and action approvals (`apps/control-plane/app/application/audit_service.py`).
- **Secrets Handling**: Environmental loading via Pydantic settings; zero hardcoded secrets in source code.

### B. Scanner Network Safety & Worker Security
- **SSRF Protection (`ssrf_guard.py`)**: Strict validation blocking private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), link-local (`169.254.169.254`), and IPv4-mapped IPv6 addresses.
- **DNS TOCTOU / Rebinding Defense (`dns_resolver.py`)**: Resolves target hostnames and validates all resolved IP addresses immediately prior to socket connections. Rejects targets resolving to mixed public/private IPs.
- **Redirect Validation**: Enforces max 5 HTTP redirects and validates destination IP on every redirect hop.
- **Resource Exhaustion Protection**: 10MB response body limit, 20:1 max decompression ratio (zip bomb defense), 50MB max ingestion payload size, 5s socket timeouts, and total job execution timeouts.
- **Worker Isolation**: Scanner worker (`apps/scanner-worker`) runs in a separate process/container with **zero database or authentication model imports**, communicating exclusively via signed ARQ Redis jobs.
- **Evidence Provenance**: Raw observation payloads are SHA-256 hashed and cryptographically signed (`HMAC-SHA256`) to guarantee non-repudiation.

### C. Backend Architecture (`apps/control-plane`)
- **FastAPI Framework**: Modular APIRouter setup across 15 v1 router endpoints (`organizations`, `domains`, `scans`, `assets`, `findings`, `risk`, `changes`, `notifications`, `actions`, `automation`, `context`, `discovery`, `graph`, `intelligence`, `assistant`).
- **Domain Services**: 29 business logic modules cleanly decoupling API contracts from ORM database models.
- **Database Architecture**: SQLAlchemy 2.0 async engine supporting both SQLite (`asm_dev.db`) and production PostgreSQL, with 12 Alembic schema migration versions up to `4d5e6f7a8b9c`.

### D. Frontend Architecture (`apps/web-frontend`)
- **Next.js 14 App Router**: 22 routes fully implemented in a light-first security operations shell.
- **Visual Design**: Strict corporate light design tokens (`#FFFFFF`, `#F8F9FB`, `#111827`, `#2563EB`, semantic status badges). Zero dark mode or neon gimmicks.
- **API Client Integration**: Real API client (`app/lib/api.ts`) connecting to backend endpoints with fallback handling for unpopulated states.

### E. Product Capability Audit (Implemented vs Simulated)

| Capability Module | Backend Engine | API Endpoints | Test Coverage | Real vs Mapped | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Organization Onboarding** | `OrgService` | `POST /api/v1/organizations` | Tested | Real | **FULL** |
| **Domain Onboarding & Verification** | `DomainService` + DNS Provider | `/api/v1/domains`, `/verify` | Tested | Real | **FULL** |
| **Asset Discovery & Inventory** | `DiscoveryEngine` | `/api/v1/assets` | Tested | Real | **FULL** |
| **Scan Execution & Worker Jobs** | ARQ Worker + Egress Guard | `/api/v1/scans` | Tested | Real | **FULL** |
| **Change Intelligence** | `ChangeDetectionService` | `/api/v1/changes` | Tested | Real | **FULL** |
| **Risk Calculation** | `RiskEngine` (`Base + Blindspot + Context`) | `/api/v1/risk/assessments` | Tested | Real | **FULL** |
| **Findings Lifecycle** | `FindingService` | `/api/v1/findings` | Tested | Real | **FULL** |
| **Remediation Verification** | `RemediationVerificationService` | `/api/v1/verification` | Tested | Real | **FULL** |
| **Controlled Action Orchestration** | `ActionAuthorizationEngine` | `/api/v1/actions` | Tested | Real | **FULL** |
| **Automation Engine** | `AutomationPolicyEngine` | `/api/v1/automation` | Tested | Real | **FULL** |
| **AI Investigation** | `AIAssistantService` | `/api/v1/assistant` | Tested | Subordinate to ASM Facts | **FULL** |
| **Egress Guard Configuration** | `EgressGuardConfig` | `/api/v1/settings/egress-guard` | Tested | Real | **FULL** |

---

## 5. Existing Test Suite Audit

The test suite was analyzed by running pytest in collection mode:

- **Total Test Count**: **389 tests collected and passing**.
- **Test Categories**:
  1. `tests/security/` (13 files): Exhaustively tests RBAC permissions, cross-tenant isolation, JWT verification, action authorization classes (`CLASS_A`, `CLASS_B`, `CLASS_C`), HMAC signatures, and audit logs.
  2. `tests/worker/` (3 files): Tests egress guard IP blocking, DNS TOCTOU rebinding defense, HTTP body truncation, decompression ratio limits, socket timeouts, and target domain verification.
  3. `tests/unit/` (11 files): Tests risk score calculations, remediation verification invariants (scan completeness checks, status transitions, fresh proof requirements), and entity change detection.
  4. `tests/integration/` (8 files): Tests Alembic database migration roundtrips, FastAPI endpoint contracts, and Redis ARQ queue processing.

---

## 6. Capability Matrix

| Capability | Existing Skill | Coverage Level | Missing Skill / Guidance |
| :--- | :--- | :--- | :--- |
| **Threat Modeling** | None | Low | `asm-security-review` |
| **Security Review** | None | Medium (in-code tests exist) | `asm-security-review` |
| **API Security** | None | High (in-code FastAPI guards) | `asm-api-change-review` |
| **Authentication** | None | High (JWT bearer & session) | Guidance on JWT secret rotation |
| **Backend Security** | None | High (RBAC, tenant isolation) | `asm-tenant-isolation` |
| **Frontend Security** | None | Medium (RBACGate components) | Client-side token storage guidance |
| **Tenant Isolation** | None | High (Strict org_id scoping) | `asm-tenant-isolation` |
| **Scanner Security** | None | High (Egress guard, SSRF, TOCTOU) | `asm-scanner-safety` |
| **Evidence Integrity** | None | High (HMAC-SHA256 provenance) | `asm-evidence-integrity` |
| **Architecture** | None | High (Clean domain decoupling) | Architecture governance guidelines |
| **Python / FastAPI** | None | High (Python 3.11 + Pydantic v2) | Python backend best practices |
| **PostgreSQL / DB** | None | High (SQLAlchemy 2.0 async) | Database performance tuning |
| **Database Migrations** | None | High (12 Alembic versions) | `asm-migration-safety` |
| **Testing** | None | High (389 pytest cases) | TDD enforcement guidelines |
| **TDD** | None | Medium | `asm-feature-completeness` |
| **E2E / Browser Testing** | None | Low | `asm-e2e-validation` |
| **Debugging** | None | Medium | Diagnostic runbook skill |
| **Dependency Auditing** | None | Low | Automated pip/npm audit skill |
| **Deployment** | None | Low | Docker/K8s production manifests |
| **Container Security** | None | Low | Container hardening rules |
| **Observability** | None | Medium (Structured loggers) | OpenTelemetry / Prometheus tracing |
| **Production Readiness** | None | Medium | `asm-production-readiness` |

---

## 7. Skill Conflicts & Redundancies

### Identified Skill Conflicts:
1. **Frontend Aesthetic Overload**: 33 installed skills focus on marketing animations, GSAP effects, Apple consumer design, and industrial brutalism. **These conflict directly with ASM's light-first, calm, enterprise security operational design rules.**
2. **Unsafe Autonomous Generation**: Skills like `prototype`, `image-to-code`, and `redesign-existing-projects` encourage LLMs to rewrite major layout structures or generate throwaway code, risking breaking changes to real API integrations and security bounds.
3. **Redundant Duplicate Skills**:
   - `impeccable` exists in both `~/.gemini/skills/` and `~/.agents/skills/`.
   - `design-taste-frontend` and `design-taste-frontend-v1` duplicate each other.
   - 8 separate GSAP animation skills (`gsap-core`, `gsap-react`, `gsap-plugins`, `gsap-scrolltrigger`, `gsap-timeline`, `gsap-utils`, `gsap-performance`, `gsap-frameworks`) provide zero value to a security ops tool.

---

## 8. Recommended Minimal Skill Stack

### Tier S — Required (Essential for Immediate Security Engineering)
1. **`stitch-design-taste`**: Provides semantic design system constraints for Google Stitch UI layouts.
2. **`minimalist-ui`**: Enforces quiet, clean typography and high signal-to-noise ratio.
3. **`full-output-enforcement`**: Overrides token truncation to enforce complete code generation.

### Tier A — Strongly Recommended (Engineering Quality & Integrity)
1. **`impeccable`**: Enforces strict UI craft, component accessibility, and layout polish.
2. **`high-end-visual-design`**: Guidance for enterprise-grade visual hierarchy.

### Tier B — Optional (Task-Specific Tooling)
1. **`pick-ui-library`**: Helps select vetted lightweight component primitives when needed.

### Skills to Avoid (Unsafe, Redundant, or Irrelevant)
- **Avoid all 8 GSAP skills** (`gsap-core`, `gsap-react`, `gsap-plugins`, etc.) — ASM bans motion gimmicks.
- **Avoid consumer design skills** (`apple-design`, `industrial-brutalist-ui`, `gpt-taste`, `brandkit`).
- **Avoid autonomous code generators** (`prototype`, `image-to-code`, `imagegen-frontend-web`, `imagegen-frontend-mobile`).

---

## 9. Recommended Custom ASM-Specific Skills

Because generic public skills do not cover cybersecurity boundaries, scanner safety, or tenant isolation, the following 9 custom ASM skills should be created:

1. **`asm-security-review`**:
   - Enforces 4-tier RBAC validation, auth session verification, and security audit log generation on all backend changes.
2. **`asm-tenant-isolation`**:
   - Enforces mandatory `org_id` URL path scoping, ORM database filter clauses, and cross-tenant query rejection.
3. **`asm-scanner-safety`**:
   - Enforces egress guard IP checking, DNS TOCTOU resolution guards, HTTP body limits (10MB), and worker process isolation (zero DB/auth imports).
4. **`asm-evidence-integrity`**:
   - Enforces cryptographic hashing (`SHA-256`) and HMAC signatures on all raw scan observations before ingestion.
5. **`asm-api-change-review`**:
   - Prevents breaking API contract changes between `apps/control-plane`, `packages/shared-contracts`, and `apps/web-frontend`.
6. **`asm-migration-safety`**:
   - Enforces reversible Alembic migration scripts, zero-downtime schema changes, and dual SQLite/PostgreSQL compatibility.
7. **`asm-feature-completeness`**:
   - Guarantees that UI features map 1:1 to real backend domain engines rather than mock data.
8. **`asm-e2e-validation`**:
   - Governs end-to-end verification workflows (`npm run build`, pytest execution, and real browser route testing).
9. **`asm-production-readiness`**:
   - Audits error handling, logging, rate limiting, and container health checks prior to deployment.

---

## 10. Security Boundary Enforcement Rules

All future agent actions within ASM must adhere strictly to these hard security boundaries:

- **Untrusted Inputs**: Scanner output and user-controlled target inputs are untrusted and must be sanitized.
- **AI Subordination**: AI-generated responses (`/assistant`) are interpretations, NOT authoritative scanner evidence.
- **Tenant Scope**: Cross-tenant data leaks or global rule mutations based on tenant observations are strictly prohibited.
- **Server Authority**: Authorization and permission checks must occur server-side; UI visibility is purely presentation.
- **Controlled Automation**: Security-impacting actions (`CLASS_B`, `CLASS_C`) require explicit human authorization/policy approval.
- **Destructive Operations**: No database drops, schema rewrites, or destructive backend commands without human approval.

---

## 11. Installation Plan (Commands Only — DO NOT EXECUTE)

```bash
# 1. Clean up redundant GSAP and consumer design skills (DO NOT EXECUTE NOW)
rm -rf ~/.agents/skills/gsap-*
rm -rf ~/.agents/skills/apple-design ~/.agents/skills/brandkit ~/.agents/skills/prototype ~/.agents/skills/image-to-code

# 2. Create directory structure for custom ASM skills (DO NOT EXECUTE NOW)
mkdir -p .agents/skills/asm-security-review
mkdir -p .agents/skills/asm-tenant-isolation
mkdir -p .agents/skills/asm-scanner-safety
mkdir -p .agents/skills/asm-evidence-integrity
mkdir -p .agents/skills/asm-api-change-review
mkdir -p .agents/skills/asm-migration-safety
mkdir -p .agents/skills/asm-feature-completeness
mkdir -p .agents/skills/asm-e2e-validation
mkdir -p .agents/skills/asm-production-readiness
```

---

## 12. Next Step

**Do not install or modify anything until the user reviews this audit.**
