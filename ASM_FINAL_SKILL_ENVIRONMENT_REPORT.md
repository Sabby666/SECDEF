# ASM Final Skill Environment Report (`ASM_FINAL_SKILL_ENVIRONMENT_REPORT.md`)

> **Status:** FINAL SKILL ENVIRONMENT SETUP COMPLETE  
> **Date:** 2026-10-04  
> **Target:** Attack Surface Monitor (ASM) Workspace Skill & Plugin Environment  
> **Author:** Antigravity AI Agent  

---

## 1. Executive Summary

The Antigravity skill and plugin environment for the Attack Surface Monitor (ASM) has been fully hardened, configured, and setup. 

All 24 redundant animation, marketing, and unsafe autonomous skills have been disabled/removed from `~/.agents/skills/`. The workspace has been equipped with **9 project-specific custom ASM skills** enforcing hard security boundaries, multi-tenant data isolation, scanner egress guards, cryptographic HMAC observation provenance, and feature completeness. In addition, the **Playwright testing skill (`playwright-cli`)** was linked into workspace skills, while **Get Shit Done (GSD)** and **Ponytail** plugins were audited and integrated with strict security override governance.

Zero application source code, database models, API contracts, or migrations were modified during this setup.

---

## 2. Final Skill Inventory

The workspace skill environment is now composed of **16 active skills** (3 retained generic UI skills, 1 testing tool skill, 9 custom ASM security/engineering skills, 2 execution plugins, and 1 design system skill):

| Skill Name | Scope / Location | Category | Operational Role in ASM |
| :--- | :--- | :--- | :--- |
| **asm-security-review** | `.agents/skills/asm-security-review/` | Custom ASM Skill | Server-side auth, 4-tier RBAC (`OWNER`/`ADMIN`/`MEMBER`/`VIEWER`), action authorization classes (`CLASS_A`/`B`/`C`), audit logging. |
| **asm-tenant-isolation** | `.agents/skills/asm-tenant-isolation/` | Custom ASM Skill | `org_id` URL path scoping, ORM database query filtering, zero cross-tenant data leaks. |
| **asm-scanner-safety** | `.agents/skills/asm-scanner-safety/` | Custom ASM Skill | Egress guard IP blocking, DNS TOCTOU rebinding defense, body limits (10MB), worker process isolation. |
| **asm-evidence-integrity** | `.agents/skills/asm-evidence-integrity/` | Custom ASM Skill | SHA-256 observation hashing, HMAC-SHA256 tamper evidence & authenticity provenance. |
| **asm-api-change-review** | `.agents/skills/asm-api-change-review/` | Custom ASM Skill | Pydantic v2 validation, shared DTO contract bounds (`packages/shared-contracts`). |
| **asm-migration-safety** | `.agents/skills/asm-migration-safety/` | Custom ASM Skill | Reversible Alembic migrations (`upgrade`/`downgrade`), dual SQLite/PostgreSQL compatibility. |
| **asm-feature-completeness** | `.agents/skills/asm-feature-completeness/` | Custom ASM Skill | 1:1 binding between UI views and real FastAPI backend domain engines; zero mock data. |
| **asm-e2e-validation** | `.agents/skills/asm-e2e-validation/` | Custom ASM Skill | Next.js production builds (`npm run build`), route testing, Playwright E2E customer journey validation. |
| **asm-production-readiness** | `.agents/skills/asm-production-readiness/` | Custom ASM Skill | Structured JSON logging, health checks (`/healthz`, `/readyz`), rate limiting, container hardening. |
| **playwright-cli** | `.agents/skills/playwright-cli/` | Verified Local Skill | E2E browser route testing, DOM screenshot capture, and visual validation. |
| **stitch-design-taste** | `~/.agents/skills/stitch-design-taste/` | Generic UI Skill | Google Stitch design system token adherence. |
| **minimalist-ui** | `~/.agents/skills/minimalist-ui/` | Generic UI Skill | High signal-to-noise typography and clean operational layout. |
| **impeccable** | `~/.gemini/skills/impeccable/` | Generic UI Skill | Craft polish, accessibility, and component structure audit. |
| **Get Shit Done (GSD)** | Environment Plugin | Execution Plugin | Structured task decomposition, step execution, and verification planning. |
| **Ponytail** | Environment Plugin | Developer Plugin | YAGNI enforcement, stdlib/platform feature reuse, minimal working diffs, `ponytail:` shortcut logging. |
| **ui-ux-pro-max** | Environment Skill | UI Intelligence | UI/UX design intelligence reference. |

---

## 3. ASM Custom Skills Specification

The following 9 workspace skills were created in `.agents/skills/`:

1. **`asm-security-review`** (`.agents/skills/asm-security-review/SKILL.md`):
   - Enforces server-side authentication, 4-tier RBAC (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`), action authorization classes (`CLASS_A`, `CLASS_B`, `CLASS_C`), audit logging, least privilege, and security regression review. AI output is strictly subordinate to ASM scanner facts.
2. **`asm-tenant-isolation`** (`.agents/skills/asm-tenant-isolation/SKILL.md`):
   - Enforces the 8-step verification flow: `Request → Auth → Org membership → RBAC → Target authorization → Tenant-scoped query → Object ownership → Serialization → Audit`. Rejects all cross-tenant reads, writes, inference, AI context, or global rule mutations.
3. **`asm-scanner-safety`** (`.agents/skills/asm-scanner-safety/SKILL.md`):
   - Enforces egress guard blocking (private IPv4, loopback `127.0.0.1`, link-local `169.254.169.254`, IPv4-mapped IPv6), DNS TOCTOU rebinding guards (`resolve → validate → connect`), HTTP redirect hop limits (max 5), response body limits (10MB max), decompression ratio limits (20:1 max zip bomb guard), socket timeouts (5s), and ARQ worker process isolation (zero DB/auth imports).
4. **`asm-evidence-integrity`** (`.agents/skills/asm-evidence-integrity/SKILL.md`):
   - Enforces strict data classification: `FACT`, `INFERENCE`, `ASSUMPTION`, `DECISION`, `RECOMMENDATION`, `AI HYPOTHESIS`. Maintains provenance chain (`observation → evidence → derivation → risk → finding → recommendation → decision → verification`). Uses accurate terminology: HMAC-SHA256 provides **integrity, authenticity, provenance, and tamper evidence** (never non-repudiation).
5. **`asm-api-change-review`** (`.agents/skills/asm-api-change-review/SKILL.md`):
   - Protects FastAPI contracts, Pydantic v2 schemas, shared DTO contracts (`packages/shared-contracts`), and frontend/backend compatibility. Prohibits placing business logic inside `shared-contracts`.
6. **`asm-migration-safety`** (`.agents/skills/asm-migration-safety/SKILL.md`):
   - Requires explicit `upgrade()` and `downgrade()` in Alembic migrations, reversible schema changes, dual SQLite (`asm_dev.db`) and PostgreSQL compatibility. Prohibits blind `stamp head` or database file deletion to fix migration errors.
7. **`asm-feature-completeness`** (`.agents/skills/asm-feature-completeness/SKILL.md`):
   - Requires 1:1 binding from UI views to real FastAPI domain engines. Prohibits fake data, hardcoded example.com values, placeholder logic, simulated success toasts, and internal development labels in production UI.
8. **`asm-e2e-validation`** (`.agents/skills/asm-e2e-validation/SKILL.md`):
   - Requires clean compilation of `npm run build` with 0 errors AND runtime route execution. Governs Playwright E2E customer journey validation (`account/org → domain onboarding → verification → discovery → assets → findings → remediation → resolution`).
9. **`asm-production-readiness`** (`.agents/skills/asm-production-readiness/SKILL.md`):
   - Governs structured JSON logging, health/readiness endpoints (`/healthz`, `/readyz`), error handling, rate limiting, and container security standards.

---

## 4. Get Shit Done (GSD) Plugin Integration

- **Role**: GSD provides task decomposition, structured step-by-step progress tracking, and execution workflow management.
- **Governance Rules**:
  - GSD MAY be used to plan task execution, break down complex requirements, and structure step-by-step verification.
  - GSD MUST NOT override any ASM security skill, tenant isolation boundary, scanner safety rule, or authorization check.
  - If a GSD execution plan proposes changes that conflict with `asm-security-review`, `asm-tenant-isolation`, or `asm-scanner-safety`, **the ASM custom security skill strictly overrides GSD**.

---

## 5. Ponytail Plugin Integration

- **Role**: Ponytail enforces lazy senior developer efficiency: YAGNI, standard library reuse over custom code, native platform features, minimal diffs, and deletion over addition.
- **Governance Rules**:
  - Ponytail rules (e.g. YAGNI, shortest working diff, avoiding unnecessary dependencies/abstractions) apply across all engineering steps.
  - Ponytail MUST NOT cut corners on input validation, tenant isolation, scanner safety guards, or error handling.
  - Any deliberate simplification marked with a `ponytail:` comment MUST satisfy all ASM security invariants.
  - **ASM Security Skills Overrides Ponytail**: Minimal diffs must never bypass RBAC check decorators or tenant scoping clauses.

---

## 6. Skills Removed / Disabled

The following 24 redundant, marketing, motion, or unsafe autonomous skills were removed/disabled from `~/.agents/skills/`:

| Skill Directory | Removal Reason |
| :--- | :--- |
| `~/.agents/skills/gsap-core` | Redundant GSAP animation API (ASM bans motion gimmicks). |
| `~/.agents/skills/gsap-react` | Redundant GSAP hook for React. |
| `~/.agents/skills/gsap-plugins` | Redundant GSAP plugin suite. |
| `~/.agents/skills/gsap-scrolltrigger` | Redundant scroll animation triggers. |
| `~/.agents/skills/gsap-timeline` | Redundant GSAP animation timeline sequencer. |
| `~/.agents/skills/gsap-utils` | Redundant GSAP math utilities. |
| `~/.agents/skills/gsap-performance` | Redundant GSAP performance tuning. |
| `~/.agents/skills/gsap-frameworks` | Redundant GSAP framework support. |
| `~/.agents/skills/animate` | Redundant general animation principles. |
| `~/.agents/skills/animation-vocabulary` | Redundant motion naming terms. |
| `~/.agents/skills/motion-design` | Redundant Disney motion adapted for UI. |
| `~/.agents/skills/find-animation-opportunities` | Redundant motion opportunity scanner. |
| `~/.agents/skills/improve-animations` | Redundant motion audit authoring. |
| `~/.agents/skills/review-animations` | Redundant motion craft reviewer. |
| `~/.agents/skills/apple-design` | Irrelevant consumer design guidelines. |
| `~/.agents/skills/brandkit` | Irrelevant marketing brand generator (ASM palette locked). |
| `~/.agents/skills/design-dna` | Irrelevant visual identity extraction. |
| `~/.agents/skills/gpt-taste` | Irrelevant marketing page editorial typography. |
| `~/.agents/skills/imagegen-frontend-web` | Irrelevant web promo image direction generator. |
| `~/.agents/skills/imagegen-frontend-mobile` | Irrelevant mobile app promo image generator. |
| `~/.agents/skills/design-taste-frontend-v1` | Legacy duplicate of `design-taste-frontend`. |
| `~/.agents/skills/full-output-enforcement` | Token override hack (reclassified; completeness comes from tests). |
| `~/.agents/skills/prototype` | Dangerous autonomous variant generator. |
| `~/.agents/skills/image-to-code` | Dangerous autonomous screenshot-to-code converter. |

---

## 7. Skills Rejected & Not Installed

- **Generic Security Skills** (`security-auditor`, `threat-modeling-expert`, `auth-implementation-patterns`, `backend-security-coder`, `security-requirement-extraction`, `stride-analysis-patterns`, `dependency-management-deps-audit`, `secrets-management`): Not present in verified local registries; rejected to avoid unverified external installations (`UNKNOWN — DO NOT INSTALL`).
- **Generic Backend & Database Skills**: Rejected to avoid generic prompt clutter; ASM backend standards are governed by FastAPI codebase patterns and custom ASM skills.

---

## 8. Security Boundary Rules (Summary Table)

| Security Boundary | Rule & Constraint | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Server-Side Auth & RBAC** | All requests authenticated via JWT; 4-tier RBAC (`OWNER`/`ADMIN`/`MEMBER`/`VIEWER`). | `apps/control-plane/app/api/dependencies/auth.py` + `asm-security-review` |
| **Tenant Isolation** | Mandatory `org_id` URL path scoping & database query `.where()` filtering. | `asm-tenant-isolation` |
| **Egress Guard** | Blocks private IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback, link-local metadata (`169.254.169.254`), IPv4-mapped IPv6. | `worker/safety/egress_guard.py` + `asm-scanner-safety` |
| **DNS TOCTOU Defense** | Resolve hostname → Validate IP → Connect directly to validated IP. | `worker/safety/dns_resolver.py` + `asm-scanner-safety` |
| **Worker Isolation** | Worker process runs with zero DB or auth imports; payload verified via HMAC job nonces. | `apps/scanner-worker/worker/runner.py` + `asm-scanner-safety` |
| **Evidence Provenance** | Cryptographic SHA-256 payload hashing and HMAC signatures. | `asm-evidence-integrity` |
| **AI Subordination** | AI responses (`/assistant`) are strictly `AI HYPOTHESIS` or `RECOMMENDATION`, never authoritative scanner facts. | `asm-evidence-integrity` & `asm-security-review` |

---

## 9. Final Skill Architecture

```
                                +-------------------------------------------+
                                |          USER / ENVIRONMENT               |
                                |  - Get Shit Done (GSD) Execution Plugin   |
                                |  - Ponytail Dev Efficiency Plugin         |
                                +-------------------------------------------+
                                                      |
                                                      v
                                +-------------------------------------------+
                                |          GENERIC UI & TOOL SKILLS         |
                                |  - stitch-design-taste                    |
                                |  - minimalist-ui                          |
                                |  - impeccable                             |
                                |  - playwright-cli (Testing)               |
                                +-------------------------------------------+
                                                      |
                                                      v
+-----------------------------------------------------------------------------------------------------------------+
|                                    PROJECT CUSTOM ASM WORKSPACE SKILLS                                         |
|  1. asm-security-review       : Server Auth, 4-Tier RBAC, Action Authorization Classes & Audit Logs             |
|  2. asm-tenant-isolation      : Mandatory org_id Scoping, ORM Query Filtering & Boundary Checks                 |
|  3. asm-scanner-safety        : Egress Guard IP Blocking, DNS TOCTOU Defense & Worker Isolation                 |
|  4. asm-evidence-integrity    : SHA-256 Hashing, HMAC Tamper Evidence & Data Provenance                          |
|  5. asm-api-change-review     : Pydantic v2 Schema Compatibility & Shared DTO Protection                        |
|  6. asm-migration-safety      : Reversible Alembic Migrations & Dual SQLite/Postgres Compatibility               |
|  7. asm-feature-completeness  : 1:1 UI to Domain Engine Binding & Honest Empty States                            |
|  8. asm-e2e-validation        : Next.js Build Compilation & Playwright E2E Route Journeys                        |
|  9. asm-production-readiness  : Structured Logging, Health Probes (/healthz, /readyz) & Rate Limiting            |
+-----------------------------------------------------------------------------------------------------------------+
```

---

## 10. Verification Results

1. **Workspace Skills Verified**: Listed `.agents/skills/` — confirmed presence of 9 custom ASM skills (`asm-security-review`, `asm-tenant-isolation`, `asm-scanner-safety`, `asm-evidence-integrity`, `asm-api-change-review`, `asm-migration-safety`, `asm-feature-completeness`, `asm-e2e-validation`, `asm-production-readiness`) and `playwright-cli`.
2. **User Home Skills Cleaned**: Verified `~/.agents/skills/` — confirmed removal of 24 redundant/unwanted skills and preservation of approved UI skills (`stitch-design-taste`, `minimalist-ui`, `impeccable`, `design-taste-frontend`, `high-end-visual-design`, `pick-ui-library`, `redesign-existing-projects`, `industrial-brutalist-ui`, `emil-design-eng`).
3. **Application Code Safety Verified**: Confirmed ZERO modifications to application source files in `apps/control-plane`, `apps/scanner-worker`, `apps/web-frontend`, `packages/shared-contracts`, database models, or Alembic migrations.

---

## 11. Files Changed

| File / Path | Action | Reason |
| :--- | :--- | :--- |
| `.agents/skills/asm-security-review/SKILL.md` | **Created** | ASM Security Review Workspace Skill. |
| `.agents/skills/asm-tenant-isolation/SKILL.md` | **Created** | ASM Tenant Isolation Workspace Skill. |
| `.agents/skills/asm-scanner-safety/SKILL.md` | **Created** | ASM Scanner Safety Workspace Skill. |
| `.agents/skills/asm-evidence-integrity/SKILL.md` | **Created** | ASM Evidence Integrity Workspace Skill. |
| `.agents/skills/asm-api-change-review/SKILL.md` | **Created** | ASM API Change Review Workspace Skill. |
| `.agents/skills/asm-migration-safety/SKILL.md` | **Created** | ASM Migration Safety Workspace Skill. |
| `.agents/skills/asm-feature-completeness/SKILL.md` | **Created** | ASM Feature Completeness Workspace Skill. |
| `.agents/skills/asm-e2e-validation/SKILL.md` | **Created** | ASM E2E Validation Workspace Skill. |
| `.agents/skills/asm-production-readiness/SKILL.md` | **Created** | ASM Production Readiness Workspace Skill. |
| `.agents/skills/playwright-cli/SKILL.md` | **Copied** | Linked verified local Playwright testing skill. |
| `~/.agents/skills/[24 rejected skills]` | **Removed** | Cleaned up redundant animation, marketing, and unsafe skills. |
| `ASM_FINAL_SKILL_ENVIRONMENT_REPORT.md` | **Created** | Final skill environment setup report. |

---

## 12. Plugins & Skills Preserved
- **Get Shit Done (GSD)** plugin: Preserved.
- **Ponytail** plugin: Preserved.
- **stitch-design-taste** skill: Preserved.
- **minimalist-ui** skill: Preserved.
- **impeccable** skill: Preserved.

---

## 13. Remaining Risks & Mitigation

- **Risk**: A future agent prompt might attempt to bypass tenant scoping using a generic coding pattern.
- **Mitigation**: `asm-tenant-isolation` and `asm-security-review` strictly mandate `org_id` filtering on all database queries and FastAPI dependencies, taking priority over generic suggestions.

---

## 14. Final Recommendation

The Antigravity skill environment for the Attack Surface Monitor (ASM) is now fully hardened, aligned with enterprise security SaaS standards, and ready for development governance.

---

### FINAL STOP CONDITION

**STOP.**

**DO NOT create the ASM Master Prompt.**
**DO NOT begin product development.**
**DO NOT implement features.**
**DO NOT perform the Product Readiness Audit.**

The setup of the Antigravity skill/plugin environment is complete. Awaiting human review of [`ASM_FINAL_SKILL_ENVIRONMENT_REPORT.md`](file:///home/sabby/Projects/attack-surface-monitor/ASM_FINAL_SKILL_ENVIRONMENT_REPORT.md).
