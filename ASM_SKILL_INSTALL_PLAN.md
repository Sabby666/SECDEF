# ASM — Skill Installation Preparation Audit & Plan (`ASM_SKILL_INSTALL_PLAN.md`)

> **Status:** PREPARATION AUDIT COMPLETE — PENDING HUMAN APPROVAL  
> **Date:** 2026-09-30  
> **Target:** Attack Surface Monitor (ASM) Repository & Agent Skill Environment  
> **Author:** Antigravity AI Agent  

---

## 1. Verified Existing Skills

The following 33 agent skills were verified as currently installed in the user's environment (`~/.agents/skills/`, `~/.gemini/skills/`, `~/.claude/skills/`):

| Skill Name | Installed Location | Core Coverage | Evaluation Status |
| :--- | :--- | :--- | :--- |
| **stitch-design-taste** | `~/.agents/skills/stitch-design-taste/` | Google Stitch semantic design system | **KEEP** |
| **minimalist-ui** | `~/.agents/skills/minimalist-ui/` | Clean editorial UI layout & typography | **KEEP** |
| **impeccable** | `~/.gemini/skills/impeccable/` & `~/.agents/skills/impeccable/` | High-craft UI design, polish & audit | **KEEP** |
| **high-end-visual-design** | `~/.agents/skills/high-end-visual-design/` | Agency-level visual typography & spacing | **OPTIONAL** |
| **pick-ui-library** | `~/.agents/skills/pick-ui-library/` | Curated UI component library selector | **OPTIONAL** |
| **redesign-existing-projects** | `~/.agents/skills/redesign-existing-projects/` | Quality upgrades for existing apps | **OPTIONAL** |
| **design-taste-frontend** | `~/.agents/skills/design-taste-frontend/` | Anti-slop frontend design principles | **OPTIONAL** |
| **industrial-brutalist-ui** | `~/.agents/skills/industrial-brutalist-ui/` | Terminal/dense typography styling | **OPTIONAL** |
| **emil-design-eng** | `~/.agents/skills/emil-design-eng/` | Micro-interactions & UI polish | **OPTIONAL** |
| **full-output-enforcement** | `~/.agents/skills/full-output-enforcement/` | Token-limit output extension | **DISABLE / REMOVE LATER** |
| **design-taste-frontend-v1** | `~/.agents/skills/design-taste-frontend-v1/` | Legacy frontend taste rules | **DISABLE / REMOVE LATER** |
| **gpt-taste** | `~/.agents/skills/gpt-taste/` | Landing page layout & editorial typography | **DISABLE / REMOVE LATER** |
| **apple-design** | `~/.agents/skills/apple-design/` | Consumer Apple-style visual guidelines | **DISABLE / REMOVE LATER** |
| **brandkit** | `~/.agents/skills/brandkit/` | Brand color & identity generation | **DISABLE / REMOVE LATER** |
| **design-dna** | `~/.agents/skills/design-dna/` | Visual identity extraction | **DISABLE / REMOVE LATER** |
| **animate** | `~/.agents/skills/animate/` | General animation principles | **DISABLE / REMOVE LATER** |
| **animation-vocabulary** | `~/.agents/skills/animation-vocabulary/` | Motion design terminology | **DISABLE / REMOVE LATER** |
| **motion-design** | `~/.agents/skills/motion-design/` | Disney motion adapted to web UI | **DISABLE / REMOVE LATER** |
| **find-animation-opportunities** | `~/.agents/skills/find-animation-opportunities/` | Motion opportunity scanner | **DISABLE / REMOVE LATER** |
| **improve-animations** | `~/.agents/skills/improve-animations/` | Motion audit & plan authoring | **DISABLE / REMOVE LATER** |
| **review-animations** | `~/.agents/skills/review-animations/` | Motion craft code reviewer | **DISABLE / REMOVE LATER** |
| **imagegen-frontend-web** | `~/.agents/skills/imagegen-frontend-web/` | Web image direction generation | **DISABLE / REMOVE LATER** |
| **imagegen-frontend-mobile** | `~/.agents/skills/imagegen-frontend-mobile/` | Mobile image direction generation | **DISABLE / REMOVE LATER** |
| **image-to-code** | `~/.agents/skills/image-to-code/` | Uncontrolled screenshot-to-code generation | **DISABLE / REMOVE LATER** |
| **prototype** | `~/.agents/skills/prototype/` | Throwaway variant generator | **DISABLE / REMOVE LATER** |
| **gsap-core** | `~/.agents/skills/gsap-core/` | GSAP core animation API | **REDUNDANT** |
| **gsap-react** | `~/.agents/skills/gsap-react/` | GSAP hook for React | **REDUNDANT** |
| **gsap-plugins** | `~/.agents/skills/gsap-plugins/` | GSAP plugin suite | **REDUNDANT** |
| **gsap-scrolltrigger** | `~/.agents/skills/gsap-scrolltrigger/` | Scroll-linked animation triggers | **REDUNDANT** |
| **gsap-timeline** | `~/.agents/skills/gsap-timeline/` | GSAP animation timelines | **REDUNDANT** |
| **gsap-utils** | `~/.agents/skills/gsap-utils/` | GSAP math utilities | **REDUNDANT** |
| **gsap-performance** | `~/.agents/skills/gsap-performance/` | GSAP performance optimization | **REDUNDANT** |
| **gsap-frameworks** | `~/.agents/skills/gsap-frameworks/` | GSAP for Vue/Svelte | **REDUNDANT** |

---

## 2. Verified Available Skills (Capability Audit)

The following capability areas were audited against known public/system skill sources. Capabilities not pre-installed or explicitly verified from an accessible registry are marked `UNKNOWN — REQUIRES VERIFICATION` per audit rules:

| Category | Capability Area | Installed Status | Verified Skill Name | Availability Status |
| :--- | :--- | :--- | :--- | :--- |
| **Security** | Threat Modeling | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-security-review`) |
| **Security** | Security Auditing | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-security-review`) |
| **Security** | STRIDE Methodology | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-security-review`) |
| **Security** | API Security | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-api-change-review`) |
| **Security** | Auth/Security Patterns | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Covered in-code (`apps/control-plane/app/core/security.py`) |
| **Security** | Backend Security | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-tenant-isolation`) |
| **Security** | Frontend Security | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Covered in-code (`RBACGate` components) |
| **Security** | Dependency Security | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Can use standard `pip-audit` / `npm audit` |
| **Architecture** | Software Architecture | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Governance via `ProductConstitution.md` |
| **Architecture** | Senior Architecture | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Governance via `ProductConstitution.md` |
| **Architecture** | API Design | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-api-change-review`) |
| **Architecture** | Python | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | In-code Python 3.11 / FastAPI standards |
| **Architecture** | FastAPI | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | In-code FastAPI APIRouter structure |
| **Architecture** | PostgreSQL | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | In-code SQLAlchemy 2.0 async engine |
| **Architecture** | Database Migrations | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-migration-safety`) |
| **Testing** | TDD | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-feature-completeness`) |
| **Testing** | Testing Patterns | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | In-code `pytest` suite (389 collected tests) |
| **Testing** | Test Fixing | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | In-code `pytest` suite |
| **Testing** | Browser/E2E Testing | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-e2e-validation`) |
| **Testing** | Playwright | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-e2e-validation`) |
| **Testing** | API Testing | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Covered in `tests/integration/` |
| **Production** | Docker | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-production-readiness`) |
| **Production** | Container Security | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-production-readiness`) |
| **Production** | Deployment | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-production-readiness`) |
| **Production** | Observability | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Structured logging in control-plane |
| **Production** | Secrets Management | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Environmental loading via Pydantic settings |
| **Production** | Debugging | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Pytest & uvicorn/ARQ diagnostic logs |
| **Production** | Production Readiness | Not Installed | `UNKNOWN — REQUIRES VERIFICATION` | Requires Custom Skill (`asm-production-readiness`) |

---

## 3. Recommended Security Skills

| Capability | Recommended Skill | Source / Location | Status | Purpose & ASM Coverage | Overlap |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Security Review & RBAC** | `asm-security-review` | Custom Workspace Skill (`.agents/skills/asm-security-review/`) | To Be Created | Enforces 4-tier RBAC (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`), JWT auth validation, and security audit log emission. | None |
| **Tenant Isolation** | `asm-tenant-isolation` | Custom Workspace Skill (`.agents/skills/asm-tenant-isolation/`) | To Be Created | Enforces mandatory `org_id` URL path scoping, ORM database query filtering, and cross-tenant isolation checks. | None |
| **Scanner Network Safety** | `asm-scanner-safety` | Custom Workspace Skill (`.agents/skills/asm-scanner-safety/`) | To Be Created | Enforces egress guard IP validation, DNS TOCTOU rebinding defense, response body truncation (10MB limit), and worker process isolation. | None |
| **Evidence Tamper Evidence** | `asm-evidence-integrity` | Custom Workspace Skill (`.agents/skills/asm-evidence-integrity/`) | To Be Created | Enforces SHA-256 observation hashing, HMAC-SHA256 signatures, and evidence provenance tracking. | None |

---

## 4. Recommended Architecture Skills

| Capability | Recommended Skill | Source / Location | Status | Purpose & ASM Coverage | Overlap |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **API Contract Safety** | `asm-api-change-review` | Custom Workspace Skill (`.agents/skills/asm-api-change-review/`) | To Be Created | Validates Pydantic v2 schemas, shared DTO contracts, and prevents breaking API contract changes across control-plane and web-frontend. | None |
| **Migration Safety** | `asm-migration-safety` | Custom Workspace Skill (`.agents/skills/asm-migration-safety/`) | To Be Created | Enforces reversible Alembic migration scripts, zero-downtime schema changes, and dual SQLite/PostgreSQL compatibility. | None |

---

## 5. Recommended Testing Skills

| Capability | Recommended Skill | Source / Location | Status | Purpose & ASM Coverage | Overlap |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Feature Completeness** | `asm-feature-completeness` | Custom Workspace Skill (`.agents/skills/asm-feature-completeness/`) | To Be Created | Ensures every frontend screen maps 1:1 to a real FastAPI backend domain engine; bans mock data and placeholder logic. | None |
| **E2E & Route Validation** | `asm-e2e-validation` | Custom Workspace Skill (`.agents/skills/asm-e2e-validation/`) | To Be Created | Governs Next.js production builds (`npm run build`), route validation, and browser runtime verification workflows. | None |

---

## 6. Recommended Production Skills

| Capability | Recommended Skill | Source / Location | Status | Purpose & ASM Coverage | Overlap |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Production Readiness** | `asm-production-readiness` | Custom Workspace Skill (`.agents/skills/asm-production-readiness/`) | To Be Created | Audits error handling, rate limiting, health checks, structured logging, and container security manifests prior to deployment. | None |

---

## 7. Existing Frontend Skills Classification

The 33 pre-installed frontend skills have been classified based on ASM's light-first, calm, operational enterprise security design system:

- **KEEP (3 Skills)**:
  1. `stitch-design-taste`: Essential for Google Stitch UI layout adherence.
  2. `minimalist-ui`: Enforces high signal-to-noise typography and clean layout.
  3. `impeccable`: Enforces UI craft, accessibility, and clean component structure.

- **OPTIONAL (6 Skills)**:
  1. `high-end-visual-design`: Guidance for enterprise visual hierarchy.
  2. `pick-ui-library`: Guidance for selecting vetted lightweight component primitives.
  3. `redesign-existing-projects`: Refactoring UI layouts without breaking functionality.
  4. `design-taste-frontend`: General anti-slop frontend principles.
  5. `industrial-brutalist-ui`: Dense data grid and typography guidelines.
  6. `emil-design-eng`: UI polish and interaction state guidelines.

- **DISABLE / REMOVE LATER (16 Skills)**:
  1. `apple-design`: Consumer design guidelines (irrelevant for SecOps).
  2. `brandkit`: Marketing branding generator (ASM palette is locked).
  3. `design-dna`: Consumer visual identity extraction.
  4. `gpt-taste`: Marketing page editorial typography.
  5. `animate`: Motion principles (ASM bans decorative animations).
  6. `animation-vocabulary`: Motion naming terms.
  7. `motion-design`: Disney motion principles.
  8. `find-animation-opportunities`: Motion opportunity scanner.
  9. `improve-animations`: Motion audit authoring.
  10. `review-animations`: Motion craft code reviewer.
  11. `imagegen-frontend-web`: Web image direction generator.
  12. `imagegen-frontend-mobile`: Mobile image direction generator.
  13. `design-taste-frontend-v1`: Legacy version of `design-taste-frontend`.
  14. `full-output-enforcement`: Overrides LLM output length (reclassified per section 6 instructions).
  15. `prototype`: Uncontrolled variant generator.
  16. `image-to-code`: Uncontrolled screenshot-to-code generator.

- **REDUNDANT (8 Skills)**:
  1. `gsap-core`
  2. `gsap-react`
  3. `gsap-plugins`
  4. `gsap-scrolltrigger`
  5. `gsap-timeline`
  6. `gsap-utils`
  7. `gsap-performance`
  8. `gsap-frameworks`

---

## 8. Skills to Keep

The following 3 skills should remain enabled for frontend work:
1. `stitch-design-taste` (`~/.agents/skills/stitch-design-taste/`)
2. `minimalist-ui` (`~/.agents/skills/minimalist-ui/`)
3. `impeccable` (`~/.gemini/skills/impeccable/` & `~/.agents/skills/impeccable/`)

---

## 9. Skills to Remove / Disable Later

The following 24 skills should be disabled or removed during future environment cleanup:
- All 8 GSAP animation skills (`gsap-core`, `gsap-react`, `gsap-plugins`, `gsap-scrolltrigger`, `gsap-timeline`, `gsap-utils`, `gsap-performance`, `gsap-frameworks`).
- All 6 motion & animation skills (`animate`, `animation-vocabulary`, `motion-design`, `find-animation-opportunities`, `improve-animations`, `review-animations`).
- Consumer & marketing skills (`apple-design`, `brandkit`, `design-dna`, `gpt-taste`, `imagegen-frontend-web`, `imagegen-frontend-mobile`).
- Legacy duplicate `design-taste-frontend-v1`.
- Token override skill `full-output-enforcement` (code completeness must come from tests and contract validation, not output length hacks).
- Dangerous autonomous generators (`prototype`, `image-to-code`).

---

## 10. Dangerous & Uncontrolled Skills

The following installed skills are flagged as dangerous for an enterprise security product:

| Skill Name | Path | Specific Risk / Threat to ASM |
| :--- | :--- | :--- |
| **`prototype`** | `~/.agents/skills/prototype/` | Encourages building throwaway UI variations, risking breaking real API state binding and tenant security context. |
| **`image-to-code`** | `~/.agents/skills/image-to-code/` | Performs uncontrolled screenshot-to-code conversions, risking unreviewed layout overwrites and security boundary bypasses. |
| **`redesign-existing-projects`** | `~/.agents/skills/redesign-existing-projects/` | Recommends large-scale layout refactoring, which can introduce unreviewed architecture changes if run autonomously. |
| **`gsap-*` (8 skills)** | `~/.agents/skills/gsap-*/` | Encourages adding heavy JavaScript motion libraries, layout thrashing, and decorative animations that compromise operational scanning density. |

*Action*: Report only. **Do NOT remove or modify any files during this audit.**

---

## 11. Custom ASM Workspace Skills Specification

To ensure security invariants are strictly enforced, the following 9 custom workspace skills will be created inside `.agents/skills/`:

### 1. `asm-security-review`
- **Location**: `.agents/skills/asm-security-review/SKILL.md`
- **Responsibility**: Governs authentication, authorization, and auditability.
- **Invariants**:
  - Enforce server-side 4-tier RBAC (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`).
  - Require JWT bearer validation on every control-plane endpoint.
  - Require security audit log emissions for all security-impacting state changes.

### 2. `asm-tenant-isolation`
- **Location**: `.agents/skills/asm-tenant-isolation/SKILL.md`
- **Responsibility**: Governs multi-tenant data boundaries.
- **Invariants**:
  - Enforce mandatory `org_id` URL path scoping across all API routes.
  - Require `org_id` filtering on all SQLAlchemy ORM database queries.
  - Reject cross-tenant request parameters with `403 Forbidden` / `404 Not Found`.

### 3. `asm-scanner-safety`
- **Location**: `.agents/skills/asm-scanner-safety/SKILL.md`
- **Responsibility**: Governs scanner worker network safety and resource limits.
- **Invariants**:
  - Enforce egress guard IP validation blocking private IPv4, loopback, link-local, and IPv4-mapped IPv6 ranges.
  - Enforce DNS TOCTOU rebinding guards resolving hostnames immediately prior to socket connections.
  - Enforce worker process isolation with zero database or authentication model imports.

### 4. `asm-evidence-integrity`
- **Location**: `.agents/skills/asm-evidence-integrity/SKILL.md`
- **Responsibility**: Governs raw observation tamper evidence and provenance.
- **Invariants**:
  - Enforce SHA-256 payload hashing for all raw scan observations.
  - Require HMAC-SHA256 signatures for observation ingestion payload verification.
  - Accurate terminology enforcement: report HMAC as providing **integrity, authenticity, provenance, and tamper evidence** (never non-repudiation).

### 5. `asm-api-change-review`
- **Location**: `.agents/skills/asm-api-change-review/SKILL.md`
- **Responsibility**: Governs API contract compatibility.
- **Invariants**:
  - Validate Pydantic v2 schemas against shared DTO contracts (`packages/shared-contracts`).
  - Prohibit introducing unapproved backend endpoints or breaking changes to existing endpoints.

### 6. `asm-migration-safety`
- **Location**: `.agents/skills/asm-migration-safety/SKILL.md`
- **Responsibility**: Governs database migration safety.
- **Invariants**:
  - Require explicit `upgrade()` and `downgrade()` methods in all Alembic migration scripts.
  - Enforce dual database compatibility for SQLite (`asm_dev.db`) and production PostgreSQL.

### 7. `asm-feature-completeness`
- **Location**: `.agents/skills/asm-feature-completeness/SKILL.md`
- **Responsibility**: Governs 1:1 mapping between UI components and backend engines.
- **Invariants**:
  - Prohibit mock data or hardcoded example values in production UI code.
  - Ensure all UI actions map directly to implemented FastAPI domain services.

### 8. `asm-e2e-validation`
- **Location**: `.agents/skills/asm-e2e-validation/SKILL.md`
- **Responsibility**: Governs build and route testing workflows.
- **Invariants**:
  - Require clean compilation of `npm run build` with zero TypeScript or lint errors.
  - Require browser-based route testing across desktop resolutions.

### 9. `asm-production-readiness`
- **Location**: `.agents/skills/asm-production-readiness/SKILL.md`
- **Responsibility**: Governs operational stability and deployment readiness.
- **Invariants**:
  - Require structured JSON logging and exception handling.
  - Enforce health check endpoints (`/healthz`, `/readyz`) and container security standards.

---

## 12. Final Installation Order

When authorized by human approval, skill installation and setup will proceed in this strict order:

1. **Step 1 — Create Workspace Skill Directories**: Create local directories under `.agents/skills/` for the 9 custom ASM skills.
2. **Step 2 — Author Custom ASM Skill Files**: Write `SKILL.md` instruction files for each custom skill containing rule boundaries and invariants.
3. **Step 3 — Disable / Clean Up Unwanted Skills**: Remove or disable redundant GSAP and consumer animation skills from `~/.agents/skills/`.
4. **Step 4 — Verify Workspace Skill Registration**: Confirm that local skills under `.agents/skills/` are recognized.

---

## 13. Exact Installation Commands (DO NOT EXECUTE NOW)

```bash
# ==============================================================================
# DO NOT EXECUTE THESE COMMANDS UNTIL HUMAN APPROVAL IS EXPLICITLY GIVEN
# ==============================================================================

# 1. Create directory structure for custom ASM skills
mkdir -p .agents/skills/asm-security-review
mkdir -p .agents/skills/asm-tenant-isolation
mkdir -p .agents/skills/asm-scanner-safety
mkdir -p .agents/skills/asm-evidence-integrity
mkdir -p .agents/skills/asm-api-change-review
mkdir -p .agents/skills/asm-migration-safety
mkdir -p .agents/skills/asm-feature-completeness
mkdir -p .agents/skills/asm-e2e-validation
mkdir -p .agents/skills/asm-production-readiness

# 2. Cleanup redundant GSAP skills (Optional step after backup)
# rm -rf ~/.agents/skills/gsap-*
```

---

## 14. Verification Commands

The following commands will verify skill registration and codebase integrity after installation:

```bash
# 1. Verify custom workspace skills are present
ls -la .agents/skills/

# 2. Verify Next.js frontend production build compiles cleanly
cd apps/web-frontend && npm run build

# 3. Verify Pytest suite execution status (Requires explicit execution)
# PYTHONPATH=apps/scanner-worker:apps/control-plane:packages/shared-contracts/python apps/control-plane/.venv/bin/pytest tests/
```

*Note on Test Status*: Test execution was **NOT run** during this preparation audit. During the previous collection audit, **389 tests were collected**. Test status must be verified by actual execution when authorized.

---

## 15. Items Requiring Human Approval

Before executing any installation or creating skill files, human approval is required for:

1. [ ] **Approval of Custom ASM Skills List**: Confirm creation of the 9 custom ASM workspace skills (`asm-security-review`, `asm-tenant-isolation`, `asm-scanner-safety`, etc.).
2. [ ] **Approval of Skill Cleanup Plan**: Confirm disabling/removal of 24 redundant GSAP and consumer animation skills.
3. [ ] **Authorization to Proceed**: Authorization to write the custom `SKILL.md` files in `.agents/skills/`.

---

### STOP

**Do not execute installation commands. Do not delete skills. Do not modify the repository. Do not create custom skills yet.**
