# FINAL_GENERIC_SKILL_SELECTION.md — Attack Surface Monitor (ASM)

> **Status:** FINAL GENERIC SKILL VERIFICATION COMPLETE — PENDING HUMAN APPROVAL  
> **Date:** 2026-10-04  
> **Target:** Attack Surface Monitor (ASM) Repository & Agent Skill Environment  
> **Author:** Antigravity AI Agent  

---

## 1. Executive Decision

An un-assumed, exact verification audit of generic Agent Skills was conducted across all local skill directories (`~/.agents/skills/`, `~/.gemini/skills/`, `~/.claude/skills/`, `~/.codex/skills/`, and `~/.npm/_npx/`).

### Core Findings:
1. **Zero Pre-Installed Generic Security / Backend Skills**: None of the requested generic security skills (`security-auditor`, `threat-modeling-expert`, `auth-implementation-patterns`, `backend-security-coder`, `security-requirement-extraction`, `stride-analysis-patterns`, `dependency-management-deps-audit`, `secrets-management`) exist as installed skills in the local environment or verified local catalogs.
2. **Strict Verification Enforcement**: In accordance with rule #7 ("Do NOT classify a skill as good merely because its name sounds relevant; if unavailable mark as `UNKNOWN — DO NOT INSTALL`"), all unverified generic security, architecture, and production skills are marked `UNKNOWN — DO NOT INSTALL`.
3. **Verified Local Tool Skill**: `playwright-cli` was verified as present inside the local npm package cache (`node_modules/playwright-core/lib/tools/skills/playwright-cli/SKILL.md`).
4. **Minimal Generic Stack**: Rather than attempting to install unverified external generic skills, ASM will rely on **3 verified frontend skills** (`stitch-design-taste`, `minimalist-ui`, `impeccable`), **1 verified browser testing skill** (`playwright-cli`), and **9 custom project-specific skills** designed explicitly for ASM security boundaries.

---

## 2. Verified Security Skills

The 8 requested generic security skills were audited against local and accessible skill stores:

| Skill Name | Catalog / Source | Availability | Installation Method | ASM Use Case | Safety Assessment | Overlap | Verification Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **security-auditor** | Unverified External Catalog | Not Installed | N/A | Security code auditing | Unknown | Overlaps `asm-security-review` | **UNKNOWN — DO NOT INSTALL** |
| **threat-modeling-expert** | Unverified External Catalog | Not Installed | N/A | STRIDE threat modeling | Unknown | Overlaps `asm-security-review` | **UNKNOWN — DO NOT INSTALL** |
| **auth-implementation-patterns** | Unverified External Catalog | Not Installed | N/A | Auth pattern verification | Unknown | Covered in-code (`security.py`) | **UNKNOWN — DO NOT INSTALL** |
| **backend-security-coder** | Unverified External Catalog | Not Installed | N/A | Secure coding practices | Unknown | Overlaps `asm-tenant-isolation` | **UNKNOWN — DO NOT INSTALL** |
| **security-requirement-extraction** | Unverified External Catalog | Not Installed | N/A | Security requirement extraction | Unknown | Covered in PRD/Constitution | **UNKNOWN — DO NOT INSTALL** |
| **stride-analysis-patterns** | Unverified External Catalog | Not Installed | N/A | Threat modeling methodology | Unknown | Overlaps `asm-security-review` | **UNKNOWN — DO NOT INSTALL** |
| **dependency-management-deps-audit** | Unverified External Catalog | Not Installed | N/A | Dependency security scanning | Unknown | Covered by `pip-audit` / `npm audit` | **UNKNOWN — DO NOT INSTALL** |
| **secrets-management** | Unverified External Catalog | Not Installed | N/A | Secrets scanning & isolation | Unknown | Covered in Pydantic Settings | **UNKNOWN — DO NOT INSTALL** |

---

## 3. Verified Backend / Architecture Skills

| Skill / Capability | Catalog / Source | Availability | Installation Method | ASM Use Case | Verification Decision |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **API Design** | Unverified External Catalog | Not Installed | N/A | OpenAPI / FastAPI router design | **UNKNOWN — DO NOT INSTALL** |
| **Python** | Unverified External Catalog | Not Installed | N/A | Python 3.11 code standards | **UNKNOWN — DO NOT INSTALL** |
| **FastAPI** | Unverified External Catalog | Not Installed | N/A | Control-plane API router setup | **UNKNOWN — DO NOT INSTALL** |
| **Backend Architecture** | Unverified External Catalog | Not Installed | N/A | Decoupled domain service architecture | **UNKNOWN — DO NOT INSTALL** |
| **PostgreSQL** | Unverified External Catalog | Not Installed | N/A | Production database access patterns | **UNKNOWN — DO NOT INSTALL** |
| **Database Architecture** | Unverified External Catalog | Not Installed | N/A | ORM model schema design | **UNKNOWN — DO NOT INSTALL** |
| **Database Migrations** | Unverified External Catalog | Not Installed | N/A | Alembic migration safety | **UNKNOWN — DO NOT INSTALL** |
| **Debugging** | Unverified External Catalog | Not Installed | N/A | FastAPI / ARQ diagnostic tracing | **UNKNOWN — DO NOT INSTALL** |

*Note*: All backend, API, and database architecture rules will be enforced via project code standards and the custom skill `asm-api-change-review` & `asm-migration-safety`.

---

## 4. Verified Testing Skills

| Skill Name / Capability | Catalog / Source | Availability | Installation Method | ASM Use Case | Verification Decision |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **playwright-cli** | `node_modules/playwright-core` (Local NPM Cache) | **Available Locally** | Direct reference from local npm cache | Browser E2E route testing & visual verification | **INSTALL** |
| **TDD** | Unverified External Catalog | Not Installed | N/A | Test-driven development workflows | **UNKNOWN — DO NOT INSTALL** |
| **pytest / Python Testing** | Unverified External Catalog | Not Installed | N/A | Pytest execution patterns | **UNKNOWN — DO NOT INSTALL** |
| **Unit Testing** | Unverified External Catalog | Not Installed | N/A | Unit test suite authoring | **UNKNOWN — DO NOT INSTALL** |
| **Integration Testing** | Unverified External Catalog | Not Installed | N/A | Control-plane API integration tests | **UNKNOWN — DO NOT INSTALL** |
| **API Testing** | Unverified External Catalog | Not Installed | N/A | HTTP endpoint contract testing | **UNKNOWN — DO NOT INSTALL** |
| **Test Fixing** | Unverified External Catalog | Not Installed | N/A | Test failure debugging | **UNKNOWN — DO NOT INSTALL** |
| **Verification Workflows** | Unverified External Catalog | Not Installed | N/A | Build & route verification | **UNKNOWN — DO NOT INSTALL** |

---

## 5. Verified Production Skills

| Skill / Capability | Catalog / Source | Availability | Installation Method | ASM Use Case | Verification Decision |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Docker** | Unverified External Catalog | Not Installed | N/A | Container image generation | **UNKNOWN — DO NOT INSTALL** |
| **Container Security** | Unverified External Catalog | Not Installed | N/A | Container hardening rules | **UNKNOWN — DO NOT INSTALL** |
| **Deployment** | Unverified External Catalog | Not Installed | N/A | Production deployment manifests | **UNKNOWN — DO NOT INSTALL** |
| **CI/CD** | Unverified External Catalog | Not Installed | N/A | GitHub Actions workflow rules | **UNKNOWN — DO NOT INSTALL** |
| **Observability** | Unverified External Catalog | Not Installed | N/A | OpenTelemetry / Prometheus logging | **UNKNOWN — DO NOT INSTALL** |
| **Secrets Management** | Unverified External Catalog | Not Installed | N/A | Vault / Env secret rotation | **UNKNOWN — DO NOT INSTALL** |
| **Dependency Auditing** | Unverified External Catalog | Not Installed | N/A | Pip/npm vulnerability scanning | **UNKNOWN — DO NOT INSTALL** |
| **Production Readiness** | Unverified External Catalog | Not Installed | N/A | Readiness checklist evaluation | **UNKNOWN — DO NOT INSTALL** |

*Note*: Production safety and readiness will be governed by the custom skill `asm-production-readiness`.

---

## 6. Frontend Skills

The frontend skill stack is locked to the 3 approved pre-installed skills. **No additional generic frontend skills will be added.**

### Retained Frontend Skills (KEEP):
1. **`stitch-design-taste`** (`~/.agents/skills/stitch-design-taste/`): Enforces Google Stitch UI design system tokens.
2. **`minimalist-ui`** (`~/.agents/skills/minimalist-ui/`): Enforces high signal-to-noise ratio, calm typography, and low-density layouts.
3. **`impeccable`** (`~/.gemini/skills/impeccable/` & `~/.agents/skills/impeccable/`): Enforces strict UI craft, accessibility, and component structure.

---

## 7. Skills Rejected

The following skills are explicitly **REJECTED** from installation or activation in ASM:

- **Unsafe Autonomous Code Generators**: `prototype`, `image-to-code` (risk introducing unreviewed layout overwrites and security boundary bypasses).
- **All 8 GSAP Animation Skills**: `gsap-core`, `gsap-react`, `gsap-plugins`, `gsap-scrolltrigger`, `gsap-timeline`, `gsap-utils`, `gsap-performance`, `gsap-frameworks` (ASM explicitly bans motion gimmicks and heavy animation libraries).
- **Consumer / Marketing Design Skills**: `apple-design`, `brandkit`, `design-dna`, `gpt-taste`, `imagegen-frontend-web`, `imagegen-frontend-mobile` (conflict with enterprise security workspace standards).
- **Redundant Legacy Skills**: `design-taste-frontend-v1`, `full-output-enforcement` (code completeness comes from tests and API verification, not prompt hacks).

---

## 8. Skills Requiring Further Verification

The following requested skill names cannot be verified from local skill stores or official registries and are marked **`UNKNOWN — DO NOT INSTALL`**:
- `security-auditor`
- `threat-modeling-expert`
- `auth-implementation-patterns`
- `backend-security-coder`
- `security-requirement-extraction`
- `stride-analysis-patterns`
- `dependency-management-deps-audit`
- `secrets-management`

---

## 9. Recommended Minimal Installation Set

The complete, minimal skill stack for ASM consists of **4 generic skills** (3 frontend + 1 testing) plus **9 custom workspace skills**:

| Skill Name | Skill Type | Classification | Source |
| :--- | :--- | :--- | :--- |
| **stitch-design-taste** | Generic (Frontend) | **KEEP / INSTALL** | `~/.agents/skills/stitch-design-taste/` |
| **minimalist-ui** | Generic (Frontend) | **KEEP / INSTALL** | `~/.agents/skills/minimalist-ui/` |
| **impeccable** | Generic (Frontend) | **KEEP / INSTALL** | `~/.gemini/skills/impeccable/` |
| **playwright-cli** | Generic (Testing) | **INSTALL** | `node_modules/playwright-core/...` |
| **asm-security-review** | Custom Workspace | **CUSTOM (Create Later)** | `.agents/skills/asm-security-review/` |
| **asm-tenant-isolation** | Custom Workspace | **CUSTOM (Create Later)** | `.agents/skills/asm-tenant-isolation/` |
| **asm-scanner-safety** | Custom Workspace | **CUSTOM (Create Later)** | `.agents/skills/asm-scanner-safety/` |
| **asm-evidence-integrity** | Custom Workspace | **CUSTOM (Create Later)** | `.agents/skills/asm-evidence-integrity/` |
| **asm-api-change-review** | Custom Workspace | **CUSTOM (Create Later)** | `.agents/skills/asm-api-change-review/` |
| **asm-migration-safety** | Custom Workspace | **CUSTOM (Create Later)** | `.agents/skills/asm-migration-safety/` |
| **asm-feature-completeness** | Custom Workspace | **CUSTOM (Create Later)** | `.agents/skills/asm-feature-completeness/` |
| **asm-e2e-validation** | Custom Workspace | **CUSTOM (Create Later)** | `.agents/skills/asm-e2e-validation/` |
| **asm-production-readiness** | Custom Workspace | **CUSTOM (Create Later)** | `.agents/skills/asm-production-readiness/` |

---

## 10. Installation Source for Each Skill

- **`stitch-design-taste`**: Pre-installed at `~/.agents/skills/stitch-design-taste/`
- **`minimalist-ui`**: Pre-installed at `~/.agents/skills/minimalist-ui/`
- **`impeccable`**: Pre-installed at `~/.gemini/skills/impeccable/`
- **`playwright-cli`**: Local NPM path `node_modules/playwright-core/lib/tools/skills/playwright-cli/SKILL.md`

---

## 11. Installation Method for Each Skill

- **Pre-installed Skills** (`stitch-design-taste`, `minimalist-ui`, `impeccable`): Symlink or reference directly from `.agents/skills/`.
- **Local Tool Skill** (`playwright-cli`): Copy or reference `SKILL.md` into `.agents/skills/playwright-cli/` upon approval.
- **Custom Workspace Skills**: Write dedicated `SKILL.md` files in `.agents/skills/asm-*/`.

---

## 12. Security & Safety Assessment

All generic skills selected for installation operate under strict safety constraints:
- **Read-Only / Inspection First**: Skills operate in audit and review mode before proposing changes.
- **Zero Autonomous Execution**: Skills do NOT execute destructive shell commands (`rm`, `drop database`, `git reset --hard`) without explicit human confirmation.
- **Least Privilege**: Skills operate within workspace directory bounds and respect file permission checks.

---

## 13. Generic vs. ASM-Custom Boundary

To prevent overlap and ensure absolute security enforcement, responsibilities are cleanly divided:

```
+-------------------------------------------------------------------------+
|                        GENERIC AGENT SKILLS                             |
|  - UI Design System & Craft (stitch-design-taste, minimalist-ui)        |
|  - Visual Accessibility & Layout Audit (impeccable)                     |
|  - E2E Browser Test Runner (playwright-cli)                             |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                     PROJECT-SPECIFIC ASM SKILLS                         |
|  - 4-Tier RBAC & Security Audit Logs (asm-security-review)              |
|  - Mandatory org_id Tenant Isolation (asm-tenant-isolation)              |
|  - Egress Guard, SSRF & DNS TOCTOU Defense (asm-scanner-safety)          |
|  - HMAC Observation Provenance & Tamper Evidence (asm-evidence-integrity)|
|  - Shared DTO Contract Validation (asm-api-change-review)                |
|  - Dual SQLite/Postgres Reversible Migrations (asm-migration-safety)     |
|  - 1:1 UI to Engine Feature Mapping (asm-feature-completeness)          |
|  - Next.js Build & E2E Route Validation (asm-e2e-validation)             |
|  - Error Handling & Container Health Checks (asm-production-readiness)   |
+-------------------------------------------------------------------------+
```

---

## 14. Exact Installation Plan (DO NOT EXECUTE NOW)

```bash
# ==============================================================================
# DO NOT EXECUTE THESE COMMANDS UNTIL HUMAN APPROVAL IS EXPLICITLY GIVEN
# ==============================================================================

# 1. Create directory structure for custom workspace skills
mkdir -p .agents/skills/asm-security-review
mkdir -p .agents/skills/asm-tenant-isolation
mkdir -p .agents/skills/asm-scanner-safety
mkdir -p .agents/skills/asm-evidence-integrity
mkdir -p .agents/skills/asm-api-change-review
mkdir -p .agents/skills/asm-migration-safety
mkdir -p .agents/skills/asm-feature-completeness
mkdir -p .agents/skills/asm-e2e-validation
mkdir -p .agents/skills/asm-production-readiness

# 2. Copy verified local Playwright testing skill
mkdir -p .agents/skills/playwright-cli
# cp node_modules/playwright-core/lib/tools/skills/playwright-cli/SKILL.md .agents/skills/playwright-cli/
```

---

## 15. Verification Plan

1. **Workspace Skill Discovery**: Verify `.agents/skills/` contains the 9 custom skill folders and 4 verified generic skills.
2. **Build Verification**: Run `npm run build` in `apps/web-frontend` to confirm compilation clean state.
3. **Backend Contract Verification**: Verify FastAPI endpoints pass existing Pydantic validation without contract changes.

---

## 16. Human Approval Required

Before proceeding to skill setup or authoring custom `SKILL.md` files, human approval is required for:

1. [ ] **Approval of Generic Skill Stack**: Confirm keeping `stitch-design-taste`, `minimalist-ui`, `impeccable`, and adding `playwright-cli`.
2. [ ] **Approval of Custom ASM Skills Scope**: Confirm creation of the 9 custom ASM workspace skills.
3. [ ] **Authorization to Proceed**: Authorization to author the custom skill files in `.agents/skills/`.

---

### STOP

**Do not execute any installation commands. Do not delete anything. Do not create custom skills. Do not modify the ASM repository.**
