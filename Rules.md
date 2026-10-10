# Attack Surface Monitor — Agent & Engineering Rules

> **Status:** ACTIVE — Mandatory Rules for Future Coding Agents & Engineers
> **Last Updated:** 2026-08-27
> **Parent Document:** All Documentation Set
> **Document Type:** Execution Rules & Constraints

---

## 1. Primary Operating Rules

Future AI agents and human engineers working on this codebase MUST strictly observe the following 13 rules:

### RULE 1: Read Documentation Before Implementation
Before writing any code or modifying schemas, you MUST read the relevant documentation:
- Strategy & Core Thesis: `ProductConstitution.md`
- Requirements: `PRD.md`, `Phases.md`
- Architecture & Technology: `Architecture.md`, `TechSpec.md`
- Data Models & Flows: `Schema.md`, `AppFlow.md`, `Design.md`
- Security Requirements & Gates: `SecurityChecklist.md`

### RULE 2: Strategic Source of Truth
Treat `ProductConstitution.md` as the strategic source of truth. No implementation may contradict the Constitution.

### RULE 3: Mandatory Domain Verification
NEVER bypass domain ownership verification (DNS TXT verification). Scans MUST NOT be triggered for unverified domains.

### RULE 4: Strict Worker Boundary Isolation
NEVER grant scanner workers access to control-plane databases, secrets, or write APIs. Workers communicate exclusively via sanitized Redis queue jobs.

### RULE 5: Destination Safety Is Not Target Authorization
NEVER assume domain verification authorizes arbitrary network destinations. Scanner workers MUST validate resolved IP addresses and HTTP redirect destinations against Network Destination Safety (blocking RFC 1918/4193 private ranges, loopback, and `169.254.169.254` cloud metadata). Worker connections MUST prevent DNS TOCTOU rebinding races by passing validated IPs directly to socket APIs.

### RULE 6: Strict Tenant Isolation
Every database query, API endpoint, worker job, and cache key MUST enforce `org_id` scoping. Never perform un-scoped queries on multi-tenant tables.

### RULE 7: Evidence Provenance
Every finding MUST preserve evidence provenance, linking directly to raw `observations` snapshots and immutable evidence records.

### RULE 8: Decision History Preservation
Human security decisions (risk acceptances, false positives, expected states) MUST remain append-only and fully auditable. Never delete decision records.

### RULE 9: Scope-Limited Decision Memory
NEVER convert a human decision on a single asset into a global or wildcard rule automatically. Wildcard rules MUST be explicitly defined by Admins.

### RULE 10: No Unassisted Autonomous Learning
NEVER introduce autonomous risk acceptance or auto-suppression without an explicit human decision. Learning in V1 MUST remain deterministic, explainable, and auditable.

### RULE 11: No Unannounced Scope Creep
DO NOT implement features from V2, Future, or Rejected categories without explicit approval recorded in `Memory.md` and updated in `PRD.md`.

### RULE 12: Maintain Living Knowledge
Update `Memory.md` and `Tracker.md` immediately whenever architectural decisions are made or implementation status changes.

### RULE 13: Empirical Verification Before Completion
Editing a file does NOT complete a task. You MUST run unit/integration tests and verify backend/frontend compilation before marking any item as `DONE` in `Tracker.md`.

---

## 2. Forbidden Actions (MUST NOT)

Agents MUST NOT:
1. Write raw SQL string concatenations.
2. Store secrets or passwords in plain text or source control.
3. Expose stack traces, internal paths, or credentials in error responses.
4. Follow HTTP redirects to private IP addresses or cloud metadata endpoints.
5. Silently suppress errors or return fake dummy data to make tests pass.
6. Refactor major architectural components without written proposal in `Memory.md`.
7. Bypass MFA or authentication checks.
8. Create application source directories (`src/`, `backend/`, `frontend/`, `workers/`) during documentation phases.
