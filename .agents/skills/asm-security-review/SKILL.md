---
name: asm-security-review
description: ASM Security Review & Authorization Guardrails. Enforces server-side authentication, 4-tier RBAC (OWNER, ADMIN, MEMBER, VIEWER), action authorization classes (CLASS_A, CLASS_B, CLASS_C), audit logging, least privilege, and security regression reviews for Attack Surface Monitor.
---

# ASM Security Review & Authorization Guardrails (`asm-security-review`)

## Purpose
This skill governs all security-sensitive operations, authentication, role-based access control (RBAC), action authorization boundaries, and audit logging within the Attack Surface Monitor (ASM).

## Mandatory Security Invariants

### 1. Server-Side Authority
- **No UI-Only Security**: UI visibility toggles, disabled buttons, or hidden routes are presentation helpers ONLY. ALL security policies must be validated and enforced server-side in FastAPI dependencies (`apps/control-plane/app/api/dependencies/auth.py`).
- **Authentication**: Every API request must pass JWT bearer validation or session context verification. Unauthenticated requests must return `401 Unauthorized`.

### 2. 4-Tier RBAC Hierarchy
- **OWNER**: Full organizational control, organization deletion, member role escalation.
- **ADMIN**: Administrative controls, scanner configuration, API key generation, organization context modifications, action approvals.
- **MEMBER**: Standard operational usage, domain onboarding, manual scan triggers, finding remediation state updates.
- **VIEWER**: Read-only telemetry, asset inspection, finding viewing. Rejects all state-mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`).

### 3. Action Authorization Classes
- **CLASS_A (Low Risk / Automatic)**: Automated asset discovery, passive DNS probes, header validation.
- **CLASS_B (Medium Risk / Policy Controlled)**: Active port scanning, TLS probe execution, finding state changes. Requires authorized role execution.
- **CLASS_C (High Risk / Human Approval Required)**: Remediation verification, marking expected state, configuration revocation. Requires explicit human authorization and audit logging.

### 4. Audit Logging & Least Privilege
- Every security-impacting state change MUST emit a structured audit log event (`AuditService.log_event`).
- Audit logs MUST record: `org_id`, `actor_id`, `actor_role`, `action_type`, `resource_target`, `timestamp`, `client_ip`.

### 5. AI Subordination Boundary
- **AI Output is NOT Evidence**: LLM/AI-generated text (`/assistant`) MUST NEVER automatically trigger security actions, alter finding status, or act as authoritative scanner evidence. AI output is strictly labeled `AI INTERPRETATION` or `RECOMMENDATION`.
