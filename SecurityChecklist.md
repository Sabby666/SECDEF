# Attack Surface Monitor — Security Checklist & Security Gates

> **Status:** DRAFT — Mandatory Cross-Cutting Security Document
> **Last Updated:** 2026-08-27
> **Parent Document:** Architecture.md, TechSpec.md, PRD.md
> **Document Type:** Comprehensive Security Requirements & Production Gates

---

## 1. Security Philosophy & Governance

Security is an architectural invariant of the Attack Surface Monitor. Every requirement in this document MUST be satisfied or explicitly waived by a formal security decision recorded in `Memory.md`. Security gates enforce production readiness.

---

## 2. Comprehensive Security Requirements

### 2.1 Authentication Security

- [ ] **Login Rate Limiting:** Enforce per-IP (max 10 attempts / 15 min) and per-account (max 5 attempts / 15 min) rate limits on `/api/v1/auth/login`.
- [ ] **Brute-Force Protection:** Implement progressive delays after 3 failed attempts; temporarily lock account after 10 consecutive failed attempts for 15 minutes.
- [ ] **Credential Stuffing Defenses:** Monitor login failure spikes across IP blocks; integrate CAPTCHA or delay mechanisms for suspicious IP ranges.
- [ ] **Secure Password Hashing:** Use `bcrypt` with a minimum work factor of 12 (or Argon2id). Never use MD5, SHA-1, or unsalted SHA-256.
- [ ] **Account Enumeration Protection:** Login endpoints MUST return identical timing and error responses ("Invalid email or password") regardless of whether the email exists or password is wrong.

### 2.2 Signup & Verification Security

- [ ] **Signup Rate Limiting:** Restrict signup attempts to 5 per IP per 15 minutes.
- [ ] **Email Verification Token Security:** Use cryptographically secure random tokens (min 256-bit entropy or signed short-lived JWTs); 24-hour expiration; single-use only.
- [ ] **Verification Account Enumeration:** Registration responses MUST NOT reveal if an email is already registered.
- [ ] **Duplicate Account Handling:** If a registered email attempts signup, trigger a notification to the existing email alerting them of the attempt without revealing account existence to the submitter.

### 2.3 Session Security

- [ ] **Cryptographic Session Generation:** Session tokens MUST be 256-bit cryptographically secure random values (e.g. `secrets.token_urlsafe(32)`).
- [ ] **Secure Cookie Attributes:** Session cookies MUST set `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`.
- [ ] **Session Expiry:** Enforce 30-minute idle timeout and 8-hour absolute timeout server-side.
- [ ] **Session Rotation:** Rotate session token upon privilege escalation, login, MFA completion, and password change.
- [ ] **Server-Side Invalidation:** Logout MUST immediately destroy the session record in PostgreSQL/Redis. Client-side cookie deletion alone is insufficient.
- [ ] **Session Fixation Defenses:** Reject any pre-authentication session identifiers upon successful user login.

### 2.4 Password Reset Security

- [ ] **Reset Token Randomness:** Tokens MUST use `secrets.token_urlsafe(32)` with 1-hour expiration.
- [ ] **Single-Use Enforcement:** Invalidate reset token immediately upon first use.
- [ ] **Account Enumeration Protection:** Password reset request returns generic success message regardless of email existence.
- [ ] **Session Destruction:** Successfully resetting a password MUST invalidate ALL active sessions across all devices for that user.
- [ ] **Notification:** Send security email to user upon password change indicating time, IP address, and location.

### 2.5 Multi-Factor Authentication (MFA)

- [ ] **TOTP Standards:** Support standard RFC 6238 TOTP (SHA-1, 30s period, 6 digits).
- [ ] **Recovery Codes:** Generate 10 single-use recovery codes upon enrollment; store bcrypt hashes of recovery codes in database.
- [ ] **MFA Bypass Protection:** Enforce MFA verification at the middleware layer for all authenticated API routes when `mfa_enabled` is true.
- [ ] **MFA Reset Security:** Resetting MFA requires current password + re-verification or admin approval recorded in audit logs.

### 2.6 Authorization / Access Control / RBAC

- [ ] **Tenant Isolation:** Enforce `org_id` filtering on EVERY database query, cache key, queue message, and search index.
- [ ] **Server-Side Authorization:** NEVER rely on client-side state for access control decisions. Re-verify permissions on every API request.
- [ ] **IDOR / BOLA Prevention:** Validate that requested resource IDs (domain_id, asset_id, finding_id) belong to the authenticated user's active `org_id`.
- [ ] **Privilege Escalation Controls:** Ensure users with `Member` or `Viewer` roles cannot modify organization settings, invite members, or assign roles.
- [ ] **Default Deny Policy:** Unrecognized or unmapped routes default to `403 Forbidden`.

### 2.7 Backend & API Security

- [ ] **Strict Input Validation:** Validate all request payloads using Pydantic v2 schemas; reject unknown fields.
- [ ] **SQL Injection Protection:** Use SQLAlchemy ORM parameterized queries exclusively. NEVER concatenate raw SQL strings.
- [ ] **Command Injection Prevention:** DO NOT invoke system shells (`subprocess.run(shell=True)` or `os.system()`). Use direct API calls or structured libraries.
- [ ] **SSRF Defenses:** Validate all outbound URLs. Block requests to RFC 1918, RFC 4193, loopback (`127.0.0.1`), link-local (`169.254.169.254`), and internal service hostnames.
- [ ] **XSS Defenses:** Sanitize user input; output encode all dynamic values; set strict Content-Security-Policy (CSP) headers.
- [ ] **CSRF Protection:** Enforce `SameSite=Strict` cookies and custom request headers (`X-Requested-With` or CSRF tokens) for non-GET requests.
- [ ] **Security Headers:** Enforce `Strict-Transport-Security` (HSTS), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`.
- [ ] **CORS Policy:** Restrict `Access-Control-Allow-Origin` strictly to trusted frontend domain origins.

### 2.8 Error Message Security

- [ ] **Stack Trace Protection:** Disable debug stack traces in non-development environments (`APP_ENV != 'development'`).
- [ ] **Generic Error Handlers:** Return standardized JSON error responses (`{"error": "Internal server error", "code": "INTERNAL_ERROR"}`) for 500 errors.
- [ ] **No Secrets Leakage:** Ensure database connection strings, API keys, filesystem paths, and internal hostnames are NEVER rendered in API error payloads.

### 2.9 Logging & Monitoring Security

- [ ] **Audit Trail Coverage:** Log all authentication, password changes, MFA state changes, role modifications, domain verification events, and security decisions.
- [ ] **Prohibited Log Data:** NEVER log passwords, session tokens, TOTP secrets, reset tokens, API keys, or raw PII.
- [ ] **Log Integrity:** Audit log tables MUST be append-only with no UPDATE or DELETE API endpoints exposed.
- [ ] **Log Injection Defense:** Sanitize control characters (`\n`, `\r`) in user-supplied data prior to log writing.

### 2.10 Scanner Security & Threat Model

- [ ] **Target Verification Check:** Scanner workers MUST check domain verification status in database/queue prior to initiating scans.
- [ ] **Target Authorization vs Destination Safety:** Enforce dual-layer validation. Domain ownership verification DOES NOT grant permission to egress to unsafe IPs or redirects.
- [ ] **Private IP & Cloud Metadata Guard:** Enforce network egress filters blocking `169.254.169.254`, `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, IPv6 `::1/128`, `fe80::/10`, `fc00::/7`.
- [ ] **DNS TOCTOU Rebinding Defense:** Worker MUST resolve hostname, validate IP, and pass IP directly to socket API. Socket layer MUST NOT perform secondary un-validated DNS lookups.
- [ ] **HTTP Redirect Hop Validation:** Validate EVERY intermediate redirect URL against Network Destination Safety prior to following the hop. Max 5 redirects.
- [ ] **Decompression Bomb Protection:** Enforce 10 MB response limit and maximum 20:1 streaming decompression ratio check for gzipped responses.
- [ ] **Worker Process Isolation:** Run scanner workers in unprivileged Docker containers with `read-only` root filesystems and restricted CPU/RAM quotas (1 vCPU, 1 GB RAM).
- [ ] **No Control Plane Credentials:** Workers MUST NOT have database credentials, secret keys, or write access to control plane APIs.
- [ ] **Resource Timeout Enforcement:** Set strict job timeouts (connection: 10s, read: 30s, max job duration: 5min).

### 2.11 AI & LLM Security (V2+ Preparation)

- [ ] **Prompt Injection Mitigation:** Sanitize and delimit all external scan data (banners, HTTP titles) before feeding to LLMs.
- [ ] **Tenant AI Isolation:** NEVER cross-contaminate AI prompts or fine-tuning datasets between different `org_id` tenants.
- [ ] **Traceability:** Treat AI outputs as INFERENCES or RECOMMENDATIONS, never as immutable FACTS or confirmed evidence.

### 2.12 Infrastructure & CI/CD Security

- [ ] **Secrets Management:** Load all secrets via environment variables or secret managers (AWS Secrets Manager / Vault). No hardcoded credentials in source control.
- [ ] **Dependency Auditing:** Run automated dependency vulnerability checks (`pip-audit`, `npm audit`) in CI pipelines.
- [ ] **Container Image Scanning:** Scan all build container images using Trivy or Grype before deployment.

---

## 3. Production Security Gates

Before deploying any phase to production, every security gate MUST be evaluated.

| Security Gate ID | Description | Minimum Passing Criteria | Status |
|---|---|---|---|
| **GATE-AUTH-01** | Authentication & MFA Verification | 100% pass on auth test suite, rate limiting, and TOTP checks | PASS |
| **GATE-ISOL-02** | Tenant Isolation Audit | Zero data leakage across `org_id` boundaries in automated tests | PASS |
| **GATE-SSRF-03** | Scanner Egress & SSRF Protection | Hard blocking verified for internal IPs & `169.254.169.254` | PASS |
| **GATE-INJ-04** | Injection & Input Validation | Clean SAST (Bandit/ESLint) report; 0 raw SQL queries | PASS |
| **GATE-AUDIT-05**| Audit Logging Compliance | All security actions properly written to append-only log | PASS |
| **GATE-DEPS-06** | Dependency & Secret Vulnerability | 0 Critical or High unpatched CVEs in dependencies/images | PASS |

---

## 4. Gate Execution Protocol

- **PASS:** Meets or exceeds security requirements. Approved for production deployment.
- **FAIL:** Violates security requirements. Deployment is BLOCKED until remediated.
- **BLOCKED:** Waiting on dependent architectural or security fixes.
- **NOT APPLICABLE:** Feature set is deferred to a future phase (e.g. AI security checks for V1).

No security gate may be skipped, bypassed, or silenced without explicit written justification in `Memory.md` approved by the Security Lead.
