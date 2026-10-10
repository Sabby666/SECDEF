# Attack Surface Monitor — Application Flow

> **Status:** DRAFT — Pending Human Review
> **Last Updated:** 2026-08-27
> **Parent Document:** PRD.md, Architecture.md
> **Document Type:** User Experience Flows

---

## 1. Landing & Public Pages

### 1.1 Landing Page
- **USER:** Anonymous visitor
- **SCREEN:** Public landing page
- **ACTION:** Clicks "Get Started" or "Sign Up"
- **NEXT STATE:** Registration page

### 1.2 Login Page
- **USER:** Existing user
- **SCREEN:** Login form (email, password)
- **ACTION:** Submits credentials
- **BACKEND EVENT:** Validate credentials, check brute-force limits
- **SUCCESS PATH:** → MFA verification → Dashboard
- **FAILURE PATHS:**
  - Invalid credentials → "Invalid email or password" (no enumeration)
  - Account locked → "Account temporarily locked. Try again in X minutes."
  - Rate limited → "Too many attempts. Please try again later."

---

## 2. Registration Flow

### 2.1 Sign Up
- **USER:** New visitor
- **SCREEN:** Registration form (name, email, password, confirm password)
- **ACTION:** Submits registration
- **BACKEND EVENT:**
  1. Validate input (email format, password complexity)
  2. Check if email already registered (respond identically regardless)
  3. Hash password (bcrypt, work factor 12)
  4. Create user record (status: `pending_verification`)
  5. Generate email verification token (JWT, 24h expiry)
  6. Send verification email
- **STATE CHANGE:** User created, unverified
- **NEXT STATE:** Email verification notice screen
- **SUCCESS PATH:** "Check your email to verify your account"
- **FAILURE PATHS:**
  - Invalid email format → Inline validation error
  - Password too weak → Inline validation with requirements
  - Rate limited → "Too many attempts"
- **SECURITY NOTE:** Response is identical whether email exists or not (enumeration protection)

### 2.2 Email Verification
- **USER:** New user from email link
- **SCREEN:** Verification processing page (auto-submits token)
- **ACTION:** Clicks verification link in email
- **BACKEND EVENT:**
  1. Validate token (JWT signature, expiry, single-use)
  2. Mark user as verified
  3. Invalidate token
- **STATE CHANGE:** User status → `verified`
- **NEXT STATE:** Login page with success message
- **FAILURE PATHS:**
  - Expired token → "Verification link expired. Request a new one."
  - Already used → "Account already verified. Please log in."
  - Invalid token → "Invalid verification link."
- **EMPTY STATE:** Resend verification email option

### 2.3 MFA Enrollment (Post-First-Login)
- **USER:** Verified user, first login
- **SCREEN:** MFA enrollment page (QR code + manual secret + recovery codes)
- **ACTION:** Scans QR with authenticator app, enters verification code
- **BACKEND EVENT:**
  1. Generate TOTP secret
  2. Display QR code and manual secret
  3. Generate 10 recovery codes
  4. Verify user's first TOTP code to confirm setup
  5. Hash recovery codes, store encrypted TOTP secret
- **STATE CHANGE:** MFA enrolled
- **NEXT STATE:** Recovery codes display (must acknowledge before continuing)
- **IMPORTANT:** Recovery codes shown once. User must confirm they've saved them.
- **FAILURE PATHS:**
  - Invalid TOTP code → "Invalid code. Please try again."
  - Clock drift → "Code doesn't match. Ensure your device clock is correct."

---

## 3. Authentication Flow

### 3.1 Login
- **USER:** Registered user
- **SCREEN:** Login form
- **ACTION:** Submits email + password
- **BACKEND EVENT:**
  1. Validate credentials
  2. Check account lock status
  3. If valid → Prompt MFA
  4. If invalid → Increment failure counter; response delay
- **NEXT STATE:** MFA verification screen
- **FAILURE PATH:** "Invalid email or password" (constant-time response)

### 3.2 MFA Verification
- **USER:** User with valid credentials
- **SCREEN:** MFA code entry (TOTP or recovery code)
- **ACTION:** Enters 6-digit TOTP code
- **BACKEND EVENT:**
  1. Verify TOTP code (±1 window)
  2. Create session (opaque token, 256-bit)
  3. Set HttpOnly, Secure, SameSite=Strict cookie
- **STATE CHANGE:** Session created
- **NEXT STATE:**
  - If user has no organization → Organization creation
  - If user has organization → Dashboard
- **FAILURE PATHS:**
  - Invalid TOTP → "Invalid code" (max 5 attempts per session)
  - Recovery code → Consumes one-time code; MFA bypassed; user warned to set up new MFA

### 3.3 Password Reset
- **USER:** User who forgot password
- **SCREEN:** Password reset request form (email)
- **ACTION:** Submits email
- **BACKEND EVENT:**
  1. Generate reset token (JWT, 1h expiry, single-use)
  2. Send reset email (identical response regardless of email existence)
- **NEXT STATE:** "If an account exists, you'll receive a reset email"
- **RESET SCREEN:** New password form (from email link)
- **BACKEND EVENT (confirm):**
  1. Validate token
  2. Hash new password
  3. Invalidate all existing sessions
  4. Invalidate token
  5. Send confirmation email
- **NEXT STATE:** Login page with "Password changed successfully"

### 3.4 Logout
- **USER:** Authenticated user
- **ACTION:** Clicks logout
- **BACKEND EVENT:**
  1. Invalidate session server-side
  2. Clear session cookie
- **NEXT STATE:** Login page

---

## 4. Organization Setup Flow

### 4.1 Organization Creation
- **USER:** Authenticated user without organization
- **SCREEN:** Organization creation form (organization name)
- **ACTION:** Submits organization name
- **BACKEND EVENT:**
  1. Create organization record
  2. Create membership (user → org, role: Owner)
  3. Initialize audit log
- **STATE CHANGE:** Organization created; user is Owner
- **NEXT STATE:** Domain addition page
- **EMPTY STATE:** "Create your organization to get started"

### 4.2 Domain Addition
- **USER:** Org Owner or Admin
- **SCREEN:** Domain management page
- **ACTION:** Enters root domain (e.g., `example.com`)
- **BACKEND EVENT:**
  1. Validate domain format
  2. Check for conflicts (domain already verified by another org)
  3. Generate verification token
  4. Create domain record (status: `pending_verification`)
- **STATE CHANGE:** Domain added, pending verification
- **NEXT STATE:** Domain verification instructions
- **FAILURE PATHS:**
  - Invalid domain format → Inline error
  - Domain already claimed → "This domain is already verified by another organization"
  - Rate limit → "Too many domains added recently"

### 4.3 Domain Verification
- **USER:** Org Owner or Admin
- **SCREEN:** Domain verification page with DNS TXT record instructions
- **CONTENT:** "Add this TXT record to your DNS: `_asm-verify.example.com TXT asm-verify=<token>`"
- **ACTION:** Clicks "Verify Now"
- **BACKEND EVENT:**
  1. Query DNS for TXT record
  2. Validate token match
  3. Update domain status
  4. Enqueue initial discovery scan
- **STATE CHANGE:** Domain verified; initial scan queued
- **NEXT STATE:** Discovery progress page
- **SUCCESS PATH:** "Domain verified! Discovery is starting..."
- **FAILURE PATHS:**
  - DNS record not found → "TXT record not found. DNS changes can take up to 48 hours."
  - Wrong token → "TXT record found but token doesn't match"
  - Timeout (72h) → "Verification expired. Please re-add the domain."
- **LOADING STATE:** "Checking DNS records..." (with spinner)

---

## 5. Discovery & Scanning Flow

### 5.1 Initial Discovery Progress
- **USER:** Org Owner/Admin/Member after domain verification
- **SCREEN:** Discovery progress page
- **CONTENT:** Progress indicators for each discovery phase
- **BACKEND EVENT:** Scan orchestrator executes discovery pipeline
- **PROGRESS DISPLAY:**
  ```
  ✓ Domain verified
  ⟳ Discovering subdomains...         (12 found)
  ⟳ Resolving DNS records...          (8 resolved)
  ○ Scanning services...              (pending)
  ○ Checking certificates...          (pending)
  ○ Identifying technologies...       (pending)
  ```
- **STATE CHANGE:** Assets created as discovered; observations recorded
- **NEXT STATE:** Dashboard (when initial scan completes)
- **LOADING STATE:** Real-time progress updates (polling or WebSocket)
- **FAILURE PATHS:**
  - Scan fails → "Discovery encountered errors. Partial results are available."
  - Timeout → "Discovery is taking longer than expected. Results will appear as they're ready."

### 5.2 Ongoing Scans
- **USER:** Any authenticated member
- **SCREEN:** Scan status visible in header/sidebar
- **BACKEND EVENT:** Scheduled scans run periodically (default: daily)
- **INDICATORS:**
  - Last scan time visible
  - "Scan in progress" indicator when running
  - Scan history accessible from settings
- **FAILURE PATHS:**
  - Scan fails → notification sent; previous results preserved
  - Domain verification expired → scan paused; warning displayed

---

## 6. Dashboard Flow

### 6.1 Main Dashboard
- **USER:** Authenticated member
- **SCREEN:** Dashboard with key metrics and recent activity
- **CONTENT:**
  - **Security Posture Summary:** Total assets, open findings by severity, unowned assets
  - **Recent Changes:** Last 24h/7d change feed (new assets, new services, certificate changes)
  - **Top Findings:** Highest priority findings requiring attention
  - **Action Required:** Findings awaiting decision, expiring risk acceptances
  - **Discovery Status:** Last scan time, next scan time, scan health
- **ACTIONS:** Click any element to navigate to detail view
- **EMPTY STATE (first visit):** "Discovery is in progress. Your dashboard will populate as assets are discovered."
- **LOADING STATE:** Skeleton loading for each dashboard section

---

## 7. Asset Explorer Flow

### 7.1 Asset List
- **USER:** Authenticated member
- **SCREEN:** Asset inventory table with filters and search
- **CONTENT:** Table: Hostname/IP, Type, Environment, Criticality, Owner, Last Seen, Status
- **FILTERS:** Type, Environment, Criticality, Owner, Status, Technology
- **SEARCH:** Search by hostname, IP, technology
- **ACTIONS:**
  - Click row → Asset detail page
  - Bulk select → Assign owner, Set environment, Set criticality
- **EMPTY STATE:** "No assets discovered yet. Verify a domain to begin discovery."
- **LOADING STATE:** Skeleton table rows

### 7.2 Asset Detail
- **USER:** Authenticated member
- **SCREEN:** Asset detail page with tabs
- **TABS:**
  - **Overview:** Asset identity, metadata, organizational context (owner, environment, criticality)
  - **Services:** Open ports and services on this asset
  - **Certificates:** TLS certificates associated with this asset
  - **DNS:** DNS records for this hostname
  - **Technologies:** Identified technologies
  - **Relationships:** Connected assets (parent domain, resolved IPs, services, certificates)
  - **History:** Historical observations and changes timeline
  - **Findings:** Open findings for this asset
  - **Decisions:** Decision history for this asset
- **ACTIONS:**
  - Edit ownership, environment, criticality
  - Mark services as expected
  - Navigate to related assets
  - View evidence for any observation
- **LOADING STATE:** Tab-level loading

### 7.3 Asset Relationships View
- **USER:** Authenticated member
- **SCREEN:** Relationship tree/graph for selected asset
- **CONTENT:** Visual representation: Domain → Subdomains → IPs → Services → Certificates
- **ACTIONS:** Click any node to navigate to that asset's detail page
- **EMPTY STATE:** "No relationships discovered for this asset."

---

## 8. Changes Flow

### 8.1 Change Feed
- **USER:** Authenticated member
- **SCREEN:** Chronological feed of detected changes
- **CONTENT:** Each change shows:
  - Change type (New Asset, Removed Service, Certificate Changed, etc.)
  - Affected asset (clickable)
  - Previous state → Current state
  - Timestamp
  - Organizational context (environment, criticality if assigned)
- **FILTERS:** Time range, Change type, Environment, Severity
- **ACTIONS:** Click change → Navigate to affected asset detail
- **EMPTY STATE:** "No changes detected yet. Changes will appear after the second scan."

---

## 9. Findings Flow

### 9.1 Findings List
- **USER:** Authenticated member
- **SCREEN:** Prioritized findings table
- **CONTENT:** Table: Finding title, Severity, Risk Score, Asset, Environment, Owner, Status, Age
- **DEFAULT SORT:** Risk score (highest first)
- **FILTERS:** Severity, Status, Environment, Owner, Asset type
- **ACTIONS:** Click row → Finding detail
- **EMPTY STATE:** "No findings yet. Findings will appear once discovery completes."

### 9.2 Finding Detail
- **USER:** Authenticated member
- **SCREEN:** Finding detail page
- **CONTENT:**
  - **Summary:** Finding title, severity, risk score, description
  - **Affected Asset:** Link to asset with organizational context
  - **Evidence:** Raw evidence chain (scan data, observations, timestamps)
  - **Risk Explanation:** Why this finding received its risk score (which factors contributed)
  - **Remediation Guidance:** Specific steps to resolve
  - **Decision History:** Previous decisions on this finding (if any)
- **ACTIONS:**
  - Accept Risk (requires reason, expiration)
  - Mark False Positive (requires reason)
  - Mark In Progress
  - Request Verification (after remediation)
- **PERMISSION CONTROL:** Decision actions require Member role or above
- **LOADING STATE:** Finding content with skeleton evidence section

### 9.3 Decision Modal
- **USER:** Member, Admin, or Owner
- **SCREEN:** Modal overlay on finding detail
- **CONTENT (Accept Risk):**
  - Reason (required, free text)
  - Expiration date (required, max 1 year)
  - Additional notes (optional)
  - Confirmation checkbox: "I understand this finding will be suppressed until [date]"
- **CONTENT (False Positive):**
  - Reason (required, free text)
  - Evidence/justification (optional)
- **BACKEND EVENT:**
  1. Validate decision data
  2. Store decision (append-only)
  3. Update finding status
  4. Recalculate risk (if applicable)
  5. Update alert suppression
  6. Record in audit log
- **STATE CHANGE:** Finding status updated; decision recorded
- **NEXT STATE:** Finding detail (with updated status and decision history)

---

## 10. Settings Flow

### 10.1 Organization Settings
- **USER:** Admin or Owner
- **SCREEN:** Organization settings page
- **TABS:**
  - **General:** Organization name, basic settings
  - **Domains:** Domain management (add, verify, remove)
  - **Members:** Member list, invitations, role management
  - **Notifications:** Organization-wide notification preferences
  - **Scan Settings:** Scan frequency, port range configuration
  - **Audit Log:** Filterable audit event log

### 10.2 Member Management
- **USER:** Admin or Owner
- **SCREEN:** Members tab
- **CONTENT:** Table: Name, Email, Role, Joined, Last Active
- **ACTIONS:**
  - Invite member (email)
  - Change role (dropdown)
  - Remove member (confirmation required)
- **CONSTRAINTS:** Cannot remove last Owner; cannot demote self if last Owner
- **PERMISSION FAILURE:** "You don't have permission to manage members"

### 10.3 User Settings
- **USER:** Any authenticated user
- **SCREEN:** Personal settings page
- **TABS:**
  - **Profile:** Name, email (read-only)
  - **Security:** Password change, MFA management, active sessions
  - **Notifications:** Personal notification preferences

### 10.4 Security Settings
- **USER:** Any authenticated user
- **SCREEN:** Security tab of personal settings
- **CONTENT:**
  - Change password (current password required)
  - MFA status (enrolled/not enrolled)
  - Regenerate recovery codes
  - Active sessions list (with device, IP, last active)
- **ACTIONS:**
  - Change password → All other sessions invalidated
  - Regenerate recovery codes → Previous codes invalidated
  - Revoke session → Specific session invalidated

---

## 11. Notification Flow

### 11.1 In-App Notifications
- **USER:** Authenticated user
- **SCREEN:** Notification bell icon in header; dropdown panel
- **CONTENT:** List of notifications (unread highlighted)
  - "New critical finding: [finding title] on [asset]"
  - "Certificate expiring in 7 days: [cert subject]"
  - "Risk acceptance expires in 30 days: [finding]"
  - "Scan completed: [domain] — [X] changes detected"
  - "Verification complete: [finding] — [Resolved/Still Open]"
- **ACTIONS:** Click notification → Navigate to relevant page; Mark as read
- **EMPTY STATE:** "No new notifications"

### 11.2 Email Notifications
- **USER:** User with email notifications enabled
- **CONTENT:** Same notification types as in-app
- **FREQUENCY:** Immediate for critical; daily digest for non-critical (configurable)
- **SECURITY:** No sensitive details in email body; link to platform for details

---

## 12. Audit Log Flow

### 12.1 Audit Log View
- **USER:** Admin or Owner
- **SCREEN:** Audit log page
- **CONTENT:** Table: Timestamp, Actor (name + email), Action, Resource, Result, IP
- **FILTERS:** Date range, Actor, Action type, Resource type
- **ACTIONS:** View detail → Expanded event detail
- **EMPTY STATE:** "No audit events recorded yet"
- **PERMISSION FAILURE:** Members and Viewers see "You don't have permission to view audit logs"

---

## 13. Error States

### Global Error States

| Error | User Message | Technical Handling |
|---|---|---|
| **401 Unauthorized** | Redirect to login page | Session expired or invalid |
| **403 Forbidden** | "You don't have permission to perform this action" | RBAC violation |
| **404 Not Found** | "Page not found" | Invalid route or deleted resource |
| **429 Rate Limited** | "Too many requests. Please wait a moment." | Rate limit exceeded |
| **500 Server Error** | "Something went wrong. Please try again." | Internal error (logged, no details exposed) |
| **503 Unavailable** | "Service temporarily unavailable. We're working on it." | Maintenance or outage |

### Form Error States

- Inline validation errors shown next to fields
- Server-side validation errors mapped to fields where possible
- Generic errors shown as banner at top of form
- Error messages are user-friendly, not technical
