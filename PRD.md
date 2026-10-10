# Attack Surface Monitor — Product Requirements Document (PRD)

> **Status:** DRAFT — Pending Human Review
> **Last Updated:** 2026-08-27
> **Parent Document:** ProductConstitution.md
> **Document Type:** Product Requirements

---

## 1. Problem Summary

Security teams with dynamic, cloud-native infrastructure need to understand meaningful changes in their external environment, why those changes matter to their specific organization, and what actions they should take — without manually reconstructing the business context, ownership, and risk implications every time.

Existing EASM tools focus on *scanning* and *listing*. They produce raw asset inventories and vulnerability lists but leave the critical work of contextualization, prioritization, and decision-making to manual human effort. This gap widens as infrastructure complexity grows.

---

## 2. Users & Personas

### Primary Users (V1)

| Persona | Role | Primary Job | Key Pain Point |
|---|---|---|---|
| **Alex** (Security Engineer) | Hands-on practitioner | Understand and act on external exposure | Spends 60%+ time manually gathering context |
| **Jordan** (Cloud/DevSecOps Engineer) | Cloud infrastructure security | Track cloud-to-Internet exposure | Cannot see what's actually exposed externally |
| **Morgan** (Security Lead) | Security program management | Report on and manage external risk | Cannot confidently answer "what's our posture?" |

### Secondary Users (V2+)

| Persona | Role | Primary Job |
|---|---|---|
| **Sam** (CTO/Engineering Leader) | Technical accountability | High-level exposure trends and team attribution |
| **MSSP Operator** | Multi-client management | Efficient multi-tenant monitoring |

---

## 3. User Stories

### 3.1 Onboarding & Setup

| ID | Story | Priority |
|---|---|---|
| US-001 | As a new user, I want to sign up with email and password so I can create my account | P0 |
| US-002 | As a new user, I want to verify my email so the platform confirms my identity | P0 |
| US-003 | As a new user, I want to set up MFA so my account is protected | P0 |
| US-004 | As a new user, I want to create my organization so I have a workspace for my team | P0 |
| US-005 | As an org owner, I want to add a domain and verify ownership so the platform scans my infrastructure | P0 |
| US-006 | As an org owner, I want to see initial discovery progress so I know the platform is working | P0 |
| US-007 | As an org owner, I want to invite team members so my team can collaborate | P1 |

### 3.2 Discovery & Inventory

| ID | Story | Priority |
|---|---|---|
| US-010 | As a security engineer, I want the platform to discover subdomains so I have visibility into my external footprint | P0 |
| US-011 | As a security engineer, I want to see resolved IPs for each asset so I understand the infrastructure | P0 |
| US-012 | As a security engineer, I want services/ports discovered on my assets so I know what's exposed | P0 |
| US-013 | As a security engineer, I want DNS records tracked so I can see DNS configuration | P0 |
| US-014 | As a security engineer, I want SSL/TLS certificates discovered and tracked so I can monitor certificate health | P0 |
| US-015 | As a security engineer, I want technologies identified (web server, framework, etc.) so I understand the stack | P0 |
| US-016 | As a security engineer, I want to browse my full asset inventory so I can understand my attack surface | P0 |
| US-017 | As a security engineer, I want to see asset relationships (subdomain → IP → service) so I understand connections | P1 |

### 3.3 Organizational Context

| ID | Story | Priority |
|---|---|---|
| US-020 | As a security engineer, I want to assign ownership to assets so I know who is responsible | P0 |
| US-021 | As a security engineer, I want to classify assets by environment (production, staging, dev) so I can prioritize correctly | P0 |
| US-022 | As a security engineer, I want to set criticality levels on assets so the platform understands business importance | P0 |
| US-023 | As a security engineer, I want to mark expected services/exposures so the platform distinguishes intended from unintended | P0 |
| US-024 | As a security lead, I want to see which assets lack ownership so I can assign responsibility | P1 |

### 3.4 Change Intelligence

| ID | Story | Priority |
|---|---|---|
| US-030 | As a security engineer, I want to see what changed since the last scan so I can focus on new developments | P0 |
| US-031 | As a security engineer, I want changes categorized (new asset, new service, certificate change, DNS change) so I understand the type of change | P0 |
| US-032 | As a security engineer, I want to see historical observations for any asset so I understand its evolution | P0 |
| US-033 | As a security engineer, I want alerts on meaningful changes (not noise) so I can respond to what matters | P0 |
| US-034 | As a security lead, I want a change timeline so I can review what happened over a period | P1 |

### 3.5 Risk & Evidence

| ID | Story | Priority |
|---|---|---|
| US-040 | As a security engineer, I want findings prioritized by organizational context (not just CVSS) so I focus on what matters most | P0 |
| US-041 | As a security engineer, I want to see the evidence behind every finding so I can trust the assessment | P0 |
| US-042 | As a security engineer, I want confidence scores on classifications so I know what's certain vs. inferred | P0 |
| US-043 | As a security lead, I want a dashboard showing prioritized findings so I can manage the security workload | P0 |
| US-044 | As a security engineer, I want to understand *why* something is prioritized highly so I can validate the reasoning | P1 |

### 3.6 Decisions & Actions

| ID | Story | Priority |
|---|---|---|
| US-050 | As a security engineer, I want to accept risk on a finding (with reason and expiration) so it's documented and not re-surfaced inappropriately | P0 |
| US-051 | As a security engineer, I want to mark a finding as false positive (with reason) so the platform learns | P0 |
| US-052 | As a security engineer, I want remediation guidance for findings so I know what to do | P0 |
| US-053 | As a security engineer, I want to request re-verification of a remediated issue so I can confirm it's fixed | P1 |
| US-054 | As a security lead, I want to see all decisions made across the organization so I can review security governance | P1 |
| US-055 | As a security lead, I want expiring risk acceptances surfaced so decisions are reviewed before they lapse | P1 |

### 3.7 Authentication & Security

| ID | Story | Priority |
|---|---|---|
| US-060 | As a user, I want to log in securely with my email and password | P0 |
| US-061 | As a user, I want MFA enforced on my account so it's protected | P0 |
| US-062 | As a user, I want to reset my password securely | P0 |
| US-063 | As a user, I want to log out and have my session invalidated | P0 |
| US-064 | As an org admin, I want to manage team members and roles | P0 |
| US-065 | As a user, I want audit logs of security-relevant actions | P1 |

---

## 4. Functional Requirements

### 4.1 Authentication & Account Management

#### FR-AUTH-001: User Registration
- **WHY:** Users need to create accounts to use the platform
- **WHAT:** Email/password registration with email verification
- **EXPECTED OUTCOME:** Verified user account ready for organization setup
- **ACCEPTANCE CRITERIA:**
  - Password minimum 12 characters, complexity requirements enforced
  - Email verification token sent, valid for 24 hours, single-use
  - Account enumeration protection (identical response for existing/non-existing emails)
  - Rate limiting on registration endpoint (5 attempts per IP per 15 minutes)

#### FR-AUTH-002: Login
- **WHY:** Authenticated access to the platform
- **WHAT:** Email/password authentication with MFA
- **EXPECTED OUTCOME:** Authenticated session with appropriate tokens
- **ACCEPTANCE CRITERIA:**
  - Brute-force protection (progressive delays, account lockout after 10 failed attempts)
  - Credential stuffing protection (rate limiting per IP and per account)
  - Secure session token generation (cryptographically random, min 256-bit)
  - HttpOnly, Secure, SameSite=Strict cookies
  - Session expiry: 30-minute idle timeout, 8-hour absolute timeout

#### FR-AUTH-003: Multi-Factor Authentication (MFA)
- **WHY:** Critical security control for a security platform
- **WHAT:** TOTP-based MFA with recovery codes
- **EXPECTED OUTCOME:** Second factor required for all logins
- **ACCEPTANCE CRITERIA:**
  - TOTP enrollment with QR code and manual secret display
  - 10 single-use recovery codes generated at enrollment
  - MFA required for all accounts (enforced, not optional)
  - MFA bypass protection (no API endpoints bypass MFA)
  - Recovery code regeneration invalidates previous codes

#### FR-AUTH-004: Password Reset
- **WHY:** Users need to recover access to their accounts
- **WHAT:** Secure password reset flow with token-based verification
- **EXPECTED OUTCOME:** Password changed securely, all sessions invalidated
- **ACCEPTANCE CRITERIA:**
  - Cryptographically random reset token, 1-hour expiry, single-use
  - Account enumeration protection
  - All existing sessions invalidated on password change
  - Email notification sent on password change (to old and new if changed)
  - Rate limiting on reset requests (3 per email per hour)

#### FR-AUTH-005: Session Management
- **WHY:** Secure session lifecycle prevents unauthorized access
- **WHAT:** Server-side session management with proper lifecycle
- **EXPECTED OUTCOME:** Sessions are secure, rotated, and properly expired
- **ACCEPTANCE CRITERIA:**
  - Session rotation on privilege changes
  - Logout invalidates session server-side
  - Concurrent session listing and individual revocation
  - Session fixation protection

### 4.2 Organization Management

#### FR-ORG-001: Organization Creation
- **WHY:** Organizations are the tenant boundary — all data is scoped to an organization
- **WHAT:** Create organization with name; creator becomes Owner
- **EXPECTED OUTCOME:** Isolated organizational workspace
- **ACCEPTANCE CRITERIA:**
  - Organization name required
  - Creator assigned Owner role automatically
  - Unique organization ID generated (UUID)
  - Tenant isolation enforced from creation

#### FR-ORG-002: Member Management
- **WHY:** Teams collaborate within organizations
- **WHAT:** Invite, remove, and manage members with role assignments
- **EXPECTED OUTCOME:** Controlled access to organizational data
- **ACCEPTANCE CRITERIA:**
  - Invite by email (creates pending invitation, valid 7 days)
  - Roles: Owner, Admin, Member, Viewer
  - At least one Owner required at all times
  - Role changes logged in audit trail
  - Member removal revokes all sessions for that user in that organization

#### FR-ORG-003: Role-Based Access Control (RBAC)
- **WHY:** Different users need different levels of access
- **WHAT:** Permission model tied to roles

| Role | Capabilities |
|---|---|
| **Owner** | All permissions + organization deletion + billing + owner management |
| **Admin** | Domain management + member management + security decisions + all viewing |
| **Member** | Asset viewing + finding viewing + ownership assignment + decisions on assigned assets |
| **Viewer** | Read-only access to dashboards, assets, findings |

- **ACCEPTANCE CRITERIA:**
  - Authorization enforced server-side on every API request
  - IDOR/BOLA protection on all resource access
  - Default deny — no permission means no access
  - Role changes take effect immediately

### 4.3 Domain Management

#### FR-DOM-001: Domain Registration
- **WHY:** Domains are the seed for discovery
- **WHAT:** Add root domains to the organization for scanning
- **EXPECTED OUTCOME:** Verified domain ready for discovery
- **ACCEPTANCE CRITERIA:**
  - Domain format validation
  - DNS-based verification (TXT record or CNAME)
  - Verification token unique, cryptographically random
  - Domain cannot be added to another organization while verified (conflict detection)
  - Verification must be completed within 72 hours

#### FR-DOM-002: Domain Verification
- **WHY:** Prevent unauthorized scanning of domains the user doesn't control
- **WHAT:** DNS-based ownership proof
- **EXPECTED OUTCOME:** Confirmed domain ownership, discovery begins
- **ACCEPTANCE CRITERIA:**
  - TXT record verification: `_asm-verify.domain.com TXT "asm-verify=<token>"`
  - Automated periodic re-verification (every 30 days)
  - Verification failure triggers alert, scan pausing after grace period
  - Verification status visible in UI

### 4.4 Discovery Engine

#### FR-DISC-001: Subdomain Discovery
- **WHY:** Subdomains are the primary expansion vector for external attack surface
- **WHAT:** Multi-source subdomain enumeration
- **EXPECTED OUTCOME:** Comprehensive subdomain inventory for verified domains
- **ACCEPTANCE CRITERIA:**
  - Sources: DNS brute-force (common wordlists), Certificate Transparency logs, DNS zone walking (if NSEC), passive DNS sources
  - Deduplication of discovered subdomains
  - Results stored with discovery source and confidence
  - Incremental discovery (new subdomains detected between scans)

#### FR-DISC-002: IP Resolution
- **WHY:** IP addresses are required for service discovery
- **WHAT:** DNS resolution for all discovered hostnames
- **EXPECTED OUTCOME:** IP addresses mapped to hostnames with historical tracking
- **ACCEPTANCE CRITERIA:**
  - A, AAAA, CNAME record resolution
  - Historical IP tracking (detect IP changes)
  - CDN/shared hosting detection
  - Resolution tracked with timestamp

#### FR-DISC-003: Service/Port Discovery
- **WHY:** Open services are the primary external exposure
- **WHAT:** Port scanning of discovered IP addresses
- **EXPECTED OUTCOME:** Service inventory per IP with protocol and version where identifiable
- **ACCEPTANCE CRITERIA:**
  - Top 1,000 TCP ports (V1), configurable
  - Service protocol identification (HTTP, HTTPS, SSH, FTP, etc.)
  - Banner grabbing for version identification
  - Rate limiting to avoid target disruption
  - Scan results stored with timestamp and evidence

#### FR-DISC-004: Certificate Discovery
- **WHY:** Certificate misconfigurations are high-value, low-noise findings
- **WHAT:** TLS certificate extraction and analysis
- **EXPECTED OUTCOME:** Certificate inventory with expiry tracking and chain validation
- **ACCEPTANCE CRITERIA:**
  - Certificate extraction from all HTTPS services
  - Subject and SAN extraction
  - Expiry tracking with configurable warning thresholds (30, 14, 7, 1 days)
  - Chain validation (self-signed, expired, wrong host)
  - Certificate Transparency log monitoring for new certificates

#### FR-DISC-005: DNS Observation
- **WHY:** DNS is the foundation of external infrastructure mapping
- **WHAT:** DNS record tracking and change detection
- **EXPECTED OUTCOME:** Complete DNS profile with historical comparison
- **ACCEPTANCE CRITERIA:**
  - Record types: A, AAAA, CNAME, MX, TXT, NS, SOA
  - SPF, DKIM, DMARC record analysis
  - DNS change detection (record added, changed, removed)
  - DNSSEC status tracking

#### FR-DISC-006: Technology Identification
- **WHY:** Technology context is required for risk assessment and organizational understanding
- **WHAT:** Web technology fingerprinting through response analysis
- **EXPECTED OUTCOME:** Technology stack identification per service
- **ACCEPTANCE CRITERIA:**
  - HTTP response header analysis (Server, X-Powered-By, etc.)
  - HTML content analysis (meta generators, JavaScript frameworks)
  - Rule-based matching against known technology signatures
  - Confidence scoring for identifications
  - Version identification where available

### 4.5 Asset Inventory & Graph

#### FR-ASSET-001: Asset Inventory
- **WHY:** Central repository of all discovered external assets
- **WHAT:** Unified view of all assets with metadata, classification, and status
- **EXPECTED OUTCOME:** Browsable, searchable, filterable asset inventory
- **ACCEPTANCE CRITERIA:**
  - Asset types: Domain, Subdomain, IP Address, Service, Certificate
  - Each asset has: discovery source, first seen, last seen, status, confidence
  - Filtering by type, status, environment, criticality, ownership
  - Search by hostname, IP, technology, certificate subject
  - Pagination for large inventories

#### FR-ASSET-002: Asset Relationships
- **WHY:** Understanding connections between assets provides context
- **WHAT:** Relationship mapping between discovered assets
- **EXPECTED OUTCOME:** Navigable relationship graph
- **ACCEPTANCE CRITERIA:**
  - Relationships: Domain → Subdomain, Subdomain → IP, IP → Service, Service → Certificate, Subdomain → CNAME target
  - Relationship visualization (basic graph or tree view)
  - Relationship-based navigation (click through connections)
  - Relationship history (when connections changed)

### 4.6 Organizational Context Layer

#### FR-CTX-001: Ownership Attribution
- **WHY:** Knowing who owns an asset enables accountability and routing
- **WHAT:** Manual ownership assignment to assets
- **EXPECTED OUTCOME:** Assets attributed to team members or team labels
- **ACCEPTANCE CRITERIA:**
  - Assign to organization member or free-text team label
  - Bulk assignment (select multiple assets, assign owner)
  - Unowned asset reporting (list assets without owners)
  - Ownership history tracked

#### FR-CTX-002: Environment Classification
- **WHY:** Risk priority differs between production and development
- **WHAT:** Environment labeling for assets
- **EXPECTED OUTCOME:** Assets classified as Production, Staging, Development, Test, or Unknown
- **ACCEPTANCE CRITERIA:**
  - Manual classification per asset
  - Bulk classification support
  - Unclassified asset reporting
  - Environment influences risk prioritization

#### FR-CTX-003: Criticality Scoring
- **WHY:** Not all assets have equal business importance
- **WHAT:** Criticality levels for assets
- **EXPECTED OUTCOME:** Business importance reflected in prioritization
- **ACCEPTANCE CRITERIA:**
  - Levels: Critical, High, Medium, Low, Unassigned
  - Manual assignment with reason
  - Criticality influences risk prioritization weighting
  - Unassigned criticality treated as Medium for prioritization

#### FR-CTX-004: Expected State
- **WHY:** Core differentiator — distinguishing intended from unintended exposure
- **WHAT:** Mark specific services/ports/configurations as expected
- **EXPECTED OUTCOME:** Deviations from expected state trigger higher-priority alerts
- **ACCEPTANCE CRITERIA:**
  - Mark service/port as expected on a specific asset
  - Unexpected new services on assets with expected state defined trigger elevated priority
  - Expected state recorded with actor, timestamp, reason
  - Expected state changes logged in audit trail

### 4.7 Change Intelligence

#### FR-CHG-001: Change Detection
- **WHY:** Core product differentiator — changes drive security decisions
- **WHAT:** Scan-over-scan comparison identifying meaningful changes
- **EXPECTED OUTCOME:** Categorized, prioritized change feed
- **ACCEPTANCE CRITERIA:**
  - Change types: New Asset, Removed Asset, New Service, Removed Service, Certificate Change, DNS Change, Technology Change, IP Change
  - Each change includes: what changed, previous state, current state, timestamp, affected asset
  - Changes correlated with organizational context (is this a production asset? does it have an owner?)
  - Noise reduction: routine DNS TTL changes filtered out

#### FR-CHG-002: Change-Aware Alerts
- **WHY:** Alerts on raw findings cause fatigue; alerts on meaningful changes drive action
- **WHAT:** Notification system based on contextualized changes, not raw scan results
- **EXPECTED OUTCOME:** Alerts that respect organizational context and prioritization
- **ACCEPTANCE CRITERIA:**
  - Alert triggers based on change significance (new service on production > new service on development)
  - Alert channels: in-app, email (V1)
  - Alert customization: severity thresholds, environment filters
  - Alert deduplication: same change doesn't generate multiple alerts
  - Alerts reference specific evidence and changes

### 4.8 Risk & Findings

#### FR-RISK-001: Contextual Risk Prioritization
- **WHY:** Raw CVSS/severity scores don't reflect organizational reality
- **WHAT:** Risk scoring that incorporates organizational context
- **EXPECTED OUTCOME:** Prioritized finding list reflecting actual business risk
- **ACCEPTANCE CRITERIA:**
  - Risk inputs: finding severity, asset criticality, environment, ownership, expected state, confidence, exposure duration
  - Risk tiers: Critical, High, Medium, Low, Informational
  - Explanation of risk calculation (which factors contributed)
  - Risk recalculates when context changes (e.g., asset marked as production)

#### FR-RISK-002: Evidence Model
- **WHY:** Core differentiator — every finding must be explainable through evidence
- **WHAT:** Evidence chain attached to every finding
- **EXPECTED OUTCOME:** Full traceability from finding to raw observation
- **ACCEPTANCE CRITERIA:**
  - Every finding links to: scan observation(s), discovery method, raw data
  - Evidence classified per hierarchy (Observed, Connected, Historical, Human-Confirmed, Inferred, AI)
  - Evidence viewable in finding detail view
  - Evidence preserved even if finding is resolved

#### FR-RISK-003: Findings Management
- **WHY:** Findings require lifecycle management beyond just listing
- **WHAT:** Finding lifecycle with status management and decision tracking
- **EXPECTED OUTCOME:** Every finding progresses through a clear lifecycle
- **ACCEPTANCE CRITERIA:**
  - Finding statuses: New, Acknowledged, In Progress, Remediated, Verified, Accepted Risk, False Positive
  - Status changes logged with actor and timestamp
  - Filtering by status, severity, asset, environment, owner
  - Finding count and trends on dashboard

### 4.9 Decisions

#### FR-DEC-001: Risk Acceptance
- **WHY:** Some risks are intentionally accepted; this must be documented, not lost
- **WHAT:** Formal risk acceptance with required attributes
- **EXPECTED OUTCOME:** Documented, time-bounded risk acceptance that suppresses re-alerting
- **ACCEPTANCE CRITERIA:**
  - Required: reason, expiration date (max 1 year), scope (specific finding)
  - Optional: evidence, approval reference
  - Accepted risks suppress future alerts for the same finding until expiration
  - Approaching expiration triggers notification (30 days, 7 days before)
  - Expired acceptances reactivate the finding

#### FR-DEC-002: False Positive Marking
- **WHY:** False positives must be recordable without losing audit history
- **WHAT:** Mark a finding as false positive with justification
- **EXPECTED OUTCOME:** Finding suppressed from active views but retained in history
- **ACCEPTANCE CRITERIA:**
  - Required: reason
  - False positive findings hidden from default views but accessible via filter
  - If the same exposure reappears, it's compared against false positive patterns

#### FR-DEC-003: Decision Audit Trail
- **WHY:** Accountability for security decisions
- **WHAT:** Immutable log of all security decisions
- **EXPECTED OUTCOME:** Complete, queryable decision history
- **ACCEPTANCE CRITERIA:**
  - All decisions append-only (no deletion or modification)
  - Queryable by asset, user, decision type, date range
  - Decision history visible in asset detail view
  - Export capability for compliance (V2)

### 4.10 Remediation & Verification

#### FR-REM-001: Remediation Guidance
- **WHY:** Findings without guidance create investigation overhead
- **WHAT:** Specific remediation recommendations per finding type
- **EXPECTED OUTCOME:** Actionable steps for each finding category
- **ACCEPTANCE CRITERIA:**
  - Template-based guidance mapped to finding types
  - Guidance includes: what to do, where to do it, expected outcome
  - Severity-appropriate urgency indication

#### FR-REM-002: Verification
- **WHY:** Closes the remediation loop
- **WHAT:** Re-scan specific assets/services to confirm remediation effectiveness
- **EXPECTED OUTCOME:** Confirmed resolution or continued exposure
- **ACCEPTANCE CRITERIA:**
  - Manual verification trigger (user requests re-check)
  - Automated verification on next scheduled scan
  - Verification result updates finding status
  - Verification evidence stored alongside original finding

### 4.11 Notifications

#### FR-NOT-001: Notification System
- **WHY:** Users need to be informed of meaningful events without monitoring constantly
- **WHAT:** Multi-channel notification delivery
- **EXPECTED OUTCOME:** Timely, relevant notifications through preferred channels
- **ACCEPTANCE CRITERIA:**
  - Channels (V1): In-app, Email
  - Notification types: New critical finding, Certificate expiry warning, Risk acceptance expiring, Scan completion, Verification results
  - User-configurable notification preferences
  - Notification frequency controls (immediate, daily digest)

### 4.12 Audit & Compliance

#### FR-AUD-001: Audit Logging
- **WHY:** Security platform must practice what it preaches
- **WHAT:** Comprehensive audit trail of security-relevant actions
- **EXPECTED OUTCOME:** Immutable audit log queryable by authorized users
- **ACCEPTANCE CRITERIA:**
  - Events logged: Authentication (success/failure), role changes, member changes, domain changes, security decisions, scan configuration changes, API key operations
  - Each event: timestamp, actor, action, resource, result, IP address
  - Audit logs accessible to Admin and Owner roles
  - Audit logs immutable (append-only)
  - Retention: 1 year minimum (V1)

---

## 5. Non-Functional Requirements

### 5.1 Performance

| Metric | Target | Notes |
|---|---|---|
| API response time (P95) | < 500ms | For dashboard and asset queries |
| API response time (P99) | < 2s | For complex filtered queries |
| Scan initiation to first results | < 30 minutes | For initial domain discovery |
| Full scan cycle | < 24 hours | For typical organization (< 1,000 assets) |
| Dashboard load time | < 3s | Time to interactive |

### 5.2 Availability

| Metric | Target |
|---|---|
| Platform availability | 99.5% (V1 target) |
| Scan pipeline availability | 99% |
| Data durability | 99.99% |

### 5.3 Scalability

| Metric | V1 Target | V2 Target |
|---|---|---|
| Organizations | 100 | 1,000 |
| Assets per organization | 10,000 | 100,000 |
| Concurrent users | 50 | 500 |
| Scan throughput | 100K ports/hour | 1M ports/hour |

### 5.4 Security

See SecurityChecklist.md for comprehensive security requirements. Key NFRs:

- All data encrypted in transit (TLS 1.2+)
- Sensitive data encrypted at rest
- Tenant isolation enforced at data, API, and infrastructure layers
- MFA mandatory for all accounts
- Session management with idle and absolute timeouts
- Rate limiting on all public endpoints

### 5.5 Compliance Foundations

V1 does not target specific certifications but is architected to support future:

- SOC 2 Type II
- ISO 27001
- GDPR compliance for EU customers

### 5.6 Observability

- Structured logging (JSON) for all services
- Request tracing with correlation IDs
- Metrics collection (API latency, scan throughput, error rates, queue depth)
- Health check endpoints for all services
- Alerting on service degradation

---

## 6. Scope & Thesis Validation Matrix

Every platform capability is evaluated directly against the core thesis: *"Continuously observe an organization's external attack surface and turn meaningful changes into useful, explainable, organization-aware decisions."*

| Capability | Priority | Justification | Impact on Core Thesis |
|---|---|---|---|
| **Domain Onboarding & DNS Verification** | **P0** | Legal & ethical requirement; establishes tenant boundary | Critical entry point |
| **Subdomain Discovery (CT Logs + DNS Brute)** | **P0** | Essential for external attack surface mapping | Core discovery input |
| **DNS Record Collection & Tracking** | **P0** | Foundation for change detection and IP resolution | Core observation input |
| **IP Resolution & Tracking** | **P0** | Required for service discovery and IP drift tracking | Core observation input |
| **Top-1,000 TCP Port Scanning** | **P0** | Primary external service exposure vector | Core observation input |
| **Banner Grabbing & Tech Identification** | **P0** | Identifies asset stack and asset identity | Core understanding input |
| **TLS Certificate Extraction & Expiry** | **P0** | High-value, low-noise security intelligence | Core exposure input |
| **Asset Inventory & Relationships Graph** | **P0** | Maps Subdomain → IP → Service → Certificate | Core relational model |
| **Ownership Attribution** | **P0** | Answers "Who owns this asset?" | Core organizational context |
| **Environment Classification** | **P0** | Answers "Is this Production or Staging?" | Core organizational context |
| **Criticality Scoring** | **P0** | Answers "How important is this to the business?" | Core organizational context |
| **Expected State Marking** | **P0** | Distinguishes intended from unintended exposure | Core organizational context |
| **Scan-over-Scan Change Detection** | **P0** | Answers "What changed since last scan?" | Core change intelligence |
| **Contextual Risk Prioritization** | **P0** | Ranks findings by business risk + context | Core decision input |
| **Traceable Evidence Model** | **P0** | Links every finding to raw observation data | Core explainability |
| **Human Security Decisions** | **P0** | Records Risk Acceptance & False Positive | Core decision memory |
| **Remediation Guidance** | **P0** | Actionable steps for identified issues | Core action guidance |
| **Remediation Verification** | **P0** | Re-scans to confirm resolution | Core loop closure |
| **Change-Aware Notifications** | **P0** | Alerts on meaningful contextual changes | Core operational workflow |
| **Passive DNS Integration** | **P1** | Secondary discovery source | Enriches discovery in V2 |
| **Cloud Connectors (AWS/GCP/Azure)** | **P1** | Enriches external assets with cloud tags | Enriches context in V2 |
| **SSO / SAML Identity Federation** | **P1** | Enterprise authentication requirement | Enriches enterprise UX in V2 |
| **Jira / Slack / Webhook Integrations** | **P1** | Workflow integration | Enriches operations in V2 |
| **ARES Validation Integration** | **P1** | Controlled offensive verification | Enriches proof in V2 |
| **Reusable Organizational Rules** | **P1** | Reusable pattern matching across assets | Enriches rule engine in V2 |
| **Behavioral Baselines** | **P2** | Anomaly detection from historical patterns | Requires 6+ months scan data |
| **AI Natural Language Investigation** | **P2** | Conversational query over OSM | Requires mature AI layer |
| **Autonomous Exploitation** | **REJECTED** | ARES scope; security and liability risk | Outside EASM boundary |
| **Internal Network Scanning** | **REJECTED** | Outside external attack surface focus | Outside product boundary |
| **SIEM / EDR Replacement** | **REJECTED** | Different security product category | Outside product boundary |

---

## 7. Success Metrics

| Metric | Target | Measurement | Timeframe |
|---|---|---|---|
| Time to first insight | < 30 min | Domain verification to first finding | V1 launch |
| Discovery completeness | > 90% of known assets | Customer validation against known inventory | 3 months post-launch |
| Change detection accuracy | > 85% meaningful (non-noise) | User feedback on change alerts | 3 months post-launch |
| Decision utilization | > 30% of findings receive a decision | Usage analytics | 6 months post-launch |
| User retention | > 60% weekly active users (of active accounts) | Product analytics | 3 months post-launch |
| Context adoption | > 50% of assets have ownership or environment set | Usage analytics | 6 months post-launch |
| Alert relevance | < 20% of alerts marked irrelevant | User feedback | 3 months post-launch |

---

## 8. Open Product Questions

| # | Question | Impact | Classification |
|---|---|---|---|
| PQ-1 | Should V1 include a free tier or trial period? | Business model, onboarding friction | UNKNOWN |
| PQ-2 | What is the right scan frequency for V1? (hourly vs. daily vs. configurable) | Infrastructure cost, change detection latency | ASSUMPTION (daily default, configurable) |
| PQ-3 | Should domain verification support HTTP-based verification in addition to DNS? | Onboarding friction for users without DNS control | ASSUMPTION (DNS-only for V1, more secure) |
| PQ-4 | How should the platform handle shared hosting / CDN IPs? (1 IP serving many orgs) | Discovery accuracy, false attribution | HYPOTHESIS (detect and flag, don't attribute) |
| PQ-5 | What is the maximum number of root domains per organization in V1? | Pricing model, scan infrastructure sizing | UNKNOWN |
| PQ-6 | Should MFA be truly mandatory, or mandatory-with-grace-period for onboarding? | User experience vs. security tradeoff | ASSUMPTION (mandatory, setup during onboarding) |
