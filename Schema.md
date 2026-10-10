# Attack Surface Monitor — Data Schema & Conceptual Model

> **Status:** DRAFT — Pending Human Review
> **Last Updated:** 2026-08-27
> **Parent Document:** Architecture.md, TechSpec.md, PRD.md
> **Document Type:** Conceptual Data Model & Relational Schema

---

## 1. Schema Philosophy & Design Principles

1. **Explicit Multi-Tenancy:** Every tenant-scoped entity MUST include an `org_id` foreign key.
2. **Immutability Where Appropriate:** Audit events, observation snapshots, and decision records are strictly append-only.
3. **Traceable Evidence:** Every finding links to specific observation snapshot records to prove how and when data was gathered.
4. **Soft Deletes vs Hard Deletes:** Domain objects support soft deletion (`deleted_at` timestamp) to preserve audit trails, while sensitive tokens and temporary data are hard deleted.
5. **Relational Integrity with JSONB Extension:** Structured relationships rely on standard SQL foreign keys and indexes. Unstructured/semi-structured banners, DNS responses, and metadata use PostgreSQL `JSONB`.

---

## 2. Entity-Relationship Overview

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│  organizations  │───┬───│      users      │───┬───│   memberships   │
└────────┬────────┘   │   └─────────────────┘   │   └─────────────────┘
         │            │                         │
         │            └───┌─────────────────┐───┘
         │                │    sessions     │
         │                └─────────────────┘
         │
         ├───► ┌─────────────────┐
         │     │     domains     │
         │     └────────┬────────┘
         │              │
         ├───► ┌────────┴────────┐
         │     │     assets      │◄─────────────────────────────┐
         │     └────────┬────────┘                              │
         │              │                                       │
         ├───► ┌────────┴────────┐       ┌─────────────────┐    │
         │     │  observations   │──────►│    evidence     │    │
         │     └────────┬────────┘       └─────────────────┘    │
         │              │                                       │
         ├───► ┌────────┴────────┐                              │
         │     │     changes     │                              │
         │     └────────┬────────┘                              │
         │              │                                       │
         ├───► ┌────────┴────────┐       ┌─────────────────┐    │
         │     │    findings     │──────►│    decisions    │────┘
         │     └────────┬────────┘       └─────────────────┘
         │              │
         ├───► ┌────────┴────────┐
         │     │  verifications  │
         │     └─────────────────┘
         │
         └───► ┌─────────────────┐
               │  audit_events   │
               └─────────────────┘
```

---

## 3. Core Entity Definitions

### 3.1 Organization & Identity Core

#### Table: `organizations`
Represents a customer organization (tenant boundary).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Unique org ID |
| `name` | VARCHAR(255) | NOT NULL | Organization name |
| `slug` | VARCHAR(255) | NOT NULL, UNIQUE | URL-safe identifier |
| `status` | VARCHAR(50) | NOT NULL, DEFAULT 'active' | active, suspended, archived |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Last update timestamp |

#### Table: `users`
Global user identities.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Unique user ID |
| `email` | VARCHAR(255) | NOT NULL, UNIQUE | User email address |
| `password_hash` | VARCHAR(255) | NOT NULL | bcrypt hash |
| `full_name` | VARCHAR(255) | NOT NULL | User display name |
| `status` | VARCHAR(50) | NOT NULL, DEFAULT 'pending_verification' | pending_verification, active, disabled |
| `email_verified_at` | TIMESTAMPTZ | NULL | Timestamp of email verification |
| `mfa_enabled` | BOOLEAN | NOT NULL, DEFAULT false | Whether TOTP MFA is active |
| `mfa_secret_encrypted`| TEXT | NULL | AES-encrypted TOTP secret |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Account creation time |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Account update time |

#### Table: `memberships`
Maps users to organizations with specific RBAC roles.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Membership record ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `user_id` | UUID | NOT NULL, FK -> users(id) | User reference |
| `role` | VARCHAR(50) | NOT NULL | owner, admin, member, viewer |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Join timestamp |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Role change timestamp |
| **Indexes** | Unique `(org_id, user_id)` | | Enforces single role per org |

#### Table: `sessions`
Server-side active user sessions.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Session record ID |
| `session_token_hash`| VARCHAR(64) | NOT NULL, UNIQUE | SHA-256 hash of opaque token |
| `user_id` | UUID | NOT NULL, FK -> users(id) | Associated user |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Currently active org context |
| `ip_address` | INET | NOT NULL | IP at login/last active |
| `user_agent` | TEXT | NULL | Browser User-Agent header |
| `expires_at` | TIMESTAMPTZ | NOT NULL | Absolute expiration time |
| `idle_expires_at` | TIMESTAMPTZ | NOT NULL | Idle expiration time |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Creation time |
| `last_active_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Last activity time |

---

### 3.2 Domain & Discovery Core

#### Table: `domains`
Seed domains owned and verified by organizations.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Domain ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `domain_name` | VARCHAR(255) | NOT NULL | e.g. example.com |
| `status` | VARCHAR(50) | NOT NULL, DEFAULT 'pending_verification' | pending_verification, verified, failed, expired |
| `verification_token`| VARCHAR(128) | NOT NULL | Token for TXT verification |
| `verified_at` | TIMESTAMPTZ | NULL | Ownership confirmation time |
| `last_verified_at` | TIMESTAMPTZ | NULL | Last periodic re-check time |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Addition timestamp |
| **Indexes** | Unique `(org_id, domain_name)` | | Prevents duplicate domain in org |

#### Table: `assets`
Discovered infrastructure entities belonging to an organization.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Asset ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `domain_id` | UUID | NULL, FK -> domains(id) | Parent seed domain (if applicable) |
| `asset_type` | VARCHAR(50) | NOT NULL | subdomain, ip_address, service, certificate |
| `identifier` | TEXT | NOT NULL | e.g., api.example.com or 1.2.3.4 |
| `environment` | VARCHAR(50) | NOT NULL, DEFAULT 'unknown' | production, staging, development, test, unknown |
| `criticality` | VARCHAR(50) | NOT NULL, DEFAULT 'medium' | critical, high, medium, low, unassigned |
| `owner_id` | UUID | NULL, FK -> users(id) | Assigned owner (user) |
| `owner_team` | VARCHAR(255) | NULL | Assigned owner team label |
| `expected_state` | JSONB | NULL | Definition of expected ports/services |
| `first_seen_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Initial discovery time |
| `last_seen_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Latest observation time |
| `status` | VARCHAR(50) | NOT NULL, DEFAULT 'active' | active, inactive, archived |
| **Indexes** | Index `(org_id, asset_type, identifier)`, Index `(org_id, environment)`, Index `(org_id, owner_id)` | | Query optimization |

#### Table: `asset_relationships`
Directed graph connections between assets (e.g. Subdomain -> IP -> Service).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Relationship ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `source_asset_id` | UUID | NOT NULL, FK -> assets(id) | Parent asset |
| `target_asset_id` | UUID | NOT NULL, FK -> assets(id) | Connected asset |
| `relationship_type`| VARCHAR(50) | NOT NULL | resolves_to, runs_service, presents_cert, cname_to |
| `first_seen_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Initial connection time |
| `last_seen_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Latest connection time |
| `status` | VARCHAR(50) | NOT NULL, DEFAULT 'active' | active, historical |
| **Indexes** | Unique `(org_id, source_asset_id, target_asset_id, relationship_type)` | | Prevents duplicate edges |

---

### 3.3 Observation & Change Tracking

#### Table: `scans`
Metadata regarding a scan job execution.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Scan run ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `domain_id` | UUID | NOT NULL, FK -> domains(id) | Domain being scanned |
| `status` | VARCHAR(50) | NOT NULL, DEFAULT 'queued' | queued, running, completed, failed, partial |
| `started_at` | TIMESTAMPTZ | NULL | Execution start time |
| `completed_at` | TIMESTAMPTZ | NULL | Execution end time |
| `error_message` | TEXT | NULL | Summary of failure if applicable |
| `scan_metadata` | JSONB | NULL | Statistics (total ports, subdomains found) |

#### Table: `observations`
Raw point-in-time state recorded during a scan for an asset.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Observation ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `scan_id` | UUID | NOT NULL, FK -> scans(id) | Originating scan run |
| `asset_id` | UUID | NOT NULL, FK -> assets(id) | Target asset |
| `observation_type`| VARCHAR(50)| NOT NULL | dns_record, open_port, http_banner, tls_cert, tech_stack |
| `raw_data` | JSONB | NOT NULL | Unaltered scanner payload |
| `observed_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Timestamp of observation |
| **Indexes** | Index `(org_id, asset_id, observed_at)` | | Fast historical retrieval |

#### Table: `comparison_runs`
Scan-over-scan comparison job metadata and completeness tracking.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Comparison run ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `domain_id` | UUID | NOT NULL, FK -> domains(id) | Target domain reference |
| `current_scan_id` | UUID | NOT NULL, FK -> scans(id) | Target scan being compared |
| `previous_scan_id` | UUID | NULL, FK -> scans(id) | Baseline scan reference (NULL for first scan) |
| `status` | VARCHAR(50) | NOT NULL | completed, baseline_established, skipped_out_of_order, skipped_incomplete, failed |
| `current_scan_completeness` | VARCHAR(50) | NOT NULL | complete, partial, failed, unknown |
| `completeness_details` | JSONB | NULL | Per-observation-class completeness metadata |
| `changes_detected` | INTEGER | NOT NULL, DEFAULT 0 | Count of differences detected |
| `comparison_metadata` | JSONB | NULL | Engine version and execution metadata |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Creation timestamp |
| **Indexes** | Unique `(org_id, domain_id, current_scan_id)`, Index `(org_id, created_at)`, Index `(domain_id)` | | Idempotency & chronological ordering |

#### Table: `changes`
Scan-over-scan differences calculated by the Change Engine.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Change ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `comparison_run_id` | UUID | NOT NULL, FK -> comparison_runs(id) | Associated comparison run |
| `asset_id` | UUID | NULL, FK -> assets(id) | Target asset (NULL for relationship changes) |
| `change_type` | VARCHAR(50) | NOT NULL | asset_added, asset_removed, asset_property_changed, relationship_added, relationship_removed |
| `entity_type` | VARCHAR(50) | NOT NULL | asset, relationship |
| `entity_identifier` | TEXT | NOT NULL | Canonical identifier (e.g. subdomain:api.example.com) |
| `previous_state` | JSONB | NULL | Previous state snapshot |
| `current_state` | JSONB | NULL | Current state snapshot |
| `previous_scan_id` | UUID | NULL, FK -> scans(id) | Previous scan ID |
| `current_scan_id` | UUID | NOT NULL, FK -> scans(id) | Current scan ID |
| `evidence` | JSONB | NULL | Provenance and safety gate reasoning |
| `detected_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Detection time |
| **Indexes** | Unique `(org_id, comparison_run_id, change_type, entity_type, entity_identifier)`, Index `(org_id, detected_at)`, Index `(org_id, change_type)`, Index `(comparison_run_id)` | | Deduplication & feed filtering |

---

### 3.4 Findings, Risk & Decisions

#### Table: `findings`
Identified security exposures requiring triage or action.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Finding ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `asset_id` | UUID | NOT NULL, FK -> assets(id) | Associated asset |
| `finding_type` | VARCHAR(100)| NOT NULL | unexpected_open_port, expired_cert, weak_tls, dns_wildcard_misconfig, exposed_admin_panel |
| `title` | VARCHAR(255)| NOT NULL | Concise title |
| `description` | TEXT | NOT NULL | Detailed description |
| `raw_severity` | VARCHAR(20) | NOT NULL | critical, high, medium, low, info |
| `contextual_risk_score`| NUMERIC(5,2)| NOT NULL | Calculated score (0.00 - 100.00) |
| `status` | VARCHAR(50) | NOT NULL, DEFAULT 'new' | new, acknowledged, in_progress, remediated, verified, accepted_risk, false_positive |
| `confidence` | NUMERIC(3,2)| NOT NULL, DEFAULT 1.00 | Confidence score (0.00 - 1.00) |
| `remediation_guidance`| TEXT | NULL | Step-by-step resolution guide |
| `first_detected_at`| TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Initial detection time |
| `last_detected_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Latest detection time |
| **Indexes** | Index `(org_id, status, raw_severity)`, Index `(org_id, contextual_risk_score DESC)` | | Triage sorting |

#### Table: `evidence`
Links findings to specific raw observations or external artifacts.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Evidence ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `finding_id` | UUID | NOT NULL, FK -> findings(id) | Parent finding |
| `observation_id`| UUID | NULL, FK -> observations(id) | DB observation reference |
| `evidence_type` | VARCHAR(50) | NOT NULL | observed, connected, historical, human, inferred, ai |
| `s3_object_key` | TEXT | NULL | Object storage path for large payloads |
| `payload` | JSONB | NULL | Inline JSON evidence payload |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Timestamp |

#### Table: `decisions`
Human-authoritative decisions regarding risk acceptances, false positives, or expected exposure state.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Decision ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `finding_id` | UUID | NULL, FK -> findings(id) | Specific finding (if decision targets finding) |
| `asset_id` | UUID | NOT NULL, FK -> assets(id) | Target asset |
| `service_port` | INTEGER | NULL | Targeted TCP port (if decision is port-scoped) |
| `actor_id` | UUID | NOT NULL, FK -> users(id) | Human decider |
| `decision_type` | VARCHAR(50) | NOT NULL | accept_risk, mark_false_positive, mark_expected |
| `reason` | TEXT | NOT NULL | Mandatory justification for decision |
| `evidence_snapshot`| JSONB | NULL | Copy of evidence state at time of decision |
| `expires_at` | TIMESTAMPTZ | NULL | Expiry date for time-bounded risk acceptance |
| `status` | VARCHAR(50) | NOT NULL, DEFAULT 'active' | active, revoked, expired |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Decision timestamp |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Revocation / update timestamp |
| **Indexes** | Index `(org_id, asset_id, service_port)`, Index `(org_id, finding_id)`, Index `(expires_at) WHERE status='active'` | | Decision lookup & expiry checking |

#### Table: `expected_states`
Explicit definitions of expected/approved open ports, services, and certificates per asset.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Expected state ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `asset_id` | UUID | NOT NULL, FK -> assets(id) | Target asset |
| `port` | INTEGER | NOT NULL | Approved open TCP port |
| `protocol` | VARCHAR(20) | NOT NULL, DEFAULT 'tcp' | tcp, udp |
| `service_name` | VARCHAR(50) | NULL | Approved service name (e.g. https, ssh) |
| `reason` | TEXT | NOT NULL | Explanation of why exposure is intended |
| `created_by_id` | UUID | NOT NULL, FK -> users(id) | User who approved expected state |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Creation timestamp |
| **Indexes** | Unique `(org_id, asset_id, port, protocol)` | | Enforces single rule per port |

#### Table: `verifications`
Tracks re-scanning and validation of remediated findings.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Verification ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `finding_id` | UUID | NOT NULL, FK -> findings(id) | Target finding |
| `requested_by_id`| UUID | NOT NULL, FK -> users(id) | Requesting user |
| `status` | VARCHAR(50) | NOT NULL, DEFAULT 'pending' | pending, running, verified_resolved, verified_still_exposed, failed |
| `result_summary` | TEXT | NULL | Summary of verification check |
| `verified_at` | TIMESTAMPTZ | NULL | Completion timestamp |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Request timestamp |

---

### 3.5 Notifications & Governance

#### Table: `notifications`
In-app and email alert delivery records.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Notification ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `user_id` | UUID | NULL, FK -> users(id) | Recipient user (null if org-wide) |
| `notification_type`| VARCHAR(50)| NOT NULL | critical_finding, cert_expiring, decision_expiring, scan_completed, verification_completed |
| `title` | VARCHAR(255)| NOT NULL | Alert header |
| `message` | TEXT | NOT NULL | Body message |
| `link_url` | TEXT | NULL | Deep link to asset/finding |
| `read_at` | TIMESTAMPTZ | NULL | Timestamp when user marked read |
| `sent_email_at` | TIMESTAMPTZ | NULL | Timestamp of email delivery |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Creation timestamp |
| **Indexes** | Index `(org_id, user_id, read_at)` | | Unread notification queries |

#### Table: `organization_rules` (V2 Preparation)
Explicit reusable pattern rules created by Admins (e.g. auto-tagging environment).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Rule ID |
| `org_id` | UUID | NOT NULL, FK -> organizations(id) | Tenant reference |
| `rule_type` | VARCHAR(50) | NOT NULL | environment_tag, ownership_tag, alert_suppression |
| `pattern_match` | VARCHAR(255)| NOT NULL | Glob/regex e.g. `*.staging.example.com` |
| `target_attribute` | VARCHAR(50)| NOT NULL | environment, owner_team, criticality |
| `attribute_value` | VARCHAR(255)| NOT NULL | e.g. "staging", "Team-Alpha", "high" |
| `created_by_id` | UUID | NOT NULL, FK -> users(id) | Creator reference |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Creation timestamp |

#### Table: `audit_events`
Immutable security and administrative log.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Audit event ID |
| `org_id` | UUID | NULL, FK -> organizations(id) | Tenant reference (null for system events) |
| `actor_id` | UUID | NULL, FK -> users(id) | User performing action |
| `event_type` | VARCHAR(100)| NOT NULL | auth.login_success, domain.added, decision.created, etc. |
| `resource_type` | VARCHAR(50) | NOT NULL | user, organization, domain, asset, finding, decision |
| `resource_id` | UUID | NULL | Affected resource ID |
| `ip_address` | INET | NOT NULL | Source IP |
| `user_agent` | TEXT | NULL | Client browser string |
| `details` | JSONB | NULL | Context metadata (before/after values) |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT clock_timestamp() | Immutable event time |
| **Indexes** | Index `(org_id, created_at DESC)`, Index `(actor_id, created_at DESC)` | | Log searching |

---

## 4. Database Lifecycle & Retention Policies

| Entity Class | Retention Strategy | Action on Expiration |
|---|---|---|
| `sessions` | Hard delete after `expires_at + 7 days` | Automated cleanup task (hourly) |
| `observations` | Retain 90 days of full raw observations; roll up historical summaries | Partition pruning / Archival to Cold Object Storage |
| `changes` | Retain indefinitely | Immutable log of attack surface evolution |
| `findings` | Retain indefinitely | Archived when asset is removed/archived |
| `decisions` | Retain indefinitely | Append-only audit history |
| `audit_events` | Retain minimum 1 year (configurable by plan) | Export to cold storage after 365 days |
