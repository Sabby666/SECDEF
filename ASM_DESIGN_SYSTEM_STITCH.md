# ATTACK SURFACE MONITOR (ASM) — STITCH-FIRST UI/UX REDESIGN SPECIFICATION

## 1. Executive Summary & Design Philosophy

The **Attack Surface Monitor (ASM)** UI/UX redesign transforms the interface from a visually dense, dark-themed SaaS template into a **light-first, professional cybersecurity workspace**. Designed for daily use by security engineers, security analysts, and technical operators, the new design emphasizes **calmness, clarity, precision, and high signal-to-noise ratio**.

### Core Design Principles:
1. **Light-First & Restrained**: Built on pure white (`#FFFFFF`) backgrounds with soft neutral surfaces (`#F8F9FB`, `#F3F4F6`). Zero dark-mode default, zero neon glow, zero background gradients.
2. **State-Driven Color**: Color is strictly functional. Red (`#DC2626`), Amber (`#D97706`), Green (`#16A34A`), and Blue (`#2563EB`) convey security status, severity, and verification state—never decorative aesthetics.
3. **Workspace-First Layouts**: Replaces redundant top-level KPI cards and nested bordered boxes with high-density data tables, split-pane drawers, timelines, and focused investigation graphs.
4. **Structured Information Hierarchy**: Clean typography hierarchy (Inter / System Sans) with monospace formatting strictly reserved for technical identifiers (`IPs`, `ports`, `hashes`, `domains`, `CPEs`).
5. **Subordinated AI Assistance**: AI features are framed as an inline assistant where authoritative ASM evidence is visually distinguished from AI-generated hypotheses.

---

## 2. Global Color System & Design Tokens

```css
:root {
  /* Core Backgrounds */
  --bg-app: #FFFFFF;
  --bg-surface-secondary: #F8F9FB;
  --bg-surface-tertiary: #F3F4F6;
  --bg-surface-hover: #F1F5F9;

  /* Borders & Dividers */
  --border-subtle: #E5E7EB;
  --border-strong: #D1D5DB;
  --border-focused: #2563EB;

  /* Typography Colors */
  --text-primary: #111827;     /* Near-black for primary titles/body */
  --text-secondary: #4B5563;   /* Neutral gray for metadata/labels */
  --text-tertiary: #9CA3AF;    /* Muted timestamps and placeholders */
  --text-brand: #2563EB;

  /* Security Semantic Colors (State-Only) */
  --severity-critical-bg: #FEF2F2;
  --severity-critical-text: #DC2626;
  --severity-critical-border: #FCA5A5;

  --severity-high-bg: #FFFBEB;
  --severity-high-text: #D97706;
  --severity-high-border: #FCD34D;

  --severity-medium-bg: #EFF6FF;
  --severity-medium-text: #2563EB;
  --severity-medium-border: #93C5FD;

  --severity-low-bg: #F3F4F6;
  --severity-low-text: #4B5563;
  --severity-low-border: #D1D5DB;

  --state-verified-bg: #F0FDF4;
  --state-verified-text: #16A34A;
  --state-verified-border: #86EFAC;

  /* Layout Spacing & Radius */
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;
  --shadow-subtle: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
}
```

---

## 3. Typography Hierarchy

| Level | Size | Weight | Line Height | Application |
|---|---|---|---|---|
| **Page Title** | 24px | 600 (SemiBold) | 32px | Top bar / page header title |
| **Section Header** | 16px | 600 (SemiBold) | 24px | Drawer titles, card headers, section dividers |
| **Body Primary** | 14px | 400 (Regular) | 20px | Table cell text, description paragraphs |
| **Body Medium** | 14px | 500 (Medium) | 20px | Button labels, table header text, key metrics |
| **Supporting / Meta**| 12px | 400 (Regular) | 16px | Timestamps, status subtitles, breadcrumbs |
| **Monospace** | 13px | 400 (Regular) | 18px | IPs (`203.0.113.20`), Ports (`8443`), Domains, Hashes |

---

## 4. Global Navigation & Application Shell

### Navigation Architecture

```
---------------------------------------------------------------------------------------------
[ ASM ] Attack Surface Monitor    [ Search assets, findings (Cmd+K) ]   (Org: org-001) [User]
---------------------------------------------------------------------------------------------
Sidebar (Compact & Quiet)   | Main Workspace Area
                            |
Overview                    | Breadcrumb: Attack Surface / Assets / api.example.com
  Overview                  |
                            | Page Title: Assets Workspace
Attack Surface              | High-density table / Split-view workspace
  Assets                    |
  Domains                   |
  Services                  |
  Technologies              |
  Asset Graph               |
                            |
Exposure                    |
  Findings                  |
  Risk                      |
  Attack Paths              |
                            |
Monitoring                  |
  Changes                   |
  Scans                     |
  Verification              |
                            |
Intelligence                |
  Threat Intelligence       |
  Correlations              |
  AI Investigation          |
                            |
Actions                     |
  Remediation               |
  Approvals                 |
  Automations               |
                            |
Administration              |
  Organization              |
  Notifications             |
  Integrations              |
  Settings                  |
---------------------------------------------------------------------------------------------
```

---

## 5. Representative Screen Specifications (14 Screens)

### Screen 1: Overview
- **Header**: Minimal context bar showing current active organization (`org-001`), monitoring health badge (`Verified`), and last full scan status (`12m ago`).
- **Section 1: Attention Required**: Compact queue of highest priority security conditions (e.g. `Critical: api.example.com - Unexpected public 8443/tcp service`, `High: staging.example.com - Unverified ownership candidate`).
- **Section 2: Recent Changes Feed**: Sequential list of latest attack surface events with timestamps and risk tags.
- **Section 3: Attack Surface Summary**: Minimal metric strip for total discovered Assets (`142`), Active Domains (`12`), Services (`48`), and Open Findings (`7`).
- **Section 4: Scan Coverage**: Compact table of recent scan jobs and execution status.

---

### Screen 2: Assets Workspace
- **Top Controls**: Global search input (`Filter by IP, domain, CPE, host...`), pill filters (`Environment`, `Criticality`, `Service Type`, `Owner`).
- **Primary Data Grid**:
  - Columns: `Asset Identifier` (mono), `Type`, `Environment`, `Criticality`, `Risk Score`, `Last Seen`, `Actions`.
  - Hover row highlights subtly with `#F8F9FB`.
  - Clicking any row slides open the **Asset Detail Drawer**.

---

### Screen 3: Asset Detail Drawer (Split View)
- **Slide-out Drawer Width**: 600px right-hand side panel.
- **Header**: Asset name (`api.example.com`), environment badge, risk score pill, action buttons (`Verify Domain`, `Trigger Scan`).
- **Tabs**:
  1. `Overview`: Identity, IP resolution, cloud provider, location.
  2. `Services & Ports`: Exposed ports list (`443/tcp HTTP`, `8443/tcp HTTPS`).
  3. `Technologies`: Detected tech stack (e.g., `Nginx 1.24`, `OpenSSL 3.0.2`).
  4. `Relationships`: Connected graph nodes (DNS parent, subdomains, reverse IP neighbors).
  5. `Findings`: Active vulnerabilities/exposures bound to this asset.
  6. `Changes`: Historical change events for this asset.
  7. `Evidence`: Raw HTTP headers, certificate payloads, scan raw output.

---

### Screen 4: Findings Queue
- **Header**: Filter bar (`Severity: Critical/High`, `Status: Open/In-Review`, `Asset`, `Age`).
- **Data Grid**:
  - Columns: `Severity Badge`, `Finding Title`, `Affected Asset` (mono), `Category`, `First Detected`, `Status`.
- **Row Interaction**: Click opens **Finding Detail Investigation Workspace**.

---

### Screen 5: Finding Detail (Investigation Workspace)
- **Layout**: Two-column layout (70% Investigation / 30% Context & Metadata).
- **Structured Sections**:
  1. `Header`: Finding Title, Severity Badge (`CRITICAL`), Status (`OPEN`), Affected Asset link.
  2. `Why This Matters`: Concise security explanation of the exposure impact.
  3. `What Was Observed`: Specific empirical observations recorded by the scanner.
  4. `Why ASM Considers This Risky`: Risk engine derivation and factor contributions.
  5. `Evidence`: Formatted HTTP response snippet / certificate payload block (monospace).
  6. `Expected State & Organizational Memory`: Active context override rules or memory records.
  7. `Recommended Action & Remediation`: Prescribed steps to remediate.
  8. `Verification Status`: Evidence-based verification run history.

---

### Screen 6: Changes Timeline
- **Layout**: Vertical timeline grouped by date (`Today`, `Yesterday`, `This Week`).
- **Timeline Item Structure**:
  - Timestamp (`10:42 UTC`) | Event Badge (`NEW SERVICE`) | Asset (`api.example.com:8443`)
  - `Reason`: Previously unseen externally reachable port.
  - `Evidence Link`: Scan `#1842`
  - `Risk Band`: `HIGH`
  - Inline action buttons: `Mark Expected State`, `Create Remediation Action`.

---

### Screen 7: Discovery Operational Workflow
- **Top Section**: Domain Discovery Form
  - `Target Domain Input` (`example.com`)
  - `Discovery Technique Toggles`: `[x] Certificate Transparency`, `[x] Active DNS Brute`, `[x] Passive DNS`, `[x] Service Probe`.
  - Button: `[ Run Discovery ]`
- **Bottom Section**: Candidate Pipeline Table
  - Tabs: `Candidates Discovered (14)`, `Validated Assets (128)`, `Rejected Candidates (2)`.
  - Table showing candidate hostname, discovery source, verification status, and `[ Approve Asset ]` / `[ Ignore ]` buttons.

---

### Screen 8: Asset Graph Investigation Workspace
- **Layout**: Three-pane workspace.
  - **Left Pane (240px)**: Graph filters, node type toggles, depth slider.
  - **Center Pane (Flexible)**: Interactive SVG node tree with clean connection links.
  - **Right Pane (320px)**: Node details for selected node (Asset metadata, connected services, associated findings).

---

### Screen 9: Risk Explanation View
- **Focus**: Transparent, factor-based risk breakdown rather than arbitrary numeric badges.
- **Components**:
  - `Overall Risk Rating`: `HIGH (78/100)`
  - `Risk Derivation Breakdown`: Base exposure score + Blindspot penalty + Organizational memory modifier.
  - `Contributing Factors Table`: Factor, Impact, Evidence reference.
  - `Action Plan`: Recommended risk reduction steps.

---

### Screen 10: AI Investigation Assistant
- **Structure**: Three-panel layout.
  - **Left History (220px)**: Recent AI investigation sessions.
  - **Center Conversation (Flexible)**: Chat interface where **AI interpretation** is styled with a distinct subtle background, while **Authoritative ASM Evidence** blocks are enclosed in monospace technical callouts.
  - **Right Referenced Objects (300px)**: Live links and metadata of ASM assets/findings referenced during the investigation session.

---

### Screen 11: Actions & Approvals Queue
- **Focus**: Human-in-the-loop security authorization queue.
- **Table Columns**:
  - `Proposed Action` (e.g., `VERIFY_HTTP_ENDPOINT`, `MARK_EXPECTED_STATE`)
  - `Target Resource`
  - `Requested By`
  - `Risk Class` (`CLASS_A`, `CLASS_B`, `CLASS_C`)
  - `Authorization Requirement` (`Requires ADMIN Approval`)
  - `Status` (`PENDING_APPROVAL`)
  - `Actions`: `[ Approve Action ]` / `[ Reject ]`

---

### Screen 12: Organization Context Workspace
- **Tabs**: `Expected State Rules`, `Security Decisions`, `Organizational Memory`, `Asset Ownership`, `Environment Definitions`.
- **Data Table**: Shows active decisions, memory expiration dates, creator user, scope level (`ORG` vs `ASSET`), and revocation controls.

---

### Screen 13: Monitoring & Guided Domain Onboarding
- **Top Guided Step Bar**: `1. Enter Domain` -> `2. Verify Ownership` -> `3. Configure Monitoring` -> `4. Discovery` -> `5. Review`.
- **Domain Inventory Table**: Domain name, Verification status (`Verified`), Active schedule (`Every 6 hours`), Discovered assets count, Last run timestamp.

---

### Screen 14: Administration & Settings
- **Sections**: `Organization Details`, `User Memberships & Roles`, `API Keys`, `Webhook Integrations`, `Scan Egress Guard Config`.
- Clean tabular forms with clear role-based access markers (`ADMIN ONLY`).

---

## 6. Stitch Screen-to-Route & Implementation Mapping

| # | Stitch Screen | Frontend Route (`apps/web-frontend`) | Component / File Location | API Dependencies | Status |
|---|---|---|---|---|---|
| 1 | **Overview** | `/` | `app/page.tsx`, `components/dashboard/` | `/api/v1/organizations/{org_id}/assets`, `/findings`, `/scans` | Redesign UI |
| 2 | **Assets** | `/assets` | `app/assets/page.tsx` | `/api/v1/organizations/{org_id}/assets` | Redesign UI |
| 3 | **Asset Detail** | `/assets?id={id}` | `components/assets/AssetDetailDrawer.tsx` | `/api/v1/organizations/{org_id}/assets/{id}` | Redesign UI |
| 4 | **Findings** | `/findings` | `app/findings/page.tsx` | `/api/v1/organizations/{org_id}/findings` | Redesign UI |
| 5 | **Finding Detail**| `/findings/{id}` | `app/findings/[id]/page.tsx` | `/api/v1/organizations/{org_id}/findings/{id}` | Redesign UI |
| 6 | **Changes** | `/changes` | `app/changes/page.tsx` | `/api/v1/organizations/{org_id}/changes` | Redesign UI |
| 7 | **Discovery** | `/discovery` | `app/discovery/page.tsx` | `/api/v1/organizations/{org_id}/discovery` | Redesign UI |
| 8 | **Asset Graph** | `/graph` | `app/graph/page.tsx` | `/api/v1/organizations/{org_id}/graph` | Redesign UI |
| 9 | **Risk** | `/risk` | `app/risk/page.tsx` | `/api/v1/organizations/{org_id}/risk` | Redesign UI |
| 10| **AI Assistant**| `/assistant` | `app/assistant/page.tsx` | `/api/v1/organizations/{org_id}/assistant` | Redesign UI |
| 11| **Actions** | `/actions` | `app/actions/page.tsx` | `/api/v1/organizations/{org_id}/actions` | Redesign UI |
| 12| **Org Context** | `/context` | `app/context/page.tsx` | `/api/v1/organizations/{org_id}/context` | Redesign UI |
| 13| **Monitoring** | `/domains` | `app/domains/page.tsx` | `/api/v1/organizations/{org_id}/domains` | Redesign UI |
| 14| **Settings** | `/settings` | `app/settings/page.tsx` | `/api/v1/organizations/{org_id}/settings` | Redesign UI |

---

## 7. Preservation of Backend & Security Boundaries

1. **Zero Schema/API Changes**: All redesigned screens connect directly to existing FastAPI `/api/v1/organizations/{org_id}/*` routes.
2. **Strict Auth & RBAC**: Header authentication (`X-User-ID`, `X-Org-ID`) and role permissions (`owner`, `admin`, `member`, `viewer`) remain enforced in all requests.
3. **Tenant Isolation**: All queries remain scoped by `{org_id}` URL parameters and authorization middleware.
4. **Action Approvals**: Human authorization controls for Class A/B/C actions remain untouched.

---

## 8. Frontend Implementation Plan (Pending Approval)

1. **Phase A: Base Design System & CSS Variables**:
   - Update `apps/web-frontend/app/globals.css` with the light-first design tokens.
   - Create reusable base primitives (`Button`, `Input`, `Table`, `Badge`, `Drawer`, `StatusPill`).

2. **Phase B: Global Shell & Compact Navigation**:
   - Refactor `components/layout/Sidebar.tsx` into the quiet 7-group hierarchy.
   - Update `components/layout/Header.tsx` with light minimal theme and global search modal.

3. **Phase C: Screen-by-Screen Component Redesign**:
   - Refactor Overview page (`app/page.tsx`) to attention queue & timeline layout.
   - Refactor Assets (`app/assets/page.tsx`) & Asset Detail Drawer.
   - Refactor Findings (`app/findings/page.tsx`) & Finding Detail Workspace.
   - Refactor Changes, Graph, Discovery, Risk, Actions, AI Assistant, Context, Domains, and Settings.

4. **Phase D: Validation & Testing**:
   - Run production frontend build (`npm run build`).
   - Verify full backend API connectivity and browser execution.
