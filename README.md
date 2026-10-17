# SECDEF

**External Attack Surface Management & Exposure Intelligence Platform**

SECDEF is an open-source cybersecurity platform designed to continuously map, inventory, assess, and monitor internet-exposed assets across an organization's perimeter.

SECDEF provides security teams with visibility into external digital footprints, discovering newly created subdomains, unmanaged cloud services, dangling DNS records, expiring SSL/TLS certificates, and exposed application services before adversaries exploit them.

---

## The Problem

Modern enterprise attack surfaces are highly dynamic:
- Development teams launch cloud workloads, APIs, and microservices outside centralized IT tracking.
- Ephemeral infrastructure and cloud resources create orphan assets and dangling DNS records susceptible to subdomain takeovers.
- Point-in-time penetration tests and monthly vulnerability scans fail to detect risks that appear between scanning intervals.
- Security teams lack provenance tracking to distinguish verified organizational assets from third-party shadows.

SECDEF addresses these challenges by continuously ingesting external telemetry, enforcing cryptographic target verification, and providing deterministic risk modeling and automated remediation governance.

---

## Capabilities

### Implemented Capabilities
- **Domain Onboarding & Cryptographic Ownership Verification**: Seed domain onboarding with 256-bit cryptographic DNS TXT token challenge verification.
- **Target Scope Authorization**: Strict perimeter safety policy ensuring scan jobs cannot be dispatched against unverified or unauthorized domains (`HTTP 400 Target Authorization Denial`).
- **Server-Authoritative RBAC & Multi-Tenant Isolation**: 4-tier server-enforced role-based access control (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`) derived from database membership records (`memberships.role`). Client role tampering is strictly blocked with `HTTP 403 Forbidden`.
- **Automated Discovery Pipeline**: Telemetry ingestion from Certificate Transparency (CT) logs and DNS reconnaissance, routing raw observations into an approval queue.
- **Candidate Asset Pipeline**: Staging discovered subdomains for triage, validation, and promotion into active inventory or explicit rejection.
- **Operational Asset Inventory**: Unified inventory of verified hostnames, IP addresses, running services, and certificates with business context overrides (`Criticality`, `Environment`, `Owner Team`).
- **Security Findings & Remediation Verification**: Vulnerability and exposure catalog with active comparative verification probes to prove whether a reported condition is remediated.
- **Perimeter Change Intelligence**: Timeline tracking newly observed services, configuration drifts, and decommissioned assets.
- **Deterministic Risk Scoring**: Formula-based risk calculations evaluating asset criticality, exposure depth, and vulnerability severity.
- **Action Orchestration Lifecycle**: Safe multi-stage remediation workflow (`PROPOSE` → `APPROVE` → `EXECUTE` → `ROLLBACK`) with execution logging.
- **Autonomous Policy Governance**: Tenant-configurable automation policies governing automated verification and remediation allowlists.
- **Webhook Alerts & SSRF Egress Defense**: Notification channels with strict SSRF egress filters blocking private, loopback, and unresolvable destinations.
- **API Key Lifecycle & Immutable Audit Trail**: Cryptographically hashed API key provisioning with event-level audit logging (`audit_events`).
- **Subordinate AI Security Assistant**: Natural language investigation interface grounded in authoritative scan observations with conversation persistence.
- **Asset Inventory CSV Export**: Client-side asset inventory export with structured schema validation.

### Planned Capabilities (Roadmap)
- Direct cloud provider API connectors (AWS Route53, Google Cloud DNS, Azure DNS).
- Distributed multi-region scanner worker orchestration with mTLS job transport.
- Native integration connectors for enterprise SOAR/SIEM platforms (Jira, Splunk, PagerDuty).
- Continuous BGP routing and Autonomous System Number (ASN) prefix tracking.

---

## Architecture

The platform is designed as a modular service architecture:

```
┌────────────────────────────────────────────────────────┐
│                   Web Frontend                         │
│     Next.js 14 (App Router) • React 18 • TypeScript    │
│              Vanilla CSS Design System                 │
└───────────────────────────┬────────────────────────────┘
                            │ REST / JSON (HTTP)
                            ▼
┌────────────────────────────────────────────────────────┐
│                   Control Plane                        │
│          FastAPI • SQLAlchemy 2.0 (Async)              │
│        Server-Authoritative RBAC & Audit Engine        │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────┐ ┌───────────────────────┐
│     Persistent Storage       │ │     Redis & ARQ       │
│  SQLite (Dev) / Postgres (Prod)│ │   Task Message Broker │
└──────────────────────────────┘ └──────────┬────────────┘
                                            │
                                            ▼
                                 ┌───────────────────────┐
                                 │    Scanner Worker     │
                                 │ Network Probing & DNS │
                                 │   SSRF Egress Guard   │
                                 └───────────────────────┘
```

- **`apps/control-plane/`**: FastAPI REST API handling tenant management, domain onboarding, findings, risk engine, automation policies, and audit logging.
- **`apps/web-frontend/`**: Next.js 14 web application providing a full-featured console with responsive interfaces, drawer inspectors, and live metrics.
- **`apps/scanner-worker/`**: Background worker process executing DNS lookups, TLS inspections, and remediation verification probes.
- **`packages/shared-contracts/`**: Shared Pydantic models, DTOs, and enumeration contracts shared between services.
- **`infrastructure/docker/`**: Container configurations for services, databases, and reverse proxies.

---

## Technology Stack

- **Backend**: Python 3.12+, FastAPI, SQLAlchemy 2.0 (AsyncIO), Alembic, Pydantic v2, Structlog, aiosqlite, asyncpg, dnspython, cryptography.
- **Frontend**: Next.js 14, React 18, TypeScript, Lucide Icons, Vanilla CSS.
- **Database**: SQLite (Local development) / PostgreSQL (Production).
- **Cache & Message Broker**: Redis 7+, ARQ task runner.
- **Testing & E2E**: Pytest, pytest-asyncio, Playwright (Chromium E2E automation).

---

## Getting Started

### Prerequisites
- Python 3.12 or newer
- Node.js 18.x or newer
- Git

### 1. Repository Setup
```bash
git clone <repository-url>
cd attack-surface-monitor
```

### 2. Environment Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```
Edit `.env` to configure your local secret key, database path, and CORS origins.

### 3. Backend Setup (Control Plane)
```bash
cd apps/control-plane
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pip install -e "../../packages/shared-contracts/python"

# Run FastAPI development server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Frontend Setup (Web Console)
In a separate terminal:
```bash
cd apps/web-frontend
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Verification & Testing

### Python Unit & Integration Tests
```bash
pytest
```

### Full-Stack Security Mutation & RBAC Verification
Run the 23-check full-stack security and data mutation verification suite:
```bash
python3 test_fullstack_security_mutations_e2e.py
```

### Playwright Browser E2E Suite
Run the 28-check Playwright browser automation suite (verifying RBAC forgery defense, CSV export, AI Assistant grounding, and all 18 workspace routes):
```bash
node run_playwright_e2e_reconciliation.js
```

---

## Security & Operational Scope

- **Authorization Model**: Server-authoritative session derivation via database memberships. Client `localStorage` state cannot escalate privileges.
- **Egress Safety**: All outgoing scanner requests and webhook deliveries pass through an egress security filter prohibiting loopback, RFC 1918 private IP ranges, and internal cloud metadata endpoints.
- **Target Authorization**: Scanning is strictly gated behind verified ownership proof to prevent unauthorized reconnaissance.

---

## License

Copyright (c) 2026. All rights reserved.
