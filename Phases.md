# Attack Surface Monitor — Phases

> **Status:** DRAFT — Pending Human Review
> **Last Updated:** 2026-08-27
> **Parent Document:** ProductConstitution.md, PRD.md
> **Document Type:** Evolutionary Roadmap

---

## Phase Overview

```
FOUNDATION (Phase 0)    Infrastructure, auth, multi-tenancy, core platform
        ↓
V1 (Phase 1)            Discovery, inventory, context, change intelligence, decisions
        ↓
V2 (Phase 2)            Integrations, behavioral baselines, AI classification, ARES
        ↓
FUTURE (Phase 3+)       Predictive intelligence, natural-language, advanced AI
```

---

## Phase 0 — Foundation

### Objective

Establish the secure, multi-tenant platform foundation upon which all product features are built. This phase delivers no end-user discovery features — it delivers the infrastructure, authentication, authorization, and tenant isolation that everything else depends on.

### Customer Value

None directly. Foundation enables all future customer value. Without this phase, no feature is secure or multi-tenant.

### Capabilities

| Capability | Description |
|---|---|
| **Project structure** | Repository structure, development environment, CI pipeline |
| **Database schema (core)** | Users, organizations, memberships, sessions, audit_events |
| **Authentication** | Registration, email verification, login, logout, password reset |
| **MFA** | TOTP enrollment, verification, recovery codes |
| **Session management** | Secure sessions, rotation, idle/absolute timeout, revocation |
| **Organization management** | Create org, manage members, assign roles |
| **RBAC** | Owner, Admin, Member, Viewer roles with server-side enforcement |
| **Audit logging** | Append-only audit trail for security-relevant actions |
| **API framework** | RESTful API with authentication, authorization, validation, error handling |
| **Frontend framework** | Application shell, routing, auth flows, protected routes |
| **Rate limiting** | Per-IP and per-user rate limiting on all public endpoints |
| **Security headers** | CSP, HSTS, X-Frame-Options, etc. |
| **Observability foundation** | Structured logging, health checks, request tracing |

### Dependencies

- None (this is the root phase)

### Architectural Implications

- Multi-tenancy must be designed from the start — every table includes `org_id` where applicable
- Authentication infrastructure must support MFA from day 1
- Audit logging must be append-only from the start — retrofitting is not feasible
- API authorization middleware must be in place before any feature endpoints

### Security Implications

- This phase establishes all security boundaries that subsequent phases depend on
- Authentication, session management, and RBAC must pass SecurityChecklist gates before proceeding
- Rate limiting and brute-force protection must be active before public deployment

### Exit Criteria

- [ ] User can register, verify email, set up MFA, and log in
- [ ] User can create an organization and invite members
- [ ] RBAC enforced on all API endpoints (tested with unauthorized access attempts)
- [ ] Audit log captures all authentication and membership events
- [ ] Rate limiting active on registration, login, and password reset
- [ ] Session management passes security review (HttpOnly, Secure, SameSite, rotation, timeouts)
- [ ] All security headers present and configured
- [ ] CI pipeline runs tests and security checks automatically

### Measurable Success Criteria

- 100% of API endpoints enforce authentication
- 100% of tenant-scoped endpoints enforce organization membership
- 0 RBAC bypass paths (verified by authorization test suite)
- Audit log coverage for all security-relevant actions
- < 5s response time for all auth flows

---

## Phase 1 — V1

### Objective

Prove the core product thesis: The platform can continuously observe an organization's external attack surface and turn meaningful changes into useful, explainable, organization-aware decisions.

### Customer Value

Security teams can:
1. Onboard their domains and see comprehensive external discovery within 30 minutes
2. Understand what changed since last scan without manual comparison
3. Assign ownership, environment, and criticality to assets so the platform prioritizes correctly
4. Receive alerts on meaningful changes, not raw scan noise
5. Make documented security decisions (accept risk, mark expected, report false positive)
6. Request verification of remediated issues
7. See evidence behind every finding

### Capabilities

| Capability | Description |
|---|---|
| **Domain management** | Add, verify (DNS TXT), manage domains |
| **Subdomain discovery** | Multi-source enumeration (CT logs, DNS brute-force, passive DNS) |
| **IP resolution** | DNS resolution with historical tracking |
| **Service/port discovery** | TCP port scanning (top 1,000), banner grabbing |
| **Certificate discovery** | TLS cert extraction, chain validation, expiry tracking |
| **DNS observation** | Record tracking and change detection |
| **Technology identification** | Rule-based web technology fingerprinting |
| **Asset inventory** | Unified view with search, filter, pagination |
| **Asset relationships** | Domain→Subdomain→IP→Service→Certificate mapping |
| **Ownership attribution** | Manual assignment with history |
| **Environment classification** | Production/Staging/Dev/Test/Unknown |
| **Criticality scoring** | Critical/High/Medium/Low with manual override |
| **Expected state** | Mark services as expected; deviations flagged |
| **Change detection** | Scan-over-scan comparison with categorization |
| **Change-aware alerts** | Context-sensitive notifications (in-app + email) |
| **Contextual risk prioritization** | Multi-factor risk scoring |
| **Evidence model** | Evidence chains attached to all findings |
| **Findings management** | Lifecycle management with status tracking |
| **Risk acceptance** | Documented, time-bounded, auditable |
| **False positive marking** | Documented with justification |
| **Decision audit trail** | Immutable decision history |
| **Remediation guidance** | Template-based recommendations |
| **Verification** | Re-scan to confirm remediation |
| **Dashboard** | Prioritized overview of security state |
| **Notifications** | In-app + email for meaningful events |
| **Scanner infrastructure** | Isolated worker architecture for safe scanning |

### Dependencies

- Phase 0 (Foundation) must be complete
- Scanner infrastructure requires isolated worker deployment
- Discovery engines require external network access

### Architectural Implications

- Scanner workers must be isolated from control plane (separate network, no database access)
- Scan scheduling requires job queue infrastructure (Redis + Bull or similar)
- Discovery data volume requires considered database schema (observations table will grow)
- Change detection requires efficient scan comparison logic
- Asset graph requires relational modeling with navigable relationships

### Security Implications

- **Scanner security is critical.** Workers process responses from arbitrary Internet hosts — treat all input as hostile.
- **Domain verification prevents unauthorized scanning.** This is a legal and ethical requirement, not just a feature.
- **SSRF protection required.** Scanner must not follow redirects to private IPs, cloud metadata endpoints, or internal services.
- **Scan scope enforcement.** Workers must only scan verified, authorized targets.
- **Evidence integrity.** Scan results must be tamper-evident and attributable to specific scan runs.

### Exit Criteria

- [ ] User can add and verify a domain
- [ ] Platform discovers subdomains, IPs, services, certificates, DNS records, and technologies
- [ ] Discovery results appear in asset inventory within 30 minutes
- [ ] Change detection accurately identifies new/removed/changed assets between scans
- [ ] User can assign ownership, environment, and criticality to assets
- [ ] User can mark services as expected
- [ ] Findings are prioritized using organizational context
- [ ] Every finding has traceable evidence
- [ ] User can accept risk, mark false positive, and request verification
- [ ] Alerts fire on meaningful changes respecting organizational context
- [ ] Scanner workers are isolated from control plane
- [ ] Domain verification prevents unauthorized scanning
- [ ] All V1 functional requirements (PRD Section 4) pass acceptance criteria

### Measurable Success Criteria

- Time to first insight: < 30 minutes from domain verification
- Discovery completeness: > 90% of customer-known assets discovered
- Change detection: > 85% of changes are meaningful (non-noise)
- User engagement: > 30% of findings receive a human decision within 30 days
- Alert relevance: < 20% of alerts marked irrelevant
- Scanner isolation: 0 paths from scanner to control plane database (verified by architecture review)

---

## Phase 2 — V2

### Objective

Deepen organizational intelligence, integrate with external systems, and begin the platform's evolution from EASM to Adaptive Exposure Intelligence.

### Customer Value

Security teams can:
1. Enrich external discovery with cloud context (which cloud account, which deployment)
2. See behavioral baselines emerge (what's "normal" for this organization)
3. Benefit from AI-assisted asset classification
4. Integrate findings into existing workflows (Jira, Slack, webhooks)
5. Use SSO for enterprise authentication
6. Validate high-priority findings through ARES integration
7. Generate compliance-ready reports

### Capabilities

| Capability | Description |
|---|---|
| **Cloud connectors** | AWS, GCP, Azure asset inventory enrichment |
| **Behavioral baselines** | "Normal" state detection from 6+ months of data |
| **AI-assisted classification** | ML-based asset type, purpose, and environment classification |
| **SSO/SAML** | Enterprise identity provider integration |
| **API keys** | Programmatic access for automation |
| **Workflow integrations** | Jira, Slack, webhook notifications |
| **ARES integration (basic)** | Send high-priority findings for validation |
| **Compliance reporting** | SOC 2 / ISO 27001 evidence reports |
| **Attack path analysis (basic)** | Simple exposure chains (internet → asset → service → vulnerability) |
| **Advanced notification rules** | Custom alert policies based on complex conditions |

### Dependencies

- Phase 1 (V1) must be complete and validated with customers
- Cloud connectors require cloud provider API access
- Behavioral baselines require 6+ months of V1 scan data
- AI classification requires labeled training data from V1 usage
- ARES integration requires stable ARES API

### Architectural Implications

- Cloud connectors introduce new data sources and ingestion pipelines
- Behavioral baselines require time-series analysis capabilities
- AI classification requires model training/serving infrastructure
- SSO requires identity federation layer
- Webhook delivery requires reliable outbound delivery with retry

### Security Implications

- Cloud connector credentials must be stored with dedicated encryption
- AI training data must be tenant-isolated
- SSO integration must not bypass MFA policies
- Webhook payloads must not contain sensitive data by default
- ARES validation requests must be scoped to verified domains only

### Exit Criteria

- [ ] At least one cloud connector (AWS or GCP) operational
- [ ] Behavioral baselines detecting anomalies for organizations with 6+ months of data
- [ ] AI classification accuracy > 80% on labeled validation set
- [ ] SSO login functional with at least one IdP (Okta or Google Workspace)
- [ ] Jira and Slack integrations functional
- [ ] ARES validation round-trip functional (send finding, receive result, update risk)
- [ ] Compliance reports exportable

### Measurable Success Criteria

- Cloud connector enrichment: > 70% of cloud-hosted assets enriched with cloud context
- Baseline anomaly precision: > 75% of flagged anomalies confirmed meaningful
- AI classification accuracy: > 80% agreement with human classification
- Integration adoption: > 40% of active organizations using at least one integration
- ARES validation completion rate: > 90% of validation requests return results within 1 hour

---

## Phase 3+ — Future

### Objective

Evolve the platform toward Organizational Security Intelligence — a system that deeply understands each organization's security context and provides predictive, proactive intelligence.

### Research Areas

| Area | Description | Prerequisite |
|---|---|---|
| **Predictive risk intelligence** | Anticipate likely exposure based on organizational patterns | Behavioral baselines + sufficient historical data |
| **Natural-language investigation** | Query the OSM using natural language | Mature data model + LLM integration |
| **Advanced AI reasoning** | Multi-step reasoning about organizational security state | Validated AI classification + evidence model |
| **Seedless discovery** | Discover organizational assets without initial domain seeding | ML-based entity resolution at scale |
| **Supply chain / third-party risk** | Extend visibility to vendor and partner attack surfaces | Customer demand validation |
| **MSSP multi-tenancy** | Purpose-built managed service provider capabilities | Business model validation |
| **Custom scanning templates** | User-defined discovery and assessment checks | Proven demand from customer base |
| **Full ARES integration** | Deep bi-directional validation and learning loop | Mature ARES platform |

### Classification

All Phase 3+ items are classified as **HYPOTHESIS** — they represent potential evolution paths, not commitments. Progression to Phase 3+ depends on:

1. Validated customer demand
2. Proven V1 and V2 foundation
3. Business viability analysis
4. Technical feasibility assessment

---

## Phase Summary

| Phase | Scope | Customer Value | Key Risk |
|---|---|---|---|
| **Phase 0** | Foundation | None (enables all future value) | Over-engineering auth/infra before validating product |
| **Phase 1** | V1 Core | Discovery + Context + Change Intelligence + Decisions | Scope creep; scanner security; discovery completeness |
| **Phase 2** | V2 Expansion | Integrations + AI + Behavioral + ARES | AI accuracy; integration maintenance burden; complexity growth |
| **Phase 3+** | Future Research | Predictive Intelligence + Advanced AI | Premature commitment; market validation required |
