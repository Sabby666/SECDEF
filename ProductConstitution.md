# Attack Surface Monitor — Product Constitution

> **Status:** DRAFT — Pending Human Review
> **Last Updated:** 2026-08-27
> **Document Type:** Strategic Source of Truth
> **Classification:** DECISION — This document governs all downstream product, architecture, and implementation decisions.

---

## 1. Product Identity

| Field | Value |
|---|---|
| **Working Name** | Attack Surface Monitor |
| **Abbreviation** | ASM |
| **Category** | Adaptive Exposure Intelligence Platform |
| **Initial Focus** | External Attack Surface Management (EASM) |
| **Long-Term Vision** | Organizational Security Intelligence |

The product begins as an EASM solution focused on external asset discovery and change intelligence. It is designed to evolve toward a comprehensive, organization-aware exposure intelligence platform.

The commercial brand name is deferred. "Attack Surface Monitor" is the working product name used consistently across all documentation.

---

## 2. Mission

Enable security teams to continuously understand their organization's external security state — not merely discover assets, but understand what changed, whether it matters, and what to do about it.

---

## 3. Vision

Become the platform that transforms raw external exposure data into an evolving organizational security model — where every asset, change, and risk is contextualized by who owns it, what it does, how critical it is, and what action is required.

The product moves security teams through a progression:

```
DISCOVERY → UNDERSTANDING → DECISION → VERIFICATION → CONTINUOUS LEARNING
```

---

## 4. Problem Statement

### The Surface Problem

Security teams cannot maintain an accurate, continuous inventory of their organization's Internet-exposed infrastructure. Assets appear, change, and disappear faster than manual processes can track.

### The Deeper Problem

Even when assets are discovered, security teams struggle to continuously answer:

1. **What changed?** — New subdomain, new service, certificate expiry, configuration drift
2. **Is the change expected?** — Planned deployment vs. shadow IT vs. misconfiguration
3. **What is this asset?** — Identity, purpose, technology stack
4. **Who owns it?** — Team, individual, business unit
5. **What environment is it?** — Production, staging, development, test
6. **Does it matter?** — Business criticality, data sensitivity, exposure risk
7. **Why does it matter?** — Business context, compliance implications, threat relevance
8. **How risky is it?** — Contextualized risk considering all factors above
9. **What should I do?** — Specific, actionable remediation guidance
10. **Did the action work?** — Verification that remediation was effective

### The Root Cause

Existing tools focus on *scanning* rather than *understanding*. They produce lists of assets and vulnerabilities without the organizational context required to make informed security decisions. Security teams are forced to manually reconstruct context every time a new finding appears.

### Refined Problem Statement

> Security teams with dynamic, cloud-native infrastructure need to understand meaningful changes in their external environment, why those changes matter to their specific organization, and what actions they should take — without manually reconstructing the business context, ownership, and risk implications every time.

**Classification:** HYPOTHESIS — This formulation requires customer validation. The core elements (change detection, organizational context, actionable decisions) are well-supported by market research, but the exact emphasis and wording should evolve based on user feedback.

---

## 5. Target Customer

### Ideal Customer Profile (ICP)

The target customer is defined by **security complexity**, not company size:

| Characteristic | Description |
|---|---|
| **External Complexity** | Multiple domains, subdomains, cloud providers, SaaS integrations |
| **Dynamic Infrastructure** | Frequent deployments, ephemeral resources, cloud-native architecture |
| **Limited Security Capacity** | Security team capacity is disproportionately small relative to infrastructure complexity |
| **Growth Trajectory** | Expanding infrastructure faster than security processes can adapt |

### Primary Customer Segments (V1)

| Segment | Why |
|---|---|
| SaaS companies (50–500 employees) | High external exposure, frequent deployments, limited dedicated security |
| Cloud-native technology companies | Multi-cloud, rapid infrastructure changes, developer-driven security |
| Rapidly growing startups/scaleups | Expanding attack surface outpacing security processes |

### Secondary Customer Segments (V2+)

| Segment | Why |
|---|---|
| Mid-market enterprises (500–5,000) | Multiple business units, complex domain portfolios, M&A activity |
| Managed Security Service Providers | Multi-tenant monitoring requirements, operational efficiency needs |

### User Personas

#### 1. Security Engineer — "Alex"
- **Role:** Hands-on security practitioner responsible for external security posture
- **Pain:** Spends 60%+ of time on manual reconnaissance and context-gathering
- **Need:** Automated discovery with organizational context; actionable change alerts
- **Success:** Understands external security posture without daily manual effort

#### 2. Cloud Security / DevSecOps Engineer — "Jordan"
- **Role:** Responsible for securing cloud infrastructure and deployment pipelines
- **Pain:** Cannot track what's actually exposed externally from cloud deployments
- **Need:** Visibility into cloud-to-Internet exposure; expected vs. unexpected services
- **Success:** Catches unintended exposures before attackers do

#### 3. Security Lead / Head of Security — "Morgan"
- **Role:** Manages security program, reports to leadership, makes risk decisions
- **Pain:** Cannot answer "what is our external security posture?" with confidence
- **Need:** Prioritized view of meaningful risks; audit trail for decisions
- **Success:** Confident, evidence-based security posture reporting

#### 4. CTO / Engineering Leader — "Sam"
- **Role:** Accountable for technical infrastructure and engineering security
- **Pain:** No visibility into security implications of engineering velocity
- **Need:** High-level understanding of exposure trends; team ownership attribution
- **Success:** Engineering velocity without unmanaged security debt

### Jobs-to-Be-Done (JTBD)

| # | Job |
|---|---|
| 1 | When my infrastructure changes, I need to know what's now exposed externally so I can assess whether it's intended |
| 2 | When a new finding appears, I need to understand its business context so I can prioritize correctly |
| 3 | When I need to report on security posture, I need an evidence-backed view so I can communicate accurately |
| 4 | When I make a security decision (accept risk, mark expected), I need it recorded so I'm not asked about it again next scan |
| 5 | When I remediate an issue, I need verification that it's actually resolved so I can close the loop |
| 6 | When I onboard a new domain/environment, I need rapid initial discovery so I can establish a baseline |

---

## 6. Product Thesis

### Core Thesis

> The product can continuously observe an organization's external attack surface and turn meaningful changes into useful, explainable, organization-aware decisions.

### Supporting Hypotheses

| # | Hypothesis | Classification |
|---|---|---|
| H1 | Security teams value contextualized change intelligence over raw vulnerability lists | HYPOTHESIS |
| H2 | Organizational context (ownership, environment, criticality) meaningfully improves prioritization | HYPOTHESIS |
| H3 | An evidence-backed decision model reduces alert fatigue and repeated triage | HYPOTHESIS |
| H4 | Teams will invest in teaching the system their organizational context if the payoff is reduced manual effort | HYPOTHESIS |
| H5 | The platform becomes more useful over time as organizational knowledge accumulates | HYPOTHESIS |
| H6 | Verification of remediation completes the security loop that most tools leave open | HYPOTHESIS |

---

## 7. Core Product Loop

```
OBSERVE         Continuously monitor external infrastructure
    ↓
DISCOVER        Identify assets, services, technologies, certificates
    ↓
IDENTIFY        Resolve asset identity (what is this?)
    ↓
RELATE          Connect assets to each other and to organizational context
    ↓
UNDERSTAND      Classify environment, ownership, criticality, expected state
    ↓
COMPARE         Detect changes from previous observations
    ↓
DETECT          Identify meaningful deviations from expected state
    ↓
CONTEXTUALIZE   Enrich with organizational knowledge, history, decisions
    ↓
PRIORITIZE      Rank by contextualized risk (not raw severity alone)
    ↓
EXPLAIN         Present evidence and reasoning for prioritization
    ↓
ACT             Guide toward specific remediation or decision
    ↓
VERIFY          Confirm that remediation resolved the issue
    ↓
LEARN           Update organizational model with outcomes and decisions
    ↺
```

---

## 8. Organizational Security Model (OSM)

### Concept

The OSM is the evolving representation of an organization's external security context. Unlike a static asset inventory, the OSM accumulates organizational knowledge over time — ownership, expected state, criticality, historical decisions, behavioral baselines.

### The 10-Level Learning Taxonomy

To prevent ambiguous "AI learning" claims, the platform formally distinguishes 10 concepts:

| Concept | Definition | Example |
|---|---|---|
| **1. OBSERVATION** | Raw objective data gathered by scanner workers | "Port 8443 open on 1.2.3.4 at 2026-08-27T02:00:00Z" |
| **2. CONTEXT** | Human-provided or system-derived meaning about an asset | "1.2.3.4 belongs to Team Alpha, Environment = Staging" |
| **3. EXPECTATION** | Approved state definition for an asset or service | "Port 8443 is an expected HTTPS proxy on staging" |
| **4. DECISION** | Human security determination on a finding or change | "Accepted risk on self-signed cert on 1.2.3.4 until 2026-12-31" |
| **5. MEMORY** | Persistent organizational knowledge derived from context/decisions | "Asset 1.2.3.4 has accepted risk #892 active" |
| **6. RULE** | Explicit reusable policy governing alert/risk calculations | "All subdomains matching `*-dev.example.com` are environment=Development" |
| **7. BASELINE** | Historically observed normal behavior over time | "Subdomain count for org averages 45 ± 3 for 90 days" |
| **8. FEEDBACK** | Human confirmation or correction of system interpretation | "User marks inferred asset environment 'Production' as incorrect -> 'Staging'" |
| **9. LEARNING** | Controlled process updating context/rules from validated feedback | "System updates pattern rule: `api-staging-*` is Staging, requiring user confirmation" |
| **10. VERIFICATION** | Empirical proof that expected remediation actually occurred | "Re-scan confirms port 8443 closed on 1.2.3.4 following ticket #402" |

### Memory Scope & Inheritance Rules

Memory MUST be explicitly scoped to prevent incorrect assumptions:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MEMORY INHERITANCE MATRIX                       │
├───────────────────────┬────────────────────┬───────────────────────────┤
│ Scope Level           │ Inherited By       │ NEVER Inherited By        │
├───────────────────────┼────────────────────┼───────────────────────────┤
│ Organization          │ Org-wide policies  │ Specific asset exceptions │
│ Domain                │ Subdomains of host │ Unrelated domains         │
│ Asset (Subdomain/IP)  │ Services on asset  │ Neighboring assets/IPs    │
│ Service/Port          │ Certs on service   │ Other ports on same asset │
│ Finding / Exception   │ Exact finding ID   │ Similar findings elsewhere│
└───────────────────────┴────────────────────┴───────────────────────────┘
```

**Concrete Inheritance Rules:**
1. **Explicit Match Only:** A decision to mark port 8443 as `Expected` on `staging-api.example.com` applies ONLY to `staging-api.example.com:8443`. It DOES NOT automatically mark port 8443 as expected on `prod-api.example.com` or `staging-db.example.com`.
2. **Wildcard Rule Constraints:** Rules with wildcards (e.g. `*.staging.example.com`) MUST be explicitly created as an **Organizational Rule** by a human user with Admin/Owner role. The system MUST NOT auto-generate wildcard rules from a single asset decision.
3. **Tenant Isolation Invariant:** Memory NEVER crosses tenant boundaries under any circumstances.

### V1 OSM Scope

| Element | V1 | V2+ | Future |
|---|---|---|---|
| Asset inventory | ✓ | | |
| Asset identity (type, technology) | ✓ | | |
| DNS observations | ✓ | | |
| Certificate tracking | ✓ | | |
| Service/port discovery | ✓ | | |
| Asset relationships (basic) | ✓ | | |
| Ownership attribution | ✓ | | |
| Environment classification | ✓ | | |
| Criticality scoring | ✓ | | |
| Expected state marking | ✓ | | |
| Change history | ✓ | | |
| Human decisions (accepted risk, false positive) | ✓ | | |
| Reusable organizational rules | | ✓ | |
| Behavioral baselines | | ✓ | |
| Dependency mapping | | ✓ | |
| Organizational patterns | | | ✓ |
| Predictive intelligence | | | ✓ |

---

## 9. Learning Philosophy

### Controlled Learning Mechanics

V1 learning is strictly **deterministic, explainable, auditable, reversible, and attributable**:

```
OBSERVED FACTS         System scans and records raw evidence
      ↓
HUMAN DECISION         Human asserts ownership, expected state, or risk decision
      ↓
MEMORY RECORD          Decision stored with explicit asset/service scope
      ↓
DETERMINISTIC RULE     Future scan matching exact scope applies decision logic
      ↓
EXPLAINABLE RESULT     UI displays: "Priority Low — Expected state marked by Alex on 2026-08-27"
```

### Learning Safety Invariants

1. **No Unassisted Wildcards:** Human decisions on single assets NEVER produce global or wildcard rules automatically.
2. **Reversibility:** Every decision or context override can be revoked or edited by authorized users, immediately restoring default risk scoring.
3. **No Risk Acceptance Auto-Pilot:** The system MUST NOT auto-accept risks or suppress alerts without an explicit human decision.
4. **Audit Traceability:** Every decision record links to the actor, timestamp, justification, and exact evidence context at the time of decision.

**Classification:** DECISION — These rules govern all decision memory implementation.

---

## 10. AI Philosophy

### AI as Component, Not Product

AI is a capability integrated into the platform — it is not the product's identity. The product is not marketed as "AI-powered ASM." The product is an exposure intelligence platform that uses AI where appropriate.

### AI Capabilities (by phase)

| Capability | V1 | V2+ | Future |
|---|---|---|---|
| Technology identification | ✓ (rule-based + lightweight ML) | | |
| Asset classification assistance | | ✓ | |
| Entity resolution | | ✓ | |
| Relationship inference | | ✓ | |
| Anomaly detection | | ✓ | |
| Summarization | | ✓ | |
| Natural-language investigation | | | ✓ |
| Remediation suggestions | | | ✓ |
| Predictive risk | | | ✓ |

### AI Boundaries

1. **AI reasoning is NOT evidence.** AI-generated classifications must be clearly labeled and distinguishable from observed facts.
2. **AI confidence is NOT organizational truth.** High-confidence AI outputs are suggestions, not decisions.
3. **AI must be explainable.** Any AI-influenced prioritization must present the reasoning and evidence chain.
4. **AI must be tenant-isolated.** No AI model may learn from or be influenced by other tenants' data.
5. **AI must be correctable.** Users must be able to override any AI classification.

**Classification:** DECISION — V1 deliberately limits AI scope to avoid dependency on complex ML infrastructure before product-market fit is established.

---

## 11. Evidence Philosophy

### Evidence Hierarchy

```
OBSERVED EVIDENCE          Direct scan/discovery results (strongest)
        >
CONNECTED SYSTEM EVIDENCE  Data from integrated systems (cloud APIs, DNS providers)
        >
HISTORICAL EVIDENCE        Past observations that provide temporal context
        >
HUMAN-CONFIRMED KNOWLEDGE  Explicit user assertions (ownership, criticality)
        >
STATISTICAL INFERENCE      Pattern-based conclusions from aggregated observations
        >
AI REASONING               AI-generated classifications and suggestions (weakest)
```

### Claim Classification

Every important claim in the system must be classifiable as:

| Type | Definition | Example |
|---|---|---|
| **FACT** | Directly observed, verifiable evidence | "Port 443 is open on 1.2.3.4" |
| **INFERENCE** | Derived from evidence through logical reasoning | "This appears to be an nginx server based on response headers" |
| **ASSUMPTION** | Temporarily accepted without direct evidence | "This asset likely belongs to the production environment" |
| **HYPOTHESIS** | Proposed explanation requiring validation | "This subdomain may be a staging instance based on naming convention" |
| **CONFIRMED DECISION** | Human-authorized organizational determination | "This asset is accepted risk until 2026-12-31" |
| **RECOMMENDATION** | System-generated suggested action | "Consider investigating this unexpected service exposure" |

**Classification:** DECISION — The evidence model is fundamental to product differentiation. It prevents the platform from becoming another "trust our AI score" black box.

---

## 12. Human Authority

### Principle

Humans remain authoritative for all consequential organizational security decisions. The system discovers, correlates, classifies, prioritizes, explains, recommends, and verifies — but important decisions require human attribution.

### Decisions Requiring Human Authority

| Decision Type | Required Attributes |
|---|---|
| Accepted Risk | Actor, timestamp, reason, evidence, expiration, scope |
| Expected Asset/Service | Actor, timestamp, reason, evidence |
| False Positive | Actor, timestamp, reason, evidence |
| Security Exception | Actor, timestamp, reason, evidence, expiration, approver |
| Asset Ownership | Actor, timestamp, evidence |
| Criticality Override | Actor, timestamp, reason, previous value |
| Policy Decision | Actor, timestamp, reason, scope, approval chain |

### Audit Requirements

- All human decisions must be immutable once recorded (append-only audit log)
- Decision history must be queryable per asset, per user, per organization
- Expired decisions must remain visible in history but inactive in prioritization
- Decisions must include the evidence context at time of decision

**Classification:** DECISION — Non-negotiable. This is both a security requirement and a regulatory requirement for enterprise customers.

---

## 13. Security Philosophy

### Security by Architecture

Security is not a bolt-on feature or a checklist item. It is an architectural constraint that influences every design decision.

### Core Security Principles

1. **Tenant isolation is absolute.** No request, query, cache key, queue message, log entry, or AI context may leak data across tenant boundaries.
2. **Defense in depth.** No single security control is relied upon exclusively. Authorization is enforced at API, service, and data layers.
3. **Least privilege.** Every component operates with the minimum privileges required. Scanner workers have no access to the control plane database.
4. **Scan targets are hostile.** Scanner infrastructure treats every scan target as potentially adversarial. Scanner workers are isolated from control plane, customer secrets, and cloud metadata.
5. **Secrets are never in code.** All secrets are managed through dedicated secrets management infrastructure. No secrets in environment variables directly in code, configuration files, or logs.
6. **Fail secure.** When in doubt, deny access. Authorization failures default to denial.
7. **Audit everything consequential.** Every security-relevant action is logged with actor, timestamp, and context.
8. **Encrypt at rest and in transit.** All data is encrypted in transit (TLS 1.2+). Sensitive data is encrypted at rest. Tenant-specific secrets use dedicated encryption.

**Classification:** DECISION — These security principles are non-negotiable and must be validated by the SecurityChecklist.

---

## 14. Competitive Positioning

### Market Context (August 2026)

The EASM market has evolved significantly:

- **Consolidation:** Gartner has folded standalone EASM into "Exposure Assessment Platforms." The market is maturing and consolidating.
- **AI Arms Race:** Vendors are competing on AI-driven discovery, with Hadrian leading on autonomous offensive AI and CyCognito on seedless discovery.
- **Validation Shift:** The market is moving from "visibility" to "validation" — proving that exposures are actually exploitable (BAS/CTEM convergence).
- **Enterprise Lock-in:** Large vendors (CrowdStrike, Microsoft, Palo Alto, Wiz) are absorbing EASM into broader platform plays, making it difficult for pure-play EASM vendors.

### Competitive Landscape

| Competitor | Category | Strengths | Weaknesses |
|---|---|---|---|
| **Censys** | EASM (enterprise) | Internet-wide scanning data, attribution engine, 65K+ ports | Enterprise-only pricing (~$93K+/yr), limited organizational context, data-focused not decision-focused |
| **Shodan** | Internet Intelligence | Developer-friendly API, real-time monitoring, extensive data | Tool, not platform; no organizational model; no prioritization; requires significant manual effort |
| **CyCognito** | EASM (enterprise) | Seedless discovery, Target Graph, adversarial validation, business context | Enterprise pricing, complex platform, heavy on validation (not learning) |
| **Hadrian** | Offensive EASM | Agentic AI, autonomous attack simulation, hourly scanning | Offensive-first may not suit all buyers; limited organizational learning model |
| **runZero** | Asset Intelligence | Agentless discovery, OT/IT convergence, internal+external | Broader than external-only; more IT ops than security decision platform |
| **Intruder** | EASM (SMB) | Accessible pricing, free tier, simple UX, SOC2/ISO support | Less sophisticated discovery, limited organizational context, feature-light |
| **Microsoft EASM** | EASM (platform) | Azure integration, Copilot AI, unified exposure management | Microsoft ecosystem lock-in, limited outside Azure, less depth than pure-play |
| **ProjectDiscovery** | OSS + Cloud ASM | Open-source Nuclei engine, 9K+ templates, developer-first | Scanning-focused, limited business context, requires technical expertise |
| **XM Cyber** | Attack Path / CEM | Attack graph analysis, choke point identification, CTEM alignment | Internal-focused (not primarily EASM), complex deployment, enterprise pricing |
| **CrowdStrike** | Platform (EASM module) | Falcon platform integration, threat intelligence, market leadership | EASM is module in larger platform; may lack depth of pure-play |

**Classification:** Research conducted August 2026. Pricing data is INFERRED from public sources and market reports. Specific capability details are VERIFIED from vendor websites and analyst reports where available.

### What Is Commoditized

- Basic subdomain enumeration
- Port scanning
- Certificate discovery
- DNS record lookup
- Technology fingerprinting (basic)
- CVSS-based severity scoring

### What Is Table Stakes

- Continuous monitoring (not just point-in-time)
- Cloud provider integration
- Basic asset inventory
- Alert notifications
- Integration with ticketing systems (Jira, Slack)

### Where Existing Tools Are Strong

- Internet-wide data collection (Censys, Shodan)
- Autonomous offensive testing (Hadrian, CyCognito)
- Broad platform integration (CrowdStrike, Microsoft)
- Template-based scanning (ProjectDiscovery)

### Where Existing Tools Are Weak

1. **Organizational Context Gap:** Most tools discover assets but don't understand *who owns them*, *what environment they belong to*, or *whether the exposure is expected*. Context reconstruction remains manual.
2. **Change Intelligence Gap:** Tools show current state but poorly answer "what changed and why does it matter?" Change detection is a notification, not an intelligence function.
3. **Decision Memory Gap:** Security decisions (accepted risks, expected services, false positives) are lost between scans. Teams re-triage the same findings repeatedly.
4. **Learning Gap:** Platforms don't become more useful over time. The 100th scan produces the same undifferentiated output as the 1st scan.
5. **Verification Gap:** Most tools don't close the remediation loop — they find problems but don't confirm resolution.

### Our Wedge

**Organization-aware change intelligence with decision memory.**

The product differentiates not by discovering more assets or scanning faster, but by:

1. Understanding *what changed* and *why it matters to this specific organization*
2. Remembering *what the organization has already decided* about an asset/finding
3. Becoming *more useful over time* as organizational context accumulates
4. Providing *evidence-backed explanations* rather than opaque risk scores
5. Completing the *decision loop* from discovery through verification

### Defensible Advantage (Hypothesis)

**The Organizational Security Model.** As customers invest in teaching the platform their context (ownership, environments, criticality, expected state, decisions), switching costs increase naturally — not through lock-in, but through accumulated organizational intelligence that would be lost in migration.

**Classification:** HYPOTHESIS — This advantage must be validated. It depends on customers actually investing in providing context and the OSM delivering measurably better outcomes.

---

## 15. V1 Boundary

### V1 Objective

Prove the core thesis: The platform can continuously observe an organization's external attack surface and turn meaningful changes into useful, explainable, organization-aware decisions.

### V1 Capabilities — Included

| Capability | Justification |
|---|---|
| **Domain onboarding & verification** | Entry point for all discovery; must prove domain ownership |
| **External subdomain discovery** | Core EASM capability; table stakes |
| **IP resolution** | Required for service discovery |
| **Service/port discovery** | Core EASM capability; required for risk assessment |
| **DNS observation & tracking** | Foundation for change detection |
| **Certificate discovery & monitoring** | High-value, low-complexity security intelligence |
| **Technology identification** | Required for contextualization (rule-based + header analysis) |
| **Asset inventory with identity** | Core value proposition; must understand *what* each asset is |
| **Basic asset relationships** | Required for organizational context (subdomain→IP→service) |
| **Historical observations** | Foundation for change detection; scan-over-scan comparison |
| **Change detection** | Core differentiator; "what changed since last scan?" |
| **Ownership attribution** | Core differentiator; "who is responsible for this?" |
| **Environment classification** | Core differentiator; "is this production or staging?" |
| **Criticality scoring** | Required for meaningful prioritization |
| **Expected state marking** | Core differentiator; "is this exposure intended?" |
| **Evidence model** | Core differentiator; every finding backed by traceable evidence |
| **Confidence scoring** | Required for distinguishing facts from inferences |
| **Contextual prioritization** | Core differentiator; risk in organizational context |
| **Change-aware alerts** | Core differentiator; alerts on meaningful changes, not raw findings |
| **Human feedback & decisions** | Core differentiator; accept risk, mark expected, confirm ownership |
| **Remediation guidance (basic)** | Required for actionable decisions |
| **Verification foundation** | Closes the loop; confirms remediation was effective |
| **Authentication (email/password + MFA)** | Security requirement |
| **Organization model** | Multi-tenancy requirement |
| **RBAC (basic: Owner, Admin, Member)** | Access control requirement |
| **Audit logging** | Security and compliance requirement |

### V1 Capabilities — Excluded

| Capability | Phase | Reason |
|---|---|---|
| Seedless discovery | V2 | Requires significant ML infrastructure; domain verification is sufficient for V1 |
| Attack path analysis | V2 | Requires deeper relationship modeling beyond V1 scope |
| Adversarial validation / exploit testing | V2+ / ARES | Security-sensitive; better handled by ARES integration |
| Behavioral baselines | V2 | Requires sufficient historical data and pattern detection |
| AI-powered classification | V2 | V1 uses rule-based classification; AI classification requires validated training data |
| Natural-language investigation | Future | Requires mature AI integration and data model |
| Compliance reporting | V2 | Not a V1 differentiator; add after core value is proven |
| Cloud connector integrations | V2 | Valuable but not required for external-only discovery V1 |
| Third-party risk / supply chain | Future | Different product focus; avoid scope creep |
| SIEM/SOAR integration | V2 | Integration platform requires stable API surface first |
| SSO/SAML | V2 | Enterprise feature; email/password + MFA sufficient for V1 ICP |
| Custom scanning templates | Future | Complexity without proven demand |
| Internal network discovery | REJECTED | Different product category; out of scope |
| Autonomous exploitation | REJECTED | ARES scope; security and liability risk |
| Compliance certification platform | REJECTED | Different product category |

**Classification:** DECISION — V1 scope is deliberately constrained to prove the core thesis. Additional capabilities are phased based on dependency, complexity, and customer value validation.

---

## 16. Anti-Features

Things the product deliberately will NOT do:

1. **Replace vulnerability scanners.** The product identifies exposure and context, not CVE-level vulnerability assessment.
2. **Replace SIEM/SOAR.** The product generates security intelligence, not security operations automation.
3. **Autonomously exploit targets.** Offensive validation is ARES scope, not ASM scope.
4. **Scan internal networks.** The product is focused on external attack surface.
5. **Enforce compliance.** The product provides evidence for compliance, not compliance enforcement.
6. **Replace penetration testing.** The product provides continuous monitoring, not point-in-time testing.
7. **Become a generic AI chatbot.** AI serves specific product functions, not open-ended conversation.

---

## 17. ARES Relationship

### Current State

ARES is a separate project — a multi-agent security assessment prototype using AI agents for controlled penetration testing.

### Future Integration Concept

```
ATTACK SURFACE MONITOR              ARES
        │                              │
   Detect Exposure                     │
        ↓                              │
   Contextualize                       │
        ↓                              │
   Prioritize                          │
        ↓                              │
   Request Validation    ─────────►   Validate Exposure
                                       │
                                   Generate Evidence
                                       │
   ◄────────────────────────────   Return Results
        │
   Update Risk Score
        ↓
   Update OSM
```

### Integration Boundaries

1. ARES is NOT a dependency for ASM V1. ASM must function independently.
2. Integration is through well-defined APIs, not shared databases or direct coupling.
3. ASM controls *what* to validate; ARES controls *how* to validate.
4. ARES results are treated as evidence within the ASM evidence hierarchy.
5. ARES execution scope is constrained by ASM authorization — ARES cannot validate assets outside the organization's verified scope.

**Classification:** DECISION — ARES integration is V2+ scope. No technical dependencies should be introduced in V1.

---

## 18. Scaling Philosophy

### Growth Path

```
Phase 1:  5–50 users (single-tenant-ready architecture, multi-tenant from day 1)
Phase 2:  50–500 users (horizontal scaling, worker pool management)
Phase 3:  500–5,000 users (infrastructure optimization, data partitioning)
Phase 4:  5,000–50,000+ users (dedicated infrastructure options, advanced multi-tenancy)
```

### Principles

1. **Multi-tenant from day one.** Tenant isolation is an architectural decision, not a migration.
2. **Modular, not micro.** Start with a well-structured monolith with clear module boundaries. Extract services only when proven necessary.
3. **Observe before optimizing.** Build observability first; optimize based on measured bottlenecks, not theoretical concerns.
4. **Stateless where possible.** API servers are stateless; state lives in databases and queues.
5. **Workers scale independently.** Scanner workers scale horizontally, independently from the API tier.

---

## 19. SaaS / Business Philosophy

1. **Self-service onboarding.** Customers should be able to sign up, verify domains, and begin discovery without human intervention.
2. **Time-to-value under 30 minutes.** First meaningful security insight within 30 minutes of domain verification.
3. **Usage-aligned pricing.** Pricing should scale with the number of monitored assets/domains, not arbitrary tier features.
4. **No feature gates on security.** Security features (MFA, audit logs, encryption) are available on all plans.
5. **Transparent operations.** System status, scan schedules, and data freshness are visible to customers.

**Classification:** HYPOTHESIS — Pricing model and self-service assumptions require market validation.

---

## 20. Success Definition

### V1 Success Criteria

| Metric | Target | Measurement |
|---|---|---|
| Time to first insight | < 30 minutes from domain verification | Product analytics |
| Asset discovery accuracy | > 90% of known assets discovered | Customer validation |
| Change detection latency | < 24 hours for critical changes | Scan comparison |
| User engagement | Active users return weekly | Product analytics |
| Decision utilization | > 30% of findings receive a human decision | Usage analytics |
| False positive rate | < 20% of surfaced findings deemed irrelevant | User feedback |
| Customer satisfaction | NPS > 40 among pilot customers | Survey |

**Classification:** HYPOTHESIS — These targets are initial hypotheses. They must be refined based on actual customer usage data.

---

## 21. Product Principles

| # | Principle | Implication |
|---|---|---|
| 1 | **Evidence over assumptions** | Every claim is traceable to observed data; AI reasoning is labeled as such |
| 2 | **Context over raw severity** | A critical CVE on a staging server may matter less than a medium issue on a production API |
| 3 | **Decisions over dashboards** | The product drives action, not passive monitoring; every finding leads to a decision |
| 4 | **Continuous state over point-in-time** | The platform maintains a living model, not periodic scan reports |
| 5 | **Explainability over magic** | Users understand *why* the platform prioritized something, not just *that* it did |
| 6 | **Human authority over consequential decisions** | The platform recommends; humans decide on risk acceptance, exceptions, criticality |
| 7 | **Security by architecture** | Security is designed in, not bolted on; tenant isolation is non-negotiable |
| 8 | **Minimal operational burden** | The platform should reduce security team workload, not create new operational overhead |
| 9 | **Vendor neutrality** | No lock-in to a specific cloud provider, identity provider, or infrastructure vendor |
| 10 | **Learn safely** | The platform improves with use but never silently changes security posture |

**Classification:** DECISION — These principles are validated through market research and product analysis. They should be challenged during customer discovery but treated as governing principles until changed.

---

## 22. Decision Hierarchy

When documents conflict, resolution follows this hierarchy:

```
1. ProductConstitution.md     (strategic direction — this document)
2. SecurityChecklist.md       (security requirements — overrides all implementation)
3. PRD.md                     (product requirements)
4. Architecture.md            (system design)
5. TechSpec.md                (technology choices)
6. Schema.md / AppFlow.md / Design.md  (implementation details)
7. ImplementationPlan.md      (execution plan)
```

Security requirements (from SecurityChecklist) can override implementation convenience but cannot override strategic product direction without explicit review.

---

## 23. Change Control

### Document Changes

| Change Type | Required |
|---|---|
| ProductConstitution changes | Human review and explicit approval |
| Security principle changes | Human review and explicit approval |
| V1 scope additions | Human review and justification against thesis |
| V1 scope reductions | Document reason in Memory.md |
| Architecture changes | Cross-document consistency audit |
| Technology changes | Justification and alternative analysis |

### Rules

1. No document may silently contradict this Constitution.
2. If a downstream document requires a Constitution change, the change must be proposed, justified, and approved before downstream documents are modified.
3. All significant decisions are recorded in Memory.md with reason, alternatives, and consequences.

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| **ASM** | Attack Surface Monitor (this product) |
| **EASM** | External Attack Surface Management (market category) |
| **OSM** | Organizational Security Model — the evolving representation of an organization's security context |
| **ARES** | Automated Red-Teaming Evaluation System — separate validation project |
| **CTEM** | Continuous Threat Exposure Management — Gartner framework |
| **ICP** | Ideal Customer Profile |
| **JTBD** | Jobs-to-Be-Done |
| **BAS** | Breach and Attack Simulation |
| **Tenant** | A single customer organization within the multi-tenant platform |

---

## Appendix B: Research Sources

| Source | Date | Confidence | What Was Verified |
|---|---|---|---|
| Gartner Exposure Assessment Platforms analysis | Aug 2026 | HIGH | EASM consolidation into exposure platforms |
| Forrester CTEM analysis | Aug 2026 | HIGH | EASM as critical security control |
| Censys product capabilities | Aug 2026 | HIGH | Discovery, attribution, pricing model |
| Hadrian product capabilities | Aug 2026 | HIGH | Agentic AI, offensive testing, hourly scanning |
| CyCognito product capabilities | Aug 2026 | HIGH | Seedless discovery, Target Graph, AEV |
| runZero product capabilities | Aug 2026 | HIGH | Agentless discovery, OT/IT, AI workflows |
| Intruder product and pricing | Aug 2026 | HIGH | SMB pricing, free tier, feature set |
| Microsoft Defender EASM | Aug 2026 | HIGH | Azure integration, Copilot, asset types |
| ProjectDiscovery / Nuclei | Aug 2026 | HIGH | OSS scanner, cloud platform, templates |
| XM Cyber | Aug 2026 | HIGH | Attack path analysis, CTEM alignment |
| Shodan | Aug 2026 | HIGH | API capabilities, monitoring, streaming |
| Market gap analysis (multiple sources) | Aug 2026 | MEDIUM | Organizational context gap, change detection gap |
