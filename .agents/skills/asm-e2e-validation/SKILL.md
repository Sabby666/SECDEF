---
name: asm-e2e-validation
description: ASM End-to-End Route & Customer Workflow Validation Guardrails. Enforces Next.js production builds (npm run build), route verification, and Playwright E2E testing for Attack Surface Monitor.
---

# ASM E2E Validation Guardrails (`asm-e2e-validation`)

## Purpose
This skill governs end-to-end customer workflow validation, Next.js build verification, and Playwright browser route testing for Attack Surface Monitor (ASM).

## Mandatory Customer Workflow Pipeline
Validation MUST verify the complete operational user journey:
```
Account / Org Onboarding
  → Domain Onboarding
  → Verification
  → Monitoring Configuration
  → Discovery Run
  → Asset Inventory & Services Inspection
  → Change Feed Detection
  → Risk Evaluation
  → Finding Triage
  → Action Request & Approval
  → Automated Remediation Verification
  → Finding Resolution
  → Notification Delivery
  → Audit Trail Inspection
```

## Mandatory Build & Route Validation Rules
- **Compilation Gate**: `npm run build` MUST compile cleanly across all static and dynamic routes with **0 TypeScript or lint errors** before any task is declared complete.
- **Runtime Route Testing**: Next.js compilation alone is insufficient; routes MUST be verified in runtime execution (`npm run dev` or `npm run start`).
- **Browser Verification**: Use `playwright-cli` or browser automation to verify page layout rendering, drawer interactions, table sorting, tab switching, and responsiveness at desktop breakpoints (1280px, 1440px, 1920px).
