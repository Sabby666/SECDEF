---
name: asm-migration-safety
description: ASM Database Migration Safety Guardrails. Enforces reversible Alembic migration scripts, dual SQLite/PostgreSQL compatibility, zero-downtime schema migrations, and diagnostic rules for Attack Surface Monitor.
---

# ASM Database Migration Safety Guardrails (`asm-migration-safety`)

## Purpose
This skill governs database schema migrations (`apps/control-plane/alembic/versions`), ORM model definitions, and dual-database compatibility (development SQLite `asm_dev.db` and production PostgreSQL) for Attack Surface Monitor (ASM).

## Mandatory Migration Invariants

### 1. Dual Upgrade/Downgrade Implementation
- Every Alembic migration script MUST implement BOTH an explicit `upgrade()` function and a fully tested, functional `downgrade()` function.
- Migration changes MUST be reversible where practical.

### 2. Dual Database Engine Compatibility
- All migration operations (table creation, column addition, index creation, foreign key constraints) MUST be compatible with both **SQLite 3.x** and **PostgreSQL 14+**.
- Use batch operations (`op.batch_alter_table`) when modifying SQLite table schemas to ensure compatibility.

### 3. Diagnostic Rules & Strict Prohibitions
- **NO Blind `stamp head`**: Running `alembic stamp head` to bypass migration errors without understanding schema divergence is STRICTLY PROHIBITED.
- **NO Database Deletion**: Deleting `asm_dev.db` or dropping production tables to fix migration failures is STRICTLY PROHIBITED.
- **Root Cause Diagnosis**: Schema inconsistencies, missing tables, or migration head mismatches MUST be diagnosed via root-cause investigation before applying edits.
- **Explicit Approval for Destructive Changes**: Dropping tables, dropping columns, or truncating data requires explicit human review and approval.
