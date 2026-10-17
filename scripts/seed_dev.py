#!/usr/bin/env python3
"""
Development Database Seed Script for SECDEF

Populates clean development SQLite database with the canonical local organization:
- Organization: org-001 (Local Development Org)
- Users:
  - user-owner-01  (Role: OWNER)
  - user-admin-01  (Role: ADMIN)
  - user-member-01 (Role: MEMBER)
  - user-viewer-01 (Role: VIEWER)

Usage:
  python scripts/seed_dev.py
"""
import asyncio
import os
import sys

# Add apps/control-plane, apps/scanner-worker, and shared-contracts to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "apps", "control-plane"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "apps", "scanner-worker"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "packages", "shared-contracts", "python"))

from app.infrastructure.db.session import AsyncSessionLocal
from app.infrastructure.db.bootstrap import bootstrap_development_data


async def main():
    print("Starting local development database seed...")
    async with AsyncSessionLocal() as session:
        success = await bootstrap_development_data(session)
        if success:
            print("Development database seeded successfully!")
        else:
            print("Seed skipped (APP_ENV is not 'development').")


if __name__ == "__main__":
    asyncio.run(main())
