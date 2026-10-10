"""Phase 1D Security Tests: Change Detection Tenant Isolation

Tests cover:
- Cross-tenant comparison prevention (service layer)
- Cross-tenant change API access (endpoint layer)
- Cross-tenant comparison API access (endpoint layer)
- RBAC enforcement on change endpoints
"""

import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, User, Membership, Domain, Scan, Observation, Asset,
    ComparisonRun, Change,
)
from app.application.change_detection_service import ChangeDetectionService
from shared_contracts.enums import DomainStatus, ComparisonStatus


class MockRedis:
    def __init__(self):
        self.counts = {}
    async def incr(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]
    async def expire(self, key, time):
        pass
    async def ping(self):
        return True
    async def close(self):
        pass


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    mock_redis_inst = MockRedis()
    patcher = patch("app.api.dependencies.rate_limit.get_redis_client", return_value=mock_redis_inst)
    patcher.start()
    async with async_engine.begin() as conn:
        from sqlalchemy import text
        await conn.execute(text("PRAGMA foreign_keys=OFF;"))
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("PRAGMA foreign_keys=ON;"))
    yield
    async with async_engine.begin() as conn:
        from sqlalchemy import text
        await conn.execute(text("PRAGMA foreign_keys=OFF;"))
        await conn.run_sync(Base.metadata.drop_all)
        await conn.execute(text("PRAGMA foreign_keys=ON;"))
    patcher.stop()


@pytest_asyncio.fixture
async def two_tenants():
    """Create two separate orgs with separate users, domains, and test data."""
    async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        org1 = Organization(name="Org Alpha", slug="org-alpha")
        org2 = Organization(name="Org Beta", slug="org-beta")
        user1 = User(email="admin@alpha.com", password_hash="hash", full_name="Alpha Admin")
        user2 = User(email="admin@beta.com", password_hash="hash", full_name="Beta Admin")
        session.add_all([org1, org2, user1, user2])
        await session.commit()

        mem1 = Membership(org_id=org1.id, user_id=user1.id, role="admin")
        mem2 = Membership(org_id=org2.id, user_id=user2.id, role="admin")

        domain1 = Domain(
            org_id=org1.id, domain_name="alpha.com",
            status=DomainStatus.VERIFIED, verification_token="t1",
            verified_at=datetime.now(timezone.utc),
        )
        domain2 = Domain(
            org_id=org2.id, domain_name="beta.com",
            status=DomainStatus.VERIFIED, verification_token="t2",
            verified_at=datetime.now(timezone.utc),
        )
        session.add_all([mem1, mem2, domain1, domain2])
        await session.commit()

        # Create scan + asset + comparison for org1
        import uuid
        t1 = datetime.now(timezone.utc)
        scan1 = Scan(
            org_id=org1.id, domain_id=domain1.id, status="completed",
            job_nonce=f"nonce-{uuid.uuid4().hex}",
            completed_at=t1, created_at=t1,
        )
        session.add(scan1)
        await session.commit()

        asset1 = Asset(
            org_id=org1.id, domain_id=domain1.id, asset_type="subdomain",
            identifier="api.alpha.com", environment="unknown", criticality="medium",
            first_seen_at=t1, last_seen_at=t1, status="active",
        )
        session.add(asset1)
        await session.commit()

        obs1 = Observation(
            org_id=org1.id, scan_id=scan1.id, asset_id=asset1.id,
            observation_type="dns_record", target="alpha.com",
            raw_data={}, observed_at=t1,
        )
        session.add(obs1)
        await session.commit()

        # Run change detection for org1 (baseline)
        detector = ChangeDetectionService(session)
        cr = await detector.detect_changes_for_scan(scan1.id, org1.id, domain1.id)
        await session.commit()

        return {
            "org1_id": org1.id,
            "org2_id": org2.id,
            "user1_id": user1.id,
            "user2_id": user2.id,
            "domain1_id": domain1.id,
            "domain2_id": domain2.id,
            "scan1_id": scan1.id,
            "asset1_id": asset1.id,
            "comparison1_id": cr.id,
        }


@pytest.mark.asyncio
class TestCrossTenantServiceLayer:

    async def test_cross_tenant_scan_rejected(self, two_tenants):
        """ChangeDetectionService must reject scans from a different org."""
        async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)
        async with async_session() as session:
            service = ChangeDetectionService(session)
            with pytest.raises(ValueError, match="not found or does not belong"):
                # Try to detect changes on org1's scan using org2's org_id
                await service.detect_changes_for_scan(
                    two_tenants["scan1_id"],
                    two_tenants["org2_id"],  # WRONG ORG
                    two_tenants["domain1_id"],
                )


@pytest.mark.asyncio
class TestCrossTenantAPI:

    async def test_org2_cannot_list_org1_changes(self, two_tenants):
        """Org2 user cannot access Org1's changes endpoint."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "X-User-ID": two_tenants["user2_id"],
                "X-Org-ID": two_tenants["org2_id"],
            }
            res = await client.get(
                f"/api/v1/organizations/{two_tenants['org1_id']}/changes",
                headers=headers,
            )
            assert res.status_code == 403

    async def test_org2_cannot_get_org1_comparison(self, two_tenants):
        """Org2 user cannot access Org1's comparisons endpoint."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "X-User-ID": two_tenants["user2_id"],
                "X-Org-ID": two_tenants["org2_id"],
            }
            res = await client.get(
                f"/api/v1/organizations/{two_tenants['org1_id']}/comparisons",
                headers=headers,
            )
            assert res.status_code == 403

    async def test_org1_can_list_own_changes(self, two_tenants):
        """Org1 user CAN access their own changes endpoint."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "X-User-ID": two_tenants["user1_id"],
                "X-Org-ID": two_tenants["org1_id"],
            }
            res = await client.get(
                f"/api/v1/organizations/{two_tenants['org1_id']}/changes",
                headers=headers,
            )
            assert res.status_code == 200
            data = res.json()
            assert "items" in data
            assert "total" in data

    async def test_org1_can_list_own_comparisons(self, two_tenants):
        """Org1 user CAN access their own comparisons endpoint."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "X-User-ID": two_tenants["user1_id"],
                "X-Org-ID": two_tenants["org1_id"],
            }
            res = await client.get(
                f"/api/v1/organizations/{two_tenants['org1_id']}/comparisons",
                headers=headers,
            )
            assert res.status_code == 200
            data = res.json()
            assert "items" in data
            assert data["total"] >= 1  # At least the baseline

    async def test_org2_cannot_get_org1_change_by_id(self, two_tenants):
        """Org2 cannot access a specific change from Org1 by guessing the ID."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Even with a fabricated change_id, org isolation prevents access
            headers = {
                "X-User-ID": two_tenants["user2_id"],
                "X-Org-ID": two_tenants["org2_id"],
            }
            res = await client.get(
                f"/api/v1/organizations/{two_tenants['org1_id']}/changes/fake-change-id",
                headers=headers,
            )
            assert res.status_code == 403
