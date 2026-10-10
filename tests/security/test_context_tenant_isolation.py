"""Phase 1E Security Test Suite: Tenant Isolation, RBAC & Immutability.

Tests verify:
1. Hard Tenant Isolation: Org B cannot see or inherit Org A decisions, contexts, or memories.
2. RBAC Access Control: Viewer role is denied write access (403), while admin succeeds.
3. Scope Boundary Enforcement: Asset-scoped decisions never leak into domain-wide resolution.
4. Decision Revocation & Append-Only Audit Trail: History is never rewritten.
"""

import pytest
import pytest_asyncio
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, User, Membership, Domain, Asset,
    AssetContext, OrganizationalDecision, OrganizationalMemory, DecisionTransitionHistory
)
from app.application.context_service import OrganizationalContextService
from app.application.decision_service import DecisionService
from app.application.context_resolver import ContextResolver
from app.main import app
from shared_contracts.enums import (
    DecisionType, ScopeLevel, DecisionStatus, DomainStatus, Environment, Criticality
)


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session():
    async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session


@pytest_asyncio.fixture
async def multi_org_setup(db_session: AsyncSession):
    """Seed two completely separate organizations, users, and assets."""
    # Org A
    org_a = Organization(name="Org Alpha", slug="org-alpha")
    admin_a = User(email="admin_a@alpha.com", password_hash="hash", full_name="Admin Alpha")
    viewer_a = User(email="viewer_a@alpha.com", password_hash="hash", full_name="Viewer Alpha")
    db_session.add_all([org_a, admin_a, viewer_a])
    await db_session.commit()

    mem_admin_a = Membership(org_id=org_a.id, user_id=admin_a.id, role="admin")
    mem_viewer_a = Membership(org_id=org_a.id, user_id=viewer_a.id, role="viewer")
    domain_a = Domain(
        org_id=org_a.id,
        domain_name="alpha.com",
        status=DomainStatus.VERIFIED,
        verification_token="token-a",
        verified_at=datetime.now(timezone.utc),
    )
    db_session.add_all([mem_admin_a, mem_viewer_a, domain_a])
    await db_session.commit()

    asset_a = Asset(
        org_id=org_a.id,
        domain_id=domain_a.id,
        asset_type="service",
        identifier="api.alpha.com:443",
        environment="production",
        criticality="high",
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    db_session.add(asset_a)

    # Org B
    org_b = Organization(name="Org Beta", slug="org-beta")
    admin_b = User(email="admin_b@beta.com", password_hash="hash", full_name="Admin Beta")
    db_session.add_all([org_b, admin_b])
    await db_session.commit()

    mem_admin_b = Membership(org_id=org_b.id, user_id=admin_b.id, role="admin")
    domain_b = Domain(
        org_id=org_b.id,
        domain_name="beta.com",
        status=DomainStatus.VERIFIED,
        verification_token="token-b",
        verified_at=datetime.now(timezone.utc),
    )
    db_session.add_all([mem_admin_b, domain_b])
    await db_session.commit()

    asset_b = Asset(
        org_id=org_b.id,
        domain_id=domain_b.id,
        asset_type="service",
        identifier="api.alpha.com:443",  # Same exact identifier string in Org B!
        environment="production",
        criticality="low",
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    db_session.add(asset_b)
    await db_session.commit()

    return {
        "org_a_id": org_a.id,
        "admin_a_id": admin_a.id,
        "viewer_a_id": viewer_a.id,
        "asset_a_id": asset_a.id,
        "org_b_id": org_b.id,
        "admin_b_id": admin_b.id,
        "asset_b_id": asset_b.id,
    }


@pytest.mark.asyncio
async def test_tenant_isolation_decision_and_resolution(db_session: AsyncSession, multi_org_setup: dict):
    """Verify Org B cannot resolve or see decisions/memories created by Org A."""
    decision_service = DecisionService(db_session)
    resolver = ContextResolver(db_session)

    # Org A creates decision marking api.alpha.com:443 as EXPECTED
    await decision_service.create_decision(
        org_id=multi_org_setup["org_a_id"],
        actor_id=multi_org_setup["admin_a_id"],
        decision_type=DecisionType.MARK_EXPECTED.value,
        scope_level=ScopeLevel.SERVICE.value,
        subject_identifier="service:api.alpha.com:443",
        new_state={"expected_state": "EXPECTED"},
        reason="Org A approved endpoint",
    )
    await db_session.commit()

    # Resolve context for Org A
    res_a = await resolver.resolve_context(
        org_id=multi_org_setup["org_a_id"],
        target_type="service",
        target_identifier="api.alpha.com:443",
        domain_name="alpha.com",
    )
    assert res_a.expected_state == "EXPECTED"
    assert len(res_a.matched_memories) == 1

    # Resolve context for Org B (SAME identifier api.alpha.com:443)
    res_b = await resolver.resolve_context(
        org_id=multi_org_setup["org_b_id"],
        target_type="service",
        target_identifier="api.alpha.com:443",
        domain_name="beta.com",
    )
    # Org B MUST NOT inherit Org A's memory
    assert res_b.expected_state == "UNSPECIFIED"
    assert len(res_b.matched_memories) == 0


@pytest.mark.asyncio
async def test_tenant_isolation_context_update(db_session: AsyncSession, multi_org_setup: dict):
    """Verify Org B cannot access or update Org A's asset context."""
    context_service = OrganizationalContextService(db_session)

    # Update context in Org A
    await context_service.update_asset_context(
        org_id=multi_org_setup["org_a_id"],
        asset_id=multi_org_setup["asset_a_id"],
        actor_id=multi_org_setup["admin_a_id"],
        environment="production",
        criticality="critical",
        owner_team="Security Core",
    )
    await db_session.commit()

    # Attempt to retrieve Org A asset using Org B tenant ID
    ctx_b = await context_service.get_asset_context(
        org_id=multi_org_setup["org_b_id"],
        asset_id=multi_org_setup["asset_a_id"],
    )
    assert ctx_b is None


@pytest.mark.asyncio
async def test_rbac_view_vs_write_permissions(multi_org_setup: dict):
    """Verify API permissions: Admin can mutate context & decisions, Viewer is denied (403)."""
    admin_headers = {
        "X-User-ID": multi_org_setup["admin_a_id"],
        "X-Org-ID": multi_org_setup["org_a_id"],
    }
    viewer_headers = {
        "X-User-ID": multi_org_setup["viewer_a_id"],
        "X-Org-ID": multi_org_setup["org_a_id"],
    }

    org_id = multi_org_setup["org_a_id"]
    asset_id = multi_org_setup["asset_a_id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Viewer tries to update asset context -> 403 (require_member role check)
        resp = await client.patch(
            f"/api/v1/organizations/{org_id}/assets/{asset_id}/context",
            headers=viewer_headers,
            json={"environment": "production", "criticality": "critical"},
        )
        assert resp.status_code == 403, f"Expected 403 for viewer context update, got {resp.status_code}"

        # 2. Viewer tries to create decision -> 403
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/decisions",
            headers=viewer_headers,
            json={
                "decision_type": "mark_expected",
                "scope_level": "service",
                "subject_identifier": "service:api.alpha.com:443",
                "new_state": {"expected_state": "EXPECTED"},
                "reason": "Unauthorized attempt",
            },
        )
        assert resp.status_code == 403, f"Expected 403 for viewer decision creation, got {resp.status_code}"

        # 3. Admin creates decision -> 201
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/decisions",
            headers=admin_headers,
            json={
                "decision_type": "mark_expected",
                "scope_level": "service",
                "subject_identifier": "service:api.alpha.com:443",
                "new_state": {"expected_state": "EXPECTED"},
                "reason": "Admin legitimate approval",
            },
        )
        assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
        dec_id = resp.json()["id"]

        # 4. Viewer can GET decisions -> 200
        resp = await client.get(
            f"/api/v1/organizations/{org_id}/decisions",
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

        # 5. Viewer tries to revoke decision -> 403
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/decisions/{dec_id}/revoke",
            headers=viewer_headers,
            json={"reason": "Viewer attempt to revoke"},
        )
        assert resp.status_code == 403

        # 6. Admin revokes decision -> 200
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/decisions/{dec_id}/revoke",
            headers=admin_headers,
            json={"reason": "Admin revoking decision"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"
