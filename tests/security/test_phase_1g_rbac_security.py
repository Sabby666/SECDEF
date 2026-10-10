import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, User, Membership, Domain, Scan, ComparisonRun, Change, Finding
)
from app.main import app
from shared_contracts.enums import UserRole, ChangeType, ScanCompleteness, FindingLifecycleStatus


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
async def rbac_env(db_session: AsyncSession):
    org = Organization(name="RBAC Test Org", slug="rbac-test-org")
    admin_user = User(email="admin@test.com", password_hash="hash", full_name="Admin User")
    member_user = User(email="member@test.com", password_hash="hash", full_name="Member User")
    viewer_user = User(email="viewer@test.com", password_hash="hash", full_name="Viewer User")
    db_session.add_all([org, admin_user, member_user, viewer_user])
    await db_session.commit()

    m_admin = Membership(org_id=org.id, user_id=admin_user.id, role=UserRole.ADMIN.value)
    m_member = Membership(org_id=org.id, user_id=member_user.id, role=UserRole.MEMBER.value)
    m_viewer = Membership(org_id=org.id, user_id=viewer_user.id, role=UserRole.VIEWER.value)
    db_session.add_all([m_admin, m_member, m_viewer])
    await db_session.commit()

    domain = Domain(org_id=org.id, domain_name="rbac.com", status="verified", verification_token="tok")
    db_session.add(domain)
    await db_session.commit()

    scan = Scan(org_id=org.id, domain_id=domain.id, status="completed", job_nonce="nonce-rbac")
    db_session.add(scan)
    await db_session.commit()

    comp = ComparisonRun(org_id=org.id, domain_id=domain.id, current_scan_id=scan.id, status="completed", current_scan_completeness=ScanCompleteness.COMPLETE.value, changes_detected=1)
    db_session.add(comp)
    await db_session.commit()

    change = Change(org_id=org.id, comparison_run_id=comp.id, change_type=ChangeType.ASSET_ADDED.value, entity_type="subdomain", entity_identifier="sub.rbac.com", current_scan_id=scan.id)
    db_session.add(change)
    await db_session.commit()

    finding = Finding(org_id=org.id, change_id=change.id, title="Test Finding", description="Desc", status=FindingLifecycleStatus.OPEN.value)
    db_session.add(finding)
    await db_session.commit()

    return {
        "org": org,
        "admin": admin_user,
        "member": member_user,
        "viewer": viewer_user,
        "finding": finding
    }


@pytest.mark.asyncio
async def test_viewer_rbac_permissions(rbac_env: dict):
    """Verify Viewer can view findings/notifications but is blocked from mutations and admin actions."""
    org = rbac_env["org"]
    viewer = rbac_env["viewer"]
    finding = rbac_env["finding"]

    headers = {"x-user-id": viewer.id, "x-org-id": org.id}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Allowed GET endpoints
        res_list = await client.get(f"/api/v1/organizations/{org.id}/findings", headers=headers)
        assert res_list.status_code == 200

        res_get = await client.get(f"/api/v1/organizations/{org.id}/findings/{finding.id}", headers=headers)
        assert res_get.status_code == 200

        res_notif = await client.get(f"/api/v1/organizations/{org.id}/notifications", headers=headers)
        assert res_notif.status_code == 200

        # 2. Blocked Mutations
        res_ack = await client.post(
            f"/api/v1/organizations/{org.id}/findings/{finding.id}/acknowledge",
            headers=headers,
            json={"reason": "Viewer trying to acknowledge"}
        )
        assert res_ack.status_code == 403

        res_ver = await client.post(f"/api/v1/organizations/{org.id}/findings/{finding.id}/verify", headers=headers)
        assert res_ver.status_code == 403

        res_dest = await client.post(
            f"/api/v1/organizations/{org.id}/notifications/destinations",
            headers=headers,
            json={"channel": "webhook", "name": "Dest", "config": {"url": "https://webhook.example.com"}}
        )
        assert res_dest.status_code == 403


@pytest.mark.asyncio
async def test_member_rbac_permissions(rbac_env: dict):
    """Verify Member can acknowledge findings and trigger verification but cannot manage notification policies/destinations."""
    org = rbac_env["org"]
    member = rbac_env["member"]
    finding = rbac_env["finding"]

    headers = {"x-user-id": member.id, "x-org-id": org.id}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Allowed operational finding mutations
        res_ack = await client.post(
            f"/api/v1/organizations/{org.id}/findings/{finding.id}/acknowledge",
            headers=headers,
            json={"reason": "Member acknowledging finding"}
        )
        assert res_ack.status_code == 200
        assert res_ack.json()["status"] == "acknowledged"

        res_ver = await client.post(f"/api/v1/organizations/{org.id}/findings/{finding.id}/verify", headers=headers)
        assert res_ver.status_code == 200

        # 2. Blocked Admin Configuration
        res_dest = await client.post(
            f"/api/v1/organizations/{org.id}/notifications/destinations",
            headers=headers,
            json={"channel": "webhook", "name": "Dest", "config": {"url": "https://webhook.example.com"}}
        )
        assert res_dest.status_code == 403

        res_policy = await client.post(
            f"/api/v1/organizations/{org.id}/notifications/policies",
            headers=headers,
            json={"name": "Policy", "min_risk_band": "HIGH"}
        )
        assert res_policy.status_code == 403


@pytest.mark.asyncio
async def test_admin_rbac_permissions(rbac_env: dict, monkeypatch):
    """Verify Admin can manage notification destinations, policies, and test webhooks."""
    org = rbac_env["org"]
    admin = rbac_env["admin"]

    headers = {"x-user-id": admin.id, "x-org-id": org.id}
    monkeypatch.setattr("app.infrastructure.notifications.webhook_delivery.WebhookDeliveryService.validate_url_and_resolve", lambda url: ("webhook.example.com", "93.184.216.34", 443))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create Destination
        res_dest = await client.post(
            f"/api/v1/organizations/{org.id}/notifications/destinations",
            headers=headers,
            json={"channel": "webhook", "name": "Admin Dest", "config": {"url": "https://webhook.example.com/ep"}}
        )
        assert res_dest.status_code == 201

        # Create Policy
        res_pol = await client.post(
            f"/api/v1/organizations/{org.id}/notifications/policies",
            headers=headers,
            json={"name": "Admin Policy", "min_risk_band": "HIGH"}
        )
        assert res_pol.status_code == 201
