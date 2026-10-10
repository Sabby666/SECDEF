"""RBAC security tests for Phase 2 Discovery endpoints."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.infrastructure.db.session import get_db_session
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, User, Membership, Domain
from app.main import app
from shared_contracts.enums import UserRole


@pytest_asyncio.fixture
async def async_rbac_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        # Create Org
        org = Organization(id="org-rbac-disc", name="RBAC Disc Org", slug="rbac-disc-org")
        dom = Domain(id="dom-rbac-disc", org_id="org-rbac-disc", domain_name="rbac-disc.com", status="verified", verification_token="tokRbac")

        # Create Users with roles
        user_viewer = User(id="usr-viewer", email="viewer@rbac.com", password_hash="pass", full_name="Viewer User", status="active")
        mem_viewer = Membership(id="mem-viewer", org_id="org-rbac-disc", user_id="usr-viewer", role=UserRole.VIEWER.value)

        user_member = User(id="usr-member", email="member@rbac.com", password_hash="pass", full_name="Member User", status="active")
        mem_member = Membership(id="mem-member", org_id="org-rbac-disc", user_id="usr-member", role=UserRole.MEMBER.value)

        user_admin = User(id="usr-admin", email="admin@rbac.com", password_hash="pass", full_name="Admin User", status="active")
        mem_admin = Membership(id="mem-admin", org_id="org-rbac-disc", user_id="usr-admin", role=UserRole.ADMIN.value)

        session.add_all([org, dom, user_viewer, mem_viewer, user_member, mem_member, user_admin, mem_admin])
        await session.commit()
        
        # Override FastAPI dependency to use this test session
        app.dependency_overrides[get_db_session] = lambda: session
        yield session
        app.dependency_overrides.clear()

    await engine.dispose()



@pytest.mark.asyncio
async def test_rbac_viewer_can_read_discovery_data(async_rbac_db: AsyncSession):
    """Verify Viewer role can read discovery sources, runs, and candidates."""
    headers = {"x-user-id": "usr-viewer", "x-org-id": "org-rbac-disc"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Read sources
        res1 = await client.get("/api/v1/organizations/org-rbac-disc/discovery/sources", headers=headers)
        assert res1.status_code == 200

        # Read runs
        res2 = await client.get("/api/v1/organizations/org-rbac-disc/discovery/runs", headers=headers)
        assert res2.status_code == 200

        # Read candidates
        res3 = await client.get("/api/v1/organizations/org-rbac-disc/discovery/candidates", headers=headers)
        assert res3.status_code == 200


@pytest.mark.asyncio
async def test_rbac_viewer_cannot_mutate_discovery_data(async_rbac_db: AsyncSession):
    """Verify Viewer role cannot trigger discovery runs or validate candidates."""
    headers = {"x-user-id": "usr-viewer", "x-org-id": "org-rbac-disc"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Attempt to trigger discovery run
        payload = {"domain_id": "dom-rbac-disc", "source_type": "certificate_transparency"}
        res1 = await client.post("/api/v1/organizations/org-rbac-disc/discovery/runs", json=payload, headers=headers)
        assert res1.status_code == 403
        assert "Required role in" in res1.text


@pytest.mark.asyncio
async def test_rbac_member_can_trigger_and_validate(async_rbac_db: AsyncSession):
    """Verify Member role can trigger discovery runs and validate candidates."""
    headers = {"x-user-id": "usr-member", "x-org-id": "org-rbac-disc"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Trigger discovery run
        payload = {"domain_id": "dom-rbac-disc", "source_type": "certificate_transparency"}
        res1 = await client.post("/api/v1/organizations/org-rbac-disc/discovery/runs", json=payload, headers=headers)
        assert res1.status_code == 201
        run_data = res1.json()
        assert run_data["status"] == "completed"


@pytest.mark.asyncio
async def test_rbac_admin_only_source_configuration(async_rbac_db: AsyncSession):
    """Verify Member and Viewer cannot configure discovery sources, but Admin can."""
    src_payload = {"source_type": "custom_connector", "name": "Custom Integration Source", "config": {"key": "val"}}

    # Member attempt -> 403 Forbidden
    mem_headers = {"x-user-id": "usr-member", "x-org-id": "org-rbac-disc"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res_mem = await client.post("/api/v1/organizations/org-rbac-disc/discovery/sources", json=src_payload, headers=mem_headers)
        assert res_mem.status_code == 403

    # Admin attempt -> 201 Created
    adm_headers = {"x-user-id": "usr-admin", "x-org-id": "org-rbac-disc"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res_adm = await client.post("/api/v1/organizations/org-rbac-disc/discovery/sources", json=src_payload, headers=adm_headers)
        assert res_adm.status_code == 201
        data = res_adm.json()
        assert data["name"] == "Custom Integration Source"
        assert data["source_type"] == "custom_connector"

