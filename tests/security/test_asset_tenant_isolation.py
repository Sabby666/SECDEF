import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, User, Membership, Asset, AssetRelationship
from app.application.asset_resolution_service import AssetResolutionService
from app.infrastructure.db.session import get_db_session
from app.main import app
from shared_contracts.enums import UserRole


@pytest_asyncio.fixture
async def test_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_cross_tenant_asset_resolution_isolation(test_db: AsyncSession):
    """
    Assert that resolving an asset with identical identifier in Org A and Org B
    creates TWO distinct tenant-isolated assets. Org A observation NEVER resolves to Org B asset.
    """
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b")
    test_db.add_all([org_a, org_b])
    await test_db.commit()

    service = AssetResolutionService(test_db)

    # Resolve same domain identifier for Org A and Org B
    asset_a = await service.resolve_or_create_asset(org_a.id, "subdomain", "shared.example.com")
    asset_b = await service.resolve_or_create_asset(org_b.id, "subdomain", "shared.example.com")
    await test_db.commit()

    assert asset_a.id != asset_b.id
    assert asset_a.org_id == org_a.id
    assert asset_b.org_id == org_b.id

    # Verify query for Org A returns ONLY Org A asset
    res_a = await test_db.execute(select(Asset).where(Asset.org_id == org_a.id))
    org_a_assets = res_a.scalars().all()
    assert len(org_a_assets) == 1
    assert org_a_assets[0].id == asset_a.id


@pytest.mark.asyncio
async def test_cross_tenant_relationship_rejection(test_db: AsyncSession):
    """
    Attempting to create a relationship edge between an Org A asset and an Org B asset
    MUST be rejected immediately with a security/validation error.
    """
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-rel")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-rel")
    test_db.add_all([org_a, org_b])
    await test_db.commit()

    service = AssetResolutionService(test_db)
    asset_a = await service.resolve_or_create_asset(org_a.id, "subdomain", "app.org-a.com")
    asset_b = await service.resolve_or_create_asset(org_b.id, "ip_address", "192.0.2.5")
    await test_db.commit()

    # Attempt cross-tenant relationship creation scoped to Org A
    with pytest.raises(ValueError, match="Cross-tenant or invalid relationship"):
        await service.resolve_or_create_relationship(
            org_id=org_a.id,
            source_asset_id=asset_a.id,
            target_asset_id=asset_b.id,
            relationship_type="resolves_to"
        )


@pytest.mark.asyncio
async def test_api_cross_tenant_asset_access_rejected(test_db: AsyncSession):
    """
    API test: User authenticated to Org A attempts to query Org B assets.
    Must return HTTP 403 Forbidden.
    """
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-api")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-api")
    user_a = User(id=str(uuid.uuid4()), email="user_a@org-a.com", password_hash="hash", full_name="User A")
    mem_a = Membership(id=str(uuid.uuid4()), org_id=org_a.id, user_id=user_a.id, role=UserRole.VIEWER)

    test_db.add_all([org_a, org_b, user_a, mem_a])
    await test_db.commit()

    # Create asset in Org B
    service = AssetResolutionService(test_db)
    await service.resolve_or_create_asset(org_b.id, "subdomain", "secret.org-b.com")
    await test_db.commit()

    async def _override_get_db():
        yield test_db

    app.dependency_overrides[get_db_session] = _override_get_db

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # User A attempts to list Org B assets using X-User-ID and X-Org-ID headers for Org A context
            headers = {
                "X-User-ID": user_a.id,
                "X-Org-ID": org_a.id
            }

            # Request Org B's assets path while authenticated to Org A
            resp = await client.get(f"/api/v1/organizations/{org_b.id}/assets", headers=headers)
            assert resp.status_code == 403
            assert "Cross-tenant access denied" in resp.json()["detail"]
    finally:
        app.dependency_overrides.clear()
