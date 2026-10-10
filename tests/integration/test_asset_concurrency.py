import uuid
import asyncio
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
from sqlalchemy.pool import StaticPool

from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, Asset, AssetRelationship
from app.application.asset_resolution_service import AssetResolutionService

TEST_ORG_ID = "org-concurrent-123"


@pytest_asyncio.fixture
async def db_session_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        echo=False
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


    async_session_maker = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with async_session_maker() as session:
        org = Organization(id=TEST_ORG_ID, name="Concurrent Corp", slug="concurrent-corp")
        session.add(org)
        await session.commit()

    yield async_session_maker

    await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_asset_resolution(db_session_factory):
    async def _resolve():
        async with db_session_factory() as session:
            service = AssetResolutionService(session)
            asset = await service.resolve_or_create_asset(
                org_id=TEST_ORG_ID,
                asset_type="subdomain",
                raw_identifier="concurrent.example.com"
            )
            await session.commit()
            return asset.id

    results = await asyncio.gather(_resolve(), _resolve(), _resolve(), return_exceptions=False)

    # All returned asset IDs must be identical
    asset_ids = set(results)
    assert len(asset_ids) == 1

    # Database query must return exactly 1 asset record
    async with db_session_factory() as session:
        res = await session.execute(
            select(Asset).where(Asset.org_id == TEST_ORG_ID, Asset.identifier == "concurrent.example.com")
        )
        db_assets = res.scalars().all()
        assert len(db_assets) == 1


@pytest.mark.asyncio
async def test_concurrent_relationship_creation(db_session_factory):
    async with db_session_factory() as session:
        service = AssetResolutionService(session)
        asset1 = await service.resolve_or_create_asset(TEST_ORG_ID, "subdomain", "app.concurrent.com")
        asset2 = await service.resolve_or_create_asset(TEST_ORG_ID, "ip_address", "198.51.100.1")
        await session.commit()
        asset1_id = asset1.id
        asset2_id = asset2.id

    async def _create_edge():
        async with db_session_factory() as session:
            service = AssetResolutionService(session)
            rel = await service.resolve_or_create_relationship(
                org_id=TEST_ORG_ID,
                source_asset_id=asset1_id,
                target_asset_id=asset2_id,
                relationship_type="resolves_to"
            )
            await session.commit()
            return rel.id

    rel_results = await asyncio.gather(_create_edge(), _create_edge(), return_exceptions=False)

    rel_ids = set(rel_results)
    assert len(rel_ids) == 1

    async with db_session_factory() as session:
        res = await session.execute(
            select(AssetRelationship).where(
                AssetRelationship.org_id == TEST_ORG_ID,
                AssetRelationship.source_asset_id == asset1_id,
                AssetRelationship.target_asset_id == asset2_id
            )
        )
        db_rels = res.scalars().all()
        assert len(db_rels) == 1
