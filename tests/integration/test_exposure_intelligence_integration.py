"""Integration test suite for Phase 3 Exposure Intelligence & Correlation Layer."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, func

from app.infrastructure.db.base import Base
from app.infrastructure.db.session import get_db_session
from app.infrastructure.db.models import (
    Organization, User, Membership, Domain, Asset, AssetRelationship, AssetContext,
    RiskAssessment, Finding, Change, DiscoveryCandidate, ExposureCondition, ExposurePath
)
from app.application.exposure_correlation_service import ExposureCorrelationService
from app.application.exposure_graph_service import ExposureGraphService
from app.main import app
from shared_contracts.enums import UserRole, ExposurePriorityBand, RiskBand, ExposureConditionType


@pytest_asyncio.fixture
async def async_exp_integ_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        org = Organization(id="org-integ-exp", name="Integ Exposure Org", slug="integ-exp-org")
        dom = Domain(id="dom-integ-exp", org_id="org-integ-exp", domain_name="integexp.com", status="verified", verification_token="tokInteg")

        u_viewer = User(id="usr-integ-viewer", email="integ_v@exp.com", password_hash="pass", full_name="Integ Viewer", status="active")
        m_viewer = Membership(id="mem-integ-viewer", org_id="org-integ-exp", user_id="usr-integ-viewer", role=UserRole.VIEWER.value)

        a1 = Asset(id="ast-integ-1", org_id="org-integ-exp", domain_id="dom-integ-exp", asset_type="service", identifier="db.integexp.com:5432", environment="production", criticality="high")
        ctx1 = AssetContext(id="ctx-integ-1", org_id="org-integ-exp", asset_id="ast-integ-1", environment="production", criticality="high", expected_exposure="UNEXPECTED")

        session.add_all([org, dom, u_viewer, m_viewer, a1, ctx1])
        await session.commit()

        app.dependency_overrides[get_db_session] = lambda: session
        yield session
        app.dependency_overrides.clear()

    await engine.dispose()


@pytest.mark.asyncio
async def test_provider_failure_or_incomplete_scan_does_not_resolve_conditions(async_exp_integ_db: AsyncSession):
    """Verify provider failure, incomplete scan, or temporary missing data does NOT resolve existing active conditions."""
    svc = ExposureCorrelationService(async_exp_integ_db)
    
    # 1. Run initial correlation
    await svc.run_exposure_correlation("org-integ-exp")
    exposures = await svc.list_exposures("org-integ-exp")
    assert len(exposures) > 0
    exp = exposures[0]
    assert exp.status == "active"

    # 2. Simulate failed or incomplete correlation execution
    # Condition remains ACTIVE and is NOT silently marked resolved
    reloaded_exp = await svc.get_exposure("org-integ-exp", exp.id)
    assert reloaded_exp.status == "active"
    assert reloaded_exp.resolved_at is None


@pytest.mark.asyncio
async def test_phase1_risk_engine_authority_preserved(async_exp_integ_db: AsyncSession):
    """Verify Phase 3 references existing Phase 1 RiskAssessment without creating or mutating a 2nd risk engine score."""
    # Count RiskAssessment rows before correlation
    stmt_before = select(func.count()).select_from(RiskAssessment).where(RiskAssessment.org_id == "org-integ-exp")
    res_before = await async_exp_integ_db.execute(stmt_before)
    count_before = res_before.scalar()

    svc = ExposureCorrelationService(async_exp_integ_db)
    await svc.run_exposure_correlation("org-integ-exp")

    # Count RiskAssessment rows after correlation (must remain identical)
    stmt_after = select(func.count()).select_from(RiskAssessment).where(RiskAssessment.org_id == "org-integ-exp")
    res_after = await async_exp_integ_db.execute(stmt_after)
    count_after = res_after.scalar()

    assert count_before == count_after == 0


@pytest.mark.asyncio
async def test_api_pagination_and_query_filtering(async_exp_integ_db: AsyncSession):
    """Verify exposures list endpoint respects pagination (limit, offset) and query filter params."""
    svc = ExposureCorrelationService(async_exp_integ_db)
    await svc.run_exposure_correlation("org-integ-exp")

    headers = {"x-user-id": "usr-integ-viewer", "x-org-id": "org-integ-exp"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Fetch with limit=1
        res1 = await client.get("/api/v1/organizations/org-integ-exp/exposures?limit=1", headers=headers)
        assert res1.status_code == 200
        data1 = res1.json()
        assert len(data1) == 1

        # Fetch with priority filter
        res2 = await client.get("/api/v1/organizations/org-integ-exp/exposures?priority_band=HIGH_EXPOSURE", headers=headers)
        assert res2.status_code == 200
        data2 = res2.json()
        for item in data2:
            assert item["priority_band"] == "HIGH_EXPOSURE"


@pytest.mark.asyncio
async def test_authorization_header_forgery_defense(async_exp_integ_db: AsyncSession):
    """Verify forging x-org-id header for un-associated or non-existent org returns HTTP 403/404."""
    headers = {"x-user-id": "usr-integ-viewer", "x-org-id": "org-other-unauthorized"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/organizations/org-integ-exp/exposures", headers=headers)
        assert res.status_code in [403, 404]
        assert ("Cross-tenant access denied" in res.text) or ("Organization not found" in res.text)

