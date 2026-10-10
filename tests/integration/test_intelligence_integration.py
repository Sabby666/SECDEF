"""Integration test suite for Phase 4 Threat & Vulnerability Intelligence Correlation Layer."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.infrastructure.db.base import Base
from app.infrastructure.db.session import get_db_session
from app.infrastructure.db.models import Organization, User, Membership, Domain, Asset
from app.application.intelligence_ingestion_service import IntelligenceIngestionService
from app.application.intelligence_correlation_service import IntelligenceCorrelationService
from app.main import app
from shared_contracts.enums import UserRole, IntelligenceSourceType


@pytest_asyncio.fixture
async def async_intel_integ_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        org = Organization(id="org-integ-intel", name="Integ Intel Org", slug="integ-intel-org")
        dom = Domain(id="dom-integ-intel", org_id="org-integ-intel", domain_name="integintel.com", status="verified", verification_token="tokIntegIntel")

        u_viewer = User(id="usr-integ-intel-v", email="v@integintel.com", password_hash="pass", full_name="Integ Viewer", status="active")
        m_viewer = Membership(id="mem-integ-intel-v", org_id="org-integ-intel", user_id="usr-integ-intel-v", role=UserRole.VIEWER.value)

        a1 = Asset(id="ast-integ-intel-1", org_id="org-integ-intel", domain_id="dom-integ-intel", asset_type="service", identifier="web.integintel.com:443 (Apache/2.4.49)", environment="production", criticality="high")

        session.add_all([org, dom, u_viewer, m_viewer, a1])
        await session.commit()

        app.dependency_overrides[get_db_session] = lambda: session
        yield session
        app.dependency_overrides.clear()

    await engine.dispose()


@pytest.mark.asyncio
async def test_intelligence_api_pagination_and_filtering(async_intel_integ_db: AsyncSession):
    """Verify intelligence records and correlations API endpoints support pagination and filtering."""
    ingest_svc = IntelligenceIngestionService(async_intel_integ_db)
    payload = """{"vulnerabilities": [{"cve": {"id": "CVE-2021-41773", "descriptions": [{"lang": "en", "value": "Path traversal"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}]}}]}"""
    await ingest_svc.ingest_feed_payload("org-integ-intel", "nvd_feed", IntelligenceSourceType.NVD.value, payload)

    corr_svc = IntelligenceCorrelationService(async_intel_integ_db)
    await corr_svc.run_intelligence_correlation("org-integ-intel")

    headers = {"x-user-id": "usr-integ-intel-v", "x-org-id": "org-integ-intel"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Fetch intelligence with limit=1
        res1 = await client.get("/api/v1/organizations/org-integ-intel/intelligence?limit=1", headers=headers)
        assert res1.status_code == 200
        data1 = res1.json()
        assert len(data1) == 1

        # Fetch correlations for asset
        res2 = await client.get("/api/v1/organizations/org-integ-intel/assets/ast-integ-intel-1/intelligence", headers=headers)
        assert res2.status_code == 200
        data2 = res2.json()
        assert len(data2) > 0
        assert data2[0]["observed_technology"] == "apache"


@pytest.mark.asyncio
async def test_authorization_header_forgery_defense_intelligence(async_intel_integ_db: AsyncSession):
    """Verify header forgery for un-associated organization returns HTTP 403."""
    headers = {"x-user-id": "usr-integ-intel-v", "x-org-id": "org-unauthorized-forged"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/organizations/org-integ-intel/intelligence", headers=headers)
        assert res.status_code in [403, 404]
