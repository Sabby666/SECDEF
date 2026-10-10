"""Unit tests for Phase 2 Discovery Framework, Providers, and Validation Engine."""
import pytest
import pytest_asyncio
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, Domain, DiscoverySource, DiscoveryRun, DiscoveryCandidate
from app.application.discovery_providers.ct_provider import CertificateTransparencyProvider
from app.application.discovery_providers.passive_dns_provider import PassiveDNSProvider
from app.application.discovery_providers.active_dns_provider import ActiveDNSDiscoveryProvider, is_ip_safe_for_egress
from app.application.discovery_service import DiscoveryService
from app.application.candidate_validation_service import CandidateValidationService
from shared_contracts.enums import ValidationState, DiscoveryConfidence, ExposureState


@pytest_asyncio.fixture
async def async_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        # Seed test org & domain
        org = Organization(id="org-disc-test-01", name="Discovery Test Org", slug="discovery-test-org")
        domain = Domain(id="dom-disc-test-01", org_id="org-disc-test-01", domain_name="example.com", status="verified", verification_token="tok123")
        session.add_all([org, domain])
        await session.commit()
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_ct_provider_discovery():
    """Test Certificate Transparency provider candidate generation and SAN capping."""
    provider = CertificateTransparencyProvider()
    evidences = await provider.execute_discovery("org-disc-test-01", "example.com")
    assert len(evidences) > 0
    for ev in evidences:
        assert ev.canonical_identifier.endswith("example.com")
        assert ev.source_type == "certificate_transparency"
        assert ev.confidence == DiscoveryConfidence.MEDIUM.value


@pytest.mark.asyncio
async def test_passive_dns_provider_discovery():
    """Test Passive DNS provider historical exposure classification."""
    provider = PassiveDNSProvider()
    evidences = await provider.execute_discovery("org-disc-test-01", "example.com")
    assert len(evidences) > 0
    exposures = {ev.exposure_state for ev in evidences}
    assert ExposureState.CURRENT.value in exposures or ExposureState.HISTORICAL.value in exposures


@pytest.mark.asyncio
async def test_active_dns_provider_safety():
    """Test Active DNS provider egress IP safety checks."""
    assert is_ip_safe_for_egress("1.1.1.1") is True
    assert is_ip_safe_for_egress("10.0.0.1") is False
    assert is_ip_safe_for_egress("127.0.0.1") is False
    assert is_ip_safe_for_egress("169.254.169.254") is False
    assert is_ip_safe_for_egress("::1") is False


@pytest.mark.asyncio
async def test_discovery_service_run_and_correlation(async_db: AsyncSession):
    """Test full DiscoveryService execution run and candidate correlation."""
    service = DiscoveryService(async_db)
    
    # Execute CT run
    run = await service.start_discovery_run("org-disc-test-01", "dom-disc-test-01", "certificate_transparency")
    assert run.status == "completed"
    assert run.candidates_discovered > 0

    # Query candidates
    candidates = await service.list_candidates("org-disc-test-01")
    assert len(candidates) > 0
    first_cand = candidates[0]
    assert first_cand.validation_state == ValidationState.UNVALIDATED.value


@pytest.mark.asyncio
async def test_candidate_validation_and_asset_promotion(async_db: AsyncSession):
    """Test candidate validation state transition and promotion to Phase 1 Asset graph."""
    service = DiscoveryService(async_db)
    val_service = CandidateValidationService(async_db)

    # Execute run to populate candidate
    await service.start_discovery_run("org-disc-test-01", "dom-disc-test-01", "certificate_transparency")
    candidates = await service.list_candidates("org-disc-test-01")
    cand = candidates[0]

    # Validate candidate
    validated = await val_service.validate_candidate(cand.id, "org-disc-test-01")
    assert validated.validation_state == ValidationState.DNS_CONFIRMED.value
    assert validated.promoted_asset_id is not None
