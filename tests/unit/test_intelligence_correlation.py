"""Unit test suite for Phase 4 Threat & Vulnerability Intelligence Ingestion & Correlation Engine."""
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, Domain, Asset, ExposureCondition
from app.application.intelligence_ingestion_service import IntelligenceIngestionService
from app.application.intelligence_correlation_service import (
    IntelligenceCorrelationService, evaluate_version_match, calculate_deterministic_confidence, parse_technology_and_version
)
from app.application.intelligence_providers.base_provider import BaseIntelligenceProvider, ProviderValidationError, sanitize_text
from app.application.intelligence_providers.nvd_provider import NvdIntelligenceProvider
from app.application.intelligence_providers.kev_provider import CisaKevIntelligenceProvider
from app.application.intelligence_providers.epss_provider import FirstEpssIntelligenceProvider
from shared_contracts.enums import (
    IntelligenceSourceType, CorrelationState, CorrelationConfidenceBand, FreshnessStatus
)


@pytest_asyncio.fixture
async def async_unit_intel_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        org = Organization(id="org-unit-intel", name="Unit Intel Org", slug="unit-intel-org")
        dom = Domain(id="dom-unit-intel", org_id="org-unit-intel", domain_name="intelunit.com", status="verified", verification_token="tokUnitIntel")
        a1 = Asset(id="ast-intel-1", org_id="org-unit-intel", domain_id="dom-unit-intel", asset_type="service", identifier="ssh.intelunit.com:22 (Apache/2.4.49)", environment="production", criticality="critical")
        a2 = Asset(id="ast-intel-2", org_id="org-unit-intel", domain_id="dom-unit-intel", asset_type="service", identifier="db.intelunit.com:5432 (PostgreSQL)", environment="production", criticality="high")

        session.add_all([org, dom, a1, a2])
        await session.commit()
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_provider_payload_size_and_depth_validation():
    """Verify provider enforces 10MB payload size limit and nested depth limits."""
    provider = BaseIntelligenceProvider("test_provider", "nvd")
    
    # Payload over 10MB
    large_bytes = b"A" * (10 * 1024 * 1024 + 1)
    with pytest.raises(ProviderValidationError):
        provider.validate_payload_size(large_bytes)

    # Nesting depth > 10
    nested = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"k": "deep"}}}}}}}}}}}
    with pytest.raises(ProviderValidationError):
        provider.validate_structure_depth(nested)


@pytest.mark.asyncio
async def test_input_string_sanitization():
    """Verify sanitize_text removes null bytes and control sequences."""
    raw_text = "Apache\x00 Server\x07 Header\nValid"
    cleaned = sanitize_text(raw_text)
    assert "\x00" not in cleaned
    assert "\x07" not in cleaned
    assert "Apache Server Header" in cleaned


@pytest.mark.asyncio
async def test_version_match_evaluation_semantics():
    """Verify version match semantics distinguish POTENTIAL_MATCH from VERSION_CONFIRMED."""
    # Missing version -> POTENTIAL_MATCH
    state1, reason1 = evaluate_version_match(None, ">=2.4.0, <=2.4.49")
    assert state1 == CorrelationState.POTENTIAL_MATCH.value
    assert "exact observed version unavailable" in reason1

    # Matching version -> VERSION_CONFIRMED
    state2, reason2 = evaluate_version_match("2.4.49", ">=2.4.0, <=2.4.49")
    assert state2 == CorrelationState.VERSION_CONFIRMED.value
    assert "matches affected range" in reason2

    # Unmatched version -> UNMATCHED
    state3, reason3 = evaluate_version_match("2.4.53", "2.4.49")
    assert state3 == CorrelationState.UNMATCHED.value


@pytest.mark.asyncio
async def test_technology_and_version_parsing_heuristic():
    """Verify parse_technology_and_version extracts product and version accurately."""
    tech1, ver1 = parse_technology_and_version("http.example.com (Apache/2.4.49)")
    assert tech1 == "apache"
    assert ver1 == "2.4.49"

    tech2, ver2 = parse_technology_and_version("ssh.example.com:22 (OpenSSH_8.2p1)")
    assert tech2 == "openssh"
    assert ver2 == "8.2p1"


@pytest.mark.asyncio
async def test_ingestion_service_stores_and_updates_records(async_unit_intel_db: AsyncSession):
    """Verify IntelligenceIngestionService ingests feed payload and updates records idempotently."""
    svc = IntelligenceIngestionService(async_unit_intel_db)
    payload = """{
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-41773",
                    "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "baseSeverity": "HIGH"}}]
                    },
                    "configurations": [
                        {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "versionStartIncluding": "2.4.49", "versionEndIncluding": "2.4.49"}]}]}
                    ]
                }
            }
        ]
    }"""
    
    run = await svc.ingest_feed_payload(
        org_id="org-unit-intel",
        source_name="nvd_cve_feed",
        source_type=IntelligenceSourceType.NVD.value,
        payload_content=payload
    )

    assert run.status == "completed"
    assert run.records_ingested == 1

    records = await svc.list_records("org-unit-intel")
    assert len(records) == 1
    assert records[0].external_id == "CVE-2021-41773"
    assert records[0].affected_product == "http_server"
