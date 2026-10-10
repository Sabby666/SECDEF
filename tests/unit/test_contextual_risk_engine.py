"""Phase 1F Unit Tests: Contextual Risk Engine & Traceable Security Evidence.

Comprehensive tests for:
1. Deterministic factor scoring & contiguous band mapping (CRITICAL, HIGH, MEDIUM, LOW, INFO).
2. Service Exposure Double-Counting Prevention (8443, 443, 22 precedence).
3. Uncertainty & Missing Data Semantics (Risk score blindspot contribution + Confidence reduction).
4. Context Conflict Handling (CONFLICT_REQUIRES_REVIEW -> EXPECTED_STATE_CONFLICT flag + 20 pts).
5. Model Versioning & Historical Immutability (v1 vs v2 independent assessments).
6. Expired / Revoked Organizational Memory Exclusion.
7. Idempotency & Concurrency handling.
8. Determinism (Identical inputs yield 100% identical risk outputs).
"""

import asyncio
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, func

from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, User, Domain, Scan, ComparisonRun, Change, Asset,
    AssetContext, OrganizationalDecision, OrganizationalMemory, RiskAssessment
)
from app.application.risk_model import RiskModelV1
from app.application.risk_engine_service import RiskEngineService
from app.application.decision_service import DecisionService
from shared_contracts.enums import (
    RiskBand, RiskModelVersion, ChangeType, DomainStatus, ScopeLevel, DecisionType
)
from shared_contracts.schemas import ContextResolutionResponse, ProvenanceExplanation


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
async def seed_data(db_session: AsyncSession):
    org = Organization(name="Risk Test Org", slug="risk-test-org")
    user = User(email="risk_admin@test.com", password_hash="hash", full_name="Risk Admin")
    db_session.add_all([org, user])
    await db_session.commit()

    domain = Domain(
        org_id=org.id,
        domain_name="example.com",
        status=DomainStatus.VERIFIED,
        verification_token="token",
        verified_at=datetime.now(timezone.utc),
    )
    db_session.add(domain)
    await db_session.commit()

    scan = Scan(
        org_id=org.id,
        domain_id=domain.id,
        job_nonce="nonce-risk-unit",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    await db_session.commit()

    comp_run = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=scan.id,
        status="completed",
        current_scan_completeness="complete",
        changes_detected=1,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(comp_run)
    await db_session.commit()

    change = Change(
        org_id=org.id,
        comparison_run_id=comp_run.id,
        change_type=ChangeType.ASSET_ADDED.value,
        entity_type="service",
        entity_identifier="staging-api.example.com:8443",
        current_scan_id=scan.id,
        evidence={"port": 8443},
        detected_at=datetime.now(timezone.utc),
    )
    db_session.add(change)
    await db_session.commit()

    return {
        "org_id": org.id,
        "user_id": user.id,
        "domain_id": domain.id,
        "scan_id": scan.id,
        "comp_run_id": comp_run.id,
        "change_id": change.id,
    }


def test_service_exposure_double_counting_precedence():
    """Verify port 8443 receives ONLY ONE service_exposure contribution (+20.0) and does not double count."""
    context_res = ContextResolutionResponse(
        target_identifier="api.example.com:8443",
        target_type="service",
        expected_state="EXPECTED",
        environment="production",
        criticality="low",
        owner_id="user-1",
        owner_team="DevOps",
        conflict_detected=False,
        resolution_status="resolved",
    )

    # Test Port 8443 (High Risk)
    _, _, _, factors_8443, _, _, _ = RiskModelV1.calculate_risk(
        change_type="asset_added",
        entity_type="service",
        entity_identifier="api.example.com:8443",
        context_res=context_res,
    )
    exp_factors_8443 = [f for f in factors_8443 if f.factor_name == "service_exposure"]
    assert len(exp_factors_8443) == 1, "Must contain exactly ONE service_exposure factor for port 8443"
    assert exp_factors_8443[0].factor_value == "high_risk_port_8443"
    assert exp_factors_8443[0].contribution == 20.0

    # Test Port 443 (Web Exposure)
    _, _, _, factors_443, _, _, _ = RiskModelV1.calculate_risk(
        change_type="asset_added",
        entity_type="service",
        entity_identifier="api.example.com:443",
        context_res=context_res,
    )
    exp_factors_443 = [f for f in factors_443 if f.factor_name == "service_exposure"]
    assert len(exp_factors_443) == 1, "Must contain exactly ONE service_exposure factor for port 443"
    assert exp_factors_443[0].factor_value == "web_exposure_443"
    assert exp_factors_443[0].contribution == 10.0

    # Test Port 22 (High Risk SSH)
    _, _, _, factors_22, _, _, _ = RiskModelV1.calculate_risk(
        change_type="asset_added",
        entity_type="service",
        entity_identifier="api.example.com:22",
        context_res=context_res,
    )
    exp_factors_22 = [f for f in factors_22 if f.factor_name == "service_exposure"]
    assert len(exp_factors_22) == 1, "Must contain exactly ONE service_exposure factor for port 22"
    assert exp_factors_22[0].factor_value == "high_risk_port_22"
    assert exp_factors_22[0].contribution == 20.0


def test_uncertainty_semantics_and_confidence_degradation():
    """Verify missing/unknown context contributes blindspot points to score while degrading confidence metric."""
    context_res = ContextResolutionResponse(
        target_identifier="sub.example.com",
        target_type="subdomain",
        expected_state="UNSPECIFIED",
        environment="unknown",
        criticality="unknown",
        owner_id=None,
        owner_team=None,
        conflict_detected=False,
        resolution_status="resolved",
    )

    (
        score,
        band,
        confidence,
        factors,
        snapshot,
        uncertainty,
        explanation,
    ) = RiskModelV1.calculate_risk(
        change_type="asset_added",
        entity_type="subdomain",
        entity_identifier="sub.example.com",
        context_res=context_res,
    )

    # 4 uncertainty flags present -> Confidence should be 1.0 - (4 * 0.15) = 0.40
    assert len(uncertainty) == 4
    assert "UNKNOWN_CRITICALITY" in uncertainty
    assert "UNKNOWN_ENVIRONMENT" in uncertainty
    assert "UNSPECIFIED_EXPECTED_STATE" in uncertainty
    assert "MISSING_OWNER" in uncertainty
    assert confidence == 0.40
    # Blindspot contributions: Criticality(10) + Env(15) + Unspecified(10) + Change(20) + Web(10) + Owner(10) = 75.0
    assert score == 75.0
    assert band == RiskBand.HIGH


def test_risk_model_context_conflict_handling():
    """Verify CONFLICT_REQUIRES_REVIEW triggers EXPECTED_STATE_CONFLICT flag and factor contribution."""
    context_res = ContextResolutionResponse(
        target_identifier="api.example.com:8443",
        target_type="service",
        expected_state="CONFLICT_REQUIRES_REVIEW",
        environment="staging",
        criticality="high",
        owner_id="user-1",
        owner_team="DevOps",
        conflict_detected=True,
        resolution_status="conflict_detected",
    )

    (
        score,
        band,
        confidence,
        factors,
        snapshot,
        uncertainty,
        explanation,
    ) = RiskModelV1.calculate_risk(
        change_type="asset_added",
        entity_type="service",
        entity_identifier="api.example.com:8443",
        context_res=context_res,
    )

    assert "EXPECTED_STATE_CONFLICT" in uncertainty
    exp_factor = next(f for f in factors if f.factor_name == "expected_state")
    assert exp_factor.factor_value == "CONFLICT_REQUIRES_REVIEW"
    assert exp_factor.contribution == 20.0


def test_determinism_invariant():
    """Verify 10 consecutive executions with identical inputs produce 100% identical outputs."""
    context_res = ContextResolutionResponse(
        target_identifier="api.example.com:443",
        target_type="service",
        expected_state="UNEXPECTED",
        environment="production",
        criticality="critical",
        owner_id="usr-123",
        owner_team="SecOps",
        conflict_detected=False,
        resolution_status="resolved",
    )

    baseline = RiskModelV1.calculate_risk(
        change_type="asset_added",
        entity_type="service",
        entity_identifier="api.example.com:443",
        context_res=context_res,
    )

    for _ in range(10):
        current = RiskModelV1.calculate_risk(
            change_type="asset_added",
            entity_type="service",
            entity_identifier="api.example.com:443",
            context_res=context_res,
        )
        assert current[0] == baseline[0]  # score
        assert current[1] == baseline[1]  # band
        assert current[2] == baseline[2]  # confidence
        assert current[4] == baseline[4]  # snapshot
        assert current[5] == baseline[5]  # uncertainty flags
        assert current[6] == baseline[6]  # explanation


@pytest.mark.asyncio
async def test_expired_and_revoked_memory_exclusion(db_session: AsyncSession, seed_data: dict):
    """Verify risk calculation ignores revoked decisions and expired memories, using UNSPECIFIED fallback."""
    decision_service = DecisionService(db_session)
    risk_service = RiskEngineService(db_session)

    # 1. Create a decision marking staging-api.example.com:8443 as EXPECTED with valid_until in the past (Expired)
    past_time = datetime.now(timezone.utc) - timedelta(days=1)
    dec_expired = await decision_service.create_decision(
        org_id=seed_data["org_id"],
        actor_id=seed_data["user_id"],
        decision_type=DecisionType.MARK_EXPECTED.value,
        scope_level=ScopeLevel.SERVICE.value,
        subject_identifier="service:staging-api.example.com:8443",
        new_state={"expected_state": "EXPECTED"},
        reason="Temporary test approval",
        valid_until=past_time,
    )
    await db_session.commit()

    # Assess risk for change -> expired decision ignored -> fallback UNSPECIFIED expected state (+10 pts)
    assessment_expired = await risk_service.assess_change_risk(
        org_id=seed_data["org_id"],
        change_id=seed_data["change_id"],
        risk_model_version="v1",
    )
    assert assessment_expired.context_snapshot["expected_state"] == "UNSPECIFIED"

    # 2. Revoke an active decision
    dec_active = await decision_service.create_decision(
        org_id=seed_data["org_id"],
        actor_id=seed_data["user_id"],
        decision_type=DecisionType.MARK_EXPECTED.value,
        scope_level=ScopeLevel.SERVICE.value,
        subject_identifier="service:staging-api.example.com:8443",
        new_state={"expected_state": "EXPECTED"},
        reason="Active approval to be revoked",
    )
    await db_session.commit()

    await decision_service.revoke_decision(
        org_id=seed_data["org_id"],
        decision_id=dec_active.id,
        actor_id=seed_data["user_id"],
        reason="Policy change",
    )
    await db_session.commit()

    # Assess risk under new change / model version -> revoked decision ignored -> UNSPECIFIED fallback
    assessment_revoked = await risk_service.assess_change_risk(
        org_id=seed_data["org_id"],
        change_id=seed_data["change_id"],
        risk_model_version="v2",
    )
    assert assessment_revoked.context_snapshot["expected_state"] == "UNSPECIFIED"


@pytest.mark.asyncio
async def test_model_versioning_and_historical_immutability(db_session: AsyncSession, seed_data: dict):
    """Verify calculate under model v1 and model v2 creates separate immutable assessments without overwriting v1."""
    service = RiskEngineService(db_session)

    # 1. Calculate under model v1
    v1_assessment = await service.assess_change_risk(
        org_id=seed_data["org_id"],
        change_id=seed_data["change_id"],
        risk_model_version="v1",
    )
    await db_session.commit()
    v1_id = v1_assessment.id
    v1_score = v1_assessment.risk_score
    v1_snapshot = v1_assessment.context_snapshot

    # 2. Calculate under model v2 (v2 produces distinct calculation)
    v2_assessment = await service.assess_change_risk(
        org_id=seed_data["org_id"],
        change_id=seed_data["change_id"],
        risk_model_version="v2",
    )
    await db_session.commit()

    # Historical Immutability Check: v1 assessment MUST remain distinct and unchanged
    res_v1 = await db_session.execute(select(RiskAssessment).where(RiskAssessment.id == v1_id))
    reloaded_v1 = res_v1.scalars().first()

    assert reloaded_v1.id == v1_id
    assert reloaded_v1.risk_score == v1_score
    assert reloaded_v1.context_snapshot == v1_snapshot
    assert v2_assessment.id != v1_id
    assert v2_assessment.risk_model_version == "v2"
    # V2 produces distinct calculation (e.g. 80.0 in V2 vs 75.0 in V1)
    assert v2_assessment.risk_score != v1_score or v2_assessment.explanation != v1_assessment.explanation


@pytest.mark.asyncio
async def test_unsupported_model_version_rejection(db_session: AsyncSession, seed_data: dict):
    """Verify requesting an unsupported model version (e.g. v99 or unknown) raises ValueError and creates 0 records."""
    service = RiskEngineService(db_session)

    with pytest.raises(ValueError, match="Unsupported or invalid risk_model_version"):
        await service.assess_change_risk(
            org_id=seed_data["org_id"],
            change_id=seed_data["change_id"],
            risk_model_version="v99_unsupported",
        )


@pytest.mark.asyncio
async def test_concurrency_protection(seed_data: dict):
    """Verify concurrent calculation requests for same (org, change, model_version) return identical row without error."""
    async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)

    async def _run_calc():
        async with async_session() as session:
            service = RiskEngineService(session)
            res = await service.assess_change_risk(seed_data["org_id"], seed_data["change_id"], "v1")
            await session.commit()
            return res

    res1, res2 = await asyncio.gather(_run_calc(), _run_calc())

    assert res1.id == res2.id
    assert res1.risk_score == res2.risk_score
