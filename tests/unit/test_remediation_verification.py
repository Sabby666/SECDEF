import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, func

from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, User, Domain, Scan, ComparisonRun, Change, RiskAssessment,
    Finding, VerificationResult, Notification, NotificationDestination, NotificationPolicy,
    NotificationDelivery, Observation
)
from app.application.finding_service import FindingService
from app.application.verification_service import VerificationService
from app.application.notification_service import NotificationService
from app.infrastructure.notifications.webhook_delivery import WebhookDeliveryService
from shared_contracts.enums import (
    FindingLifecycleStatus, VerificationStatus, ScanCompleteness, RiskBand, ChangeType, NotificationChannel
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
async def seed_env(db_session: AsyncSession):
    org = Organization(name="Verification Test Org", slug="ver-test-org")
    user = User(email="ver_user@test.com", password_hash="hash", full_name="Ver User")
    db_session.add_all([org, user])
    await db_session.commit()

    domain = Domain(org_id=org.id, domain_name="example.com", status="verified", verification_token="tok")
    db_session.add(domain)
    await db_session.commit()

    scan1 = Scan(
        org_id=org.id,
        domain_id=domain.id,
        status="completed",
        job_nonce="nonce-1",
        created_at=datetime.now(timezone.utc) - timedelta(hours=2)
    )
    db_session.add(scan1)
    await db_session.commit()

    comp1 = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=scan1.id,
        status="completed",
        current_scan_completeness=ScanCompleteness.COMPLETE.value,
        changes_detected=1,
        created_at=datetime.now(timezone.utc) - timedelta(hours=2)
    )
    db_session.add(comp1)
    await db_session.commit()

    change = Change(
        org_id=org.id,
        comparison_run_id=comp1.id,
        change_type=ChangeType.ASSET_ADDED.value,
        entity_type="subdomain",
        entity_identifier="api.example.com",
        current_scan_id=scan1.id,
        detected_at=datetime.now(timezone.utc) - timedelta(hours=2)
    )
    db_session.add(change)
    await db_session.commit()

    risk = RiskAssessment(
        org_id=org.id,
        change_id=change.id,
        risk_model_version="v1",
        risk_score=85.0,
        risk_band=RiskBand.HIGH.value,
        confidence=1.0,
        factor_breakdown=[],
        context_snapshot={},
        uncertainty_flags=[],
        explanation="High risk new exposed subdomain"
    )
    db_session.add(risk)
    await db_session.commit()

    return {
        "org": org,
        "user": user,
        "domain": domain,
        "scan1": scan1,
        "comp1": comp1,
        "change": change,
        "risk": risk
    }


# ============================================================
# Core Verification Invariant Tests (1 through 12)
# ============================================================

@pytest.mark.asyncio
async def test_1_acknowledged_does_not_resolve_finding(db_session: AsyncSession, seed_env: dict):
    """1. ACKNOWLEDGED status does NOT mark finding RESOLVED."""
    org = seed_env["org"]
    user = seed_env["user"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    ack_finding = await finding_service.acknowledge_finding(
        org_id=org.id,
        finding_id=finding.id,
        actor_id=user.id,
        reason="Acknowledged by security analyst"
    )

    assert ack_finding.status == FindingLifecycleStatus.ACKNOWLEDGED.value
    assert ack_finding.resolved_at is None


@pytest.mark.asyncio
async def test_2_in_progress_does_not_resolve_finding(db_session: AsyncSession, seed_env: dict):
    """2. IN_PROGRESS status does NOT mark finding RESOLVED."""
    org = seed_env["org"]
    user = seed_env["user"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    in_prog_finding = await finding_service.mark_in_progress(
        org_id=org.id,
        finding_id=finding.id,
        actor_id=user.id,
        reason="Remediation active"
    )

    assert in_prog_finding.status == FindingLifecycleStatus.IN_PROGRESS.value
    assert in_prog_finding.resolved_at is None


@pytest.mark.asyncio
async def test_3_risk_score_decrease_does_not_resolve_finding(db_session: AsyncSession, seed_env: dict):
    """3. Risk score decrease does NOT mark finding RESOLVED."""
    org = seed_env["org"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    risk.risk_score = 5.0
    risk.risk_band = RiskBand.INFO.value
    await db_session.commit()

    refetched = await finding_service.get_finding(org.id, finding.id)
    assert refetched.status == FindingLifecycleStatus.OPEN.value
    assert refetched.resolved_at is None


@pytest.mark.asyncio
async def test_4_time_elapsed_does_not_resolve_finding(db_session: AsyncSession, seed_env: dict):
    """4. Time elapsed without fresh complete scan evidence does NOT resolve finding."""
    org = seed_env["org"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    finding.created_at = datetime.now(timezone.utc) - timedelta(days=90)
    finding.updated_at = datetime.now(timezone.utc) - timedelta(days=90)
    await db_session.commit()

    refetched = await finding_service.get_finding(org.id, finding.id)
    assert refetched.status == FindingLifecycleStatus.OPEN.value
    assert refetched.resolved_at is None


@pytest.mark.asyncio
async def test_5_incomplete_scan_cannot_resolve_finding(db_session: AsyncSession, seed_env: dict):
    """5. Incomplete / partial scan completeness CANNOT produce RESOLVED verdict."""
    org = seed_env["org"]
    domain = seed_env["domain"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    scan_part = Scan(org_id=org.id, domain_id=domain.id, status="partial", job_nonce="nonce-partial")
    db_session.add(scan_part)
    await db_session.commit()

    comp_part = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=scan_part.id,
        status="completed",
        current_scan_completeness=ScanCompleteness.PARTIAL.value,
        changes_detected=0
    )
    db_session.add(comp_part)
    await db_session.commit()

    ver_service = VerificationService(db_session)
    ver_res = await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=comp_part.id)

    assert ver_res.status == VerificationStatus.INCOMPLETE.value
    assert finding.status == FindingLifecycleStatus.OPEN.value
    assert finding.resolved_at is None


@pytest.mark.asyncio
async def test_6_failed_scan_cannot_resolve_finding(db_session: AsyncSession, seed_env: dict):
    """6. Failed scan status CANNOT produce RESOLVED verdict."""
    org = seed_env["org"]
    domain = seed_env["domain"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    scan_fail = Scan(org_id=org.id, domain_id=domain.id, status="failed", job_nonce="nonce-failed")
    db_session.add(scan_fail)
    await db_session.commit()

    comp_fail = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=scan_fail.id,
        status="failed",
        current_scan_completeness="failed",
        changes_detected=0
    )
    db_session.add(comp_fail)
    await db_session.commit()

    ver_service = VerificationService(db_session)
    ver_res = await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=comp_fail.id)

    assert ver_res.status == VerificationStatus.INCOMPLETE.value
    assert finding.status == FindingLifecycleStatus.OPEN.value
    assert finding.resolved_at is None


@pytest.mark.asyncio
async def test_7_unknown_partial_scan_cannot_resolve_finding(db_session: AsyncSession, seed_env: dict):
    """7. Unknown / unverified scan completeness CANNOT produce RESOLVED verdict."""
    org = seed_env["org"]
    domain = seed_env["domain"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    scan_unk = Scan(org_id=org.id, domain_id=domain.id, status="completed", job_nonce="nonce-unk")
    db_session.add(scan_unk)
    await db_session.commit()

    comp_unk = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=scan_unk.id,
        status="completed",
        current_scan_completeness="unknown",
        changes_detected=0
    )
    db_session.add(comp_unk)
    await db_session.commit()

    ver_service = VerificationService(db_session)
    ver_res = await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=comp_unk.id)

    assert ver_res.status == VerificationStatus.INCOMPLETE.value
    assert finding.status == FindingLifecycleStatus.OPEN.value


@pytest.mark.asyncio
async def test_8_stale_scan_created_before_finding_cannot_resolve(db_session: AsyncSession, seed_env: dict):
    """8. Stale scan created before finding detection timestamp CANNOT resolve finding."""
    org = seed_env["org"]
    domain = seed_env["domain"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    stale_scan = Scan(
        org_id=org.id,
        domain_id=domain.id,
        status="completed",
        job_nonce="nonce-stale",
        created_at=datetime.now(timezone.utc) - timedelta(hours=5)
    )
    db_session.add(stale_scan)
    await db_session.commit()

    stale_comp = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=stale_scan.id,
        status="completed",
        current_scan_completeness=ScanCompleteness.COMPLETE.value,
        changes_detected=0,
        created_at=datetime.now(timezone.utc) - timedelta(hours=5)
    )
    db_session.add(stale_comp)
    await db_session.commit()

    ver_service = VerificationService(db_session)
    ver_res = await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=stale_comp.id)

    assert ver_res.status == VerificationStatus.UNKNOWN.value
    assert finding.status == FindingLifecycleStatus.OPEN.value


@pytest.mark.asyncio
async def test_9_fresh_complete_scan_proving_absence_resolves(db_session: AsyncSession, seed_env: dict):
    """9. Fresh COMPLETE scan proving condition absence resolves the finding."""
    org = seed_env["org"]
    domain = seed_env["domain"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    scan2 = Scan(org_id=org.id, domain_id=domain.id, status="completed", job_nonce="nonce-fresh-complete")
    db_session.add(scan2)
    await db_session.commit()

    comp2 = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=scan2.id,
        status="completed",
        current_scan_completeness=ScanCompleteness.COMPLETE.value,
        changes_detected=0
    )
    db_session.add(comp2)
    await db_session.commit()

    ver_service = VerificationService(db_session)
    ver_res = await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=comp2.id)

    assert ver_res.status == VerificationStatus.RESOLVED.value
    assert finding.status == FindingLifecycleStatus.RESOLVED.value
    assert finding.resolved_at is not None


@pytest.mark.asyncio
async def test_10_resolved_condition_returning_reopens(db_session: AsyncSession, seed_env: dict):
    """10. Previously RESOLVED condition returning in a later COMPLETE scan becomes REOPENED."""
    org = seed_env["org"]
    domain = seed_env["domain"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)
    finding.status = FindingLifecycleStatus.RESOLVED.value
    finding.resolved_at = datetime.now(timezone.utc)
    await db_session.commit()

    scan3 = Scan(org_id=org.id, domain_id=domain.id, status="completed", job_nonce="nonce-reopen")
    db_session.add(scan3)
    await db_session.commit()

    obs = Observation(
        org_id=org.id,
        scan_id=scan3.id,
        observation_type="subdomain",
        target="api.example.com",
        raw_data={"host": "api.example.com"}
    )
    db_session.add(obs)
    await db_session.commit()

    comp3 = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=scan3.id,
        status="completed",
        current_scan_completeness=ScanCompleteness.COMPLETE.value,
        changes_detected=1
    )
    db_session.add(comp3)
    await db_session.commit()

    ver_service = VerificationService(db_session)
    ver_res = await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=comp3.id)

    assert ver_res.status == VerificationStatus.STILL_PRESENT.value
    assert finding.status == FindingLifecycleStatus.REOPENED.value
    assert finding.reopened_at is not None


@pytest.mark.asyncio
async def test_11_duplicate_verification_is_idempotent(db_session: AsyncSession, seed_env: dict):
    """11. Duplicate verification with the same comparison_run/current_scan is idempotent."""
    org = seed_env["org"]
    domain = seed_env["domain"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    scan2 = Scan(org_id=org.id, domain_id=domain.id, status="completed", job_nonce="nonce-idemp")
    db_session.add(scan2)
    await db_session.commit()

    comp2 = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=scan2.id,
        status="completed",
        current_scan_completeness=ScanCompleteness.COMPLETE.value,
        changes_detected=0
    )
    db_session.add(comp2)
    await db_session.commit()

    ver_service = VerificationService(db_session)
    ver1 = await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=comp2.id)
    ver2 = await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=comp2.id)

    assert ver1.id == ver2.id
    count_stmt = select(func.count(VerificationResult.id)).where(VerificationResult.org_id == org.id)
    res_count = await db_session.execute(count_stmt)
    assert res_count.scalar() == 1


@pytest.mark.asyncio
async def test_12_out_of_order_scan_cannot_overwrite_newer_state(db_session: AsyncSession, seed_env: dict):
    """12. Out-of-order scans cannot overwrite newer verification state/timestamps."""
    org = seed_env["org"]
    domain = seed_env["domain"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org.id, change.id, risk.id)

    scan_now = Scan(org_id=org.id, domain_id=domain.id, status="completed", job_nonce="nonce-now")
    db_session.add(scan_now)
    await db_session.commit()

    comp_now = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=scan_now.id,
        status="completed",
        current_scan_completeness=ScanCompleteness.COMPLETE.value,
        changes_detected=0
    )
    db_session.add(comp_now)
    await db_session.commit()

    ver_service = VerificationService(db_session)
    await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=comp_now.id)
    assert finding.status == FindingLifecycleStatus.RESOLVED.value

    stale_scan = Scan(
        org_id=org.id,
        domain_id=domain.id,
        status="completed",
        job_nonce="nonce-out-of-order",
        created_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    db_session.add(stale_scan)
    await db_session.commit()

    stale_comp = ComparisonRun(
        org_id=org.id,
        domain_id=domain.id,
        current_scan_id=stale_scan.id,
        status="completed",
        current_scan_completeness=ScanCompleteness.COMPLETE.value,
        changes_detected=1,
        created_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    db_session.add(stale_comp)
    await db_session.commit()

    ver_stale = await ver_service.verify_finding(org.id, finding.id, target_comparison_run_id=stale_comp.id)
    assert ver_stale.status == VerificationStatus.UNKNOWN.value
    assert finding.status == FindingLifecycleStatus.RESOLVED.value


# ============================================================
# Retry Semantics Tests
# ============================================================

@pytest.mark.asyncio
async def test_bounded_delivery_retries_max_3_attempts(db_session: AsyncSession, seed_env: dict, monkeypatch):
    """Verify maximum 3 delivery attempts, no 4th attempt, persisted attempts, and final FAILED state."""
    org = seed_env["org"]
    change = seed_env["change"]
    risk = seed_env["risk"]

    monkeypatch.setattr(WebhookDeliveryService, "validate_url_and_resolve", lambda url: ("webhook.example.com", "93.184.216.34", 443))
    monkeypatch.setattr(WebhookDeliveryService, "deliver_webhook", lambda url, payload, signing_secret=None, headers=None: (False, 500, "Server Error"))

    notif_service = NotificationService(db_session)
    dest = await notif_service.create_destination(
        org_id=org.id,
        channel=NotificationChannel.WEBHOOK.value,
        name="Retry Webhook",
        config={"url": "https://webhook.example.com/endpoint"}
    )

    policy = await notif_service.create_policy(
        org_id=org.id,
        name="Retry Policy",
        min_risk_band=RiskBand.INFO.value,
        trigger_types=["high_risk_new_asset"],
        destination_ids=[dest.id]
    )

    notifs = await notif_service.evaluate_and_notify(
        org_id=org.id,
        trigger_type="high_risk_new_asset",
        source_id=change.id,
        risk_assessment_id=risk.id,
        change_id=change.id
    )

    assert len(notifs) == 1
    deliv_stmt = select(NotificationDelivery).where(
        NotificationDelivery.org_id == org.id,
        NotificationDelivery.notification_id == notifs[0].id
    ).order_by(NotificationDelivery.attempt_number.asc())
    res_deliv = await db_session.execute(deliv_stmt)
    deliveries = res_deliv.scalars().all()

    assert len(deliveries) == 3
    assert [d.attempt_number for d in deliveries] == [1, 2, 3]
    assert all(d.status == "failed" for d in deliveries)
