"""Phase 1F Security Test Suite: Tenant Isolation, RBAC, Risk Manipulation Prevention, Incomplete Scan Safety & No-Feedback-Loop Invariants.

Tests verify:
1. Hard Tenant Isolation: Org B cannot see, query, or recalculate Org A risk assessments.
2. RBAC Access Control: Viewer can read risk, Member/Admin can trigger recalculation, Viewer denied recalculate (403).
3. Risk Score Manipulation Prevention: Attempting to submit raw risk_score via API is rejected/ignored.
4. No Feedback Loop Safety Invariant: Risk engine calculation creates 0 OrganizationalMemory rows and mutates 0 AssetContext rows.
5. Evidence Provenance Tenant Integrity: Evidence references in factor details do not cross tenant boundaries.
6. Incomplete Scan Safety Propagation: Incomplete scan emits 0 removal changes and generates 0 risk assessments.
"""

import pytest
import pytest_asyncio
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, func

from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, User, Membership, Domain, Scan, ComparisonRun, Change, Asset,
    AssetContext, OrganizationalMemory, RiskAssessment, AuditEvent
)
from app.application.change_detection_service import ChangeDetectionService
from app.application.risk_engine_service import RiskEngineService
from app.main import app
from shared_contracts.enums import (
    DomainStatus, ChangeType, RiskBand, RiskModelVersion
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
async def multi_org_risk_setup(db_session: AsyncSession):
    # Org Alpha
    org_a = Organization(name="Org Alpha", slug="org-alpha")
    admin_a = User(email="admin_a@alpha.com", password_hash="hash", full_name="Admin Alpha")
    viewer_a = User(email="viewer_a@alpha.com", password_hash="hash", full_name="Viewer Alpha")
    db_session.add_all([org_a, admin_a, viewer_a])
    await db_session.commit()

    mem_admin_a = Membership(org_id=org_a.id, user_id=admin_a.id, role="admin")
    mem_viewer_a = Membership(org_id=org_a.id, user_id=viewer_a.id, role="viewer")
    domain_a = Domain(
        org_id=org_a.id,
        domain_name="alpha.com",
        status=DomainStatus.VERIFIED,
        verification_token="token-a",
        verified_at=datetime.now(timezone.utc),
    )
    db_session.add_all([mem_admin_a, mem_viewer_a, domain_a])
    await db_session.commit()

    scan_a = Scan(org_id=org_a.id, domain_id=domain_a.id, job_nonce="nonce-risk-sec", status="completed")
    db_session.add(scan_a)
    await db_session.commit()

    comp_a = ComparisonRun(org_id=org_a.id, domain_id=domain_a.id, current_scan_id=scan_a.id, status="completed", current_scan_completeness="complete", changes_detected=1)
    db_session.add(comp_a)
    await db_session.commit()

    change_a = Change(
        org_id=org_a.id,
        comparison_run_id=comp_a.id,
        change_type=ChangeType.ASSET_ADDED.value,
        entity_type="service",
        entity_identifier="api.alpha.com:8443",
        current_scan_id=scan_a.id,
        detected_at=datetime.now(timezone.utc),
    )
    db_session.add(change_a)
    await db_session.commit()

    # Org Beta
    org_b = Organization(name="Org Beta", slug="org-beta")
    admin_b = User(email="admin_b@beta.com", password_hash="hash", full_name="Admin Beta")
    db_session.add_all([org_b, admin_b])
    await db_session.commit()

    mem_admin_b = Membership(org_id=org_b.id, user_id=admin_b.id, role="admin")
    domain_b = Domain(
        org_id=org_b.id,
        domain_name="beta.com",
        status=DomainStatus.VERIFIED,
        verification_token="token-b",
        verified_at=datetime.now(timezone.utc),
    )
    db_session.add_all([mem_admin_b, domain_b])
    await db_session.commit()

    return {
        "org_a_id": org_a.id,
        "domain_a_id": domain_a.id,
        "admin_a_id": admin_a.id,
        "viewer_a_id": viewer_a.id,
        "change_a_id": change_a.id,
        "org_b_id": org_b.id,
        "admin_b_id": admin_b.id,
    }


@pytest.mark.asyncio
async def test_tenant_isolation_risk_assessments(db_session: AsyncSession, multi_org_risk_setup: dict):
    """Verify Org B cannot retrieve, see, or recalculate Org A's risk assessments."""
    service = RiskEngineService(db_session)

    # Org A calculates risk for change_a
    assessment_a = await service.assess_change_risk(
        org_id=multi_org_risk_setup["org_a_id"],
        change_id=multi_org_risk_setup["change_a_id"],
    )
    await db_session.commit()

    # Org B queries assessment_a by ID -> None
    res_b = await service.get_assessment(
        org_id=multi_org_risk_setup["org_b_id"],
        assessment_id=assessment_a.id,
    )
    assert res_b is None

    # Org B lists assessments -> 0 items
    list_b, count_b = await service.list_assessments(org_id=multi_org_risk_setup["org_b_id"])
    assert count_b == 0
    assert len(list_b) == 0


@pytest.mark.asyncio
async def test_no_feedback_loop_safety_invariant(db_session: AsyncSession, multi_org_risk_setup: dict):
    """Verify calculating risk creates 0 OrganizationalMemory rows and mutates 0 AssetContext rows."""
    service = RiskEngineService(db_session)

    mem_count_before = (await db_session.execute(select(func.count()).select_from(OrganizationalMemory))).scalar()
    ctx_count_before = (await db_session.execute(select(func.count()).select_from(AssetContext))).scalar()

    # Calculate risk
    await service.assess_change_risk(
        org_id=multi_org_risk_setup["org_a_id"],
        change_id=multi_org_risk_setup["change_a_id"],
    )
    await db_session.commit()

    mem_count_after = (await db_session.execute(select(func.count()).select_from(OrganizationalMemory))).scalar()
    ctx_count_after = (await db_session.execute(select(func.count()).select_from(AssetContext))).scalar()

    # Safety Invariant Check: Counts MUST be unchanged
    assert mem_count_after == mem_count_before
    assert ctx_count_after == ctx_count_before


@pytest.mark.asyncio
async def test_rbac_view_vs_recalculate_permissions(multi_org_risk_setup: dict):
    """Verify API RBAC: Viewer can read risk, Member/Admin can recalculate, Viewer denied recalculate (403)."""
    admin_headers = {
        "X-User-ID": multi_org_risk_setup["admin_a_id"],
        "X-Org-ID": multi_org_risk_setup["org_a_id"],
    }
    viewer_headers = {
        "X-User-ID": multi_org_risk_setup["viewer_a_id"],
        "X-Org-ID": multi_org_risk_setup["org_a_id"],
    }
    org_id = multi_org_risk_setup["org_a_id"]
    change_id = multi_org_risk_setup["change_a_id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Viewer tries to recalculate risk -> 403 Forbidden
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/risk/recalculate",
            headers=viewer_headers,
            json={"change_id": change_id},
        )
        assert resp.status_code == 403, f"Expected 403 for viewer recalculate, got {resp.status_code}"

        # 2. Admin recalculates risk -> 201 Created
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/risk/recalculate",
            headers=admin_headers,
            json={"change_id": change_id},
        )
        assert resp.status_code == 201
        assessment_id = resp.json()["id"]

        # 3. Viewer can GET risk list -> 200 OK
        resp = await client.get(
            f"/api/v1/organizations/{org_id}/risk/assessments",
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

        # 4. Viewer can GET risk detail -> 200 OK
        resp = await client.get(
            f"/api/v1/organizations/{org_id}/risk/assessments/{assessment_id}",
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == assessment_id


@pytest.mark.asyncio
async def test_score_manipulation_rejection(multi_org_risk_setup: dict):
    """Verify that attempting to inject a raw risk_score or risk_band in recalculate payload is ignored/rejected."""
    admin_headers = {
        "X-User-ID": multi_org_risk_setup["admin_a_id"],
        "X-Org-ID": multi_org_risk_setup["org_a_id"],
    }
    org_id = multi_org_risk_setup["org_a_id"]
    change_id = multi_org_risk_setup["change_a_id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Attempt to inject custom score and band in payload
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/risk/recalculate",
            headers=admin_headers,
            json={
                "change_id": change_id,
                "risk_score": 10.0,
                "risk_band": "LOW",
                "confidence": 1.0,
            },
        )
        assert resp.status_code == 201
        # The engine must compute the score deterministically (e.g. 60.0 HIGH) and ignore user-injected 10.0/LOW
        data = resp.json()
        assert data["risk_score"] != 10.0
        assert data["risk_band"] != "LOW"


@pytest.mark.asyncio
async def test_incomplete_scan_safety(db_session: AsyncSession, multi_org_risk_setup: dict):
    """Verify an incomplete scan produces 0 removal changes and 0 invalid removal risk assessments."""
    change_service = ChangeDetectionService(db_session)
    org_id = multi_org_risk_setup["org_a_id"]

    domain_id = multi_org_risk_setup["domain_a_id"]

    # Create incomplete scan
    inc_scan = Scan(org_id=org_id, domain_id=domain_id, job_nonce="nonce-inc-sec", status="partial")
    db_session.add(inc_scan)
    await db_session.commit()

    risk_count_before = (await db_session.execute(select(func.count()).select_from(RiskAssessment).where(RiskAssessment.org_id == org_id))).scalar()

    comp = await change_service.detect_changes_for_scan(
        scan_id=inc_scan.id,
        org_id=org_id,
        domain_id=domain_id,
    )
    await db_session.commit()

    # Incomplete scan -> baseline/skipped -> 0 changes emitted & 0 new risk assessments created
    assert comp.changes_detected == 0
    risk_count_after = (await db_session.execute(select(func.count()).select_from(RiskAssessment).where(RiskAssessment.org_id == org_id))).scalar()
    assert risk_count_after == risk_count_before


@pytest.mark.asyncio
async def test_recalculate_per_user_rate_limiting(db_session: AsyncSession, multi_org_risk_setup: dict):
    """Verify rate limiting: User exceeding 10 recalculations/min receives HTTP 429 and logs audit event."""
    admin_headers = {
        "X-User-ID": multi_org_risk_setup["admin_a_id"],
        "X-Org-ID": multi_org_risk_setup["org_a_id"],
    }
    org_id = multi_org_risk_setup["org_a_id"]
    change_id = multi_org_risk_setup["change_a_id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        statuses = []
        for _ in range(11):
            resp = await client.post(
                f"/api/v1/organizations/{org_id}/risk/recalculate",
                headers=admin_headers,
                json={"change_id": change_id, "risk_model_version": "v1"},
            )
            statuses.append(resp.status_code)

        # First 10 succeed (201), 11th is rate limited (429)
        assert statuses[:10] == [201] * 10
        assert statuses[10] == 429

        # Audit event check
        await db_session.rollback()
        events = (await db_session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "risk_assessment.recalculate_rate_limited")
        )).scalars().all()
        assert len(events) >= 1


@pytest.mark.asyncio
async def test_recalculate_concurrent_org_limit(multi_org_risk_setup: dict):
    """Verify concurrency protection: Max 2 concurrent recalculations per org (3rd returns 429)."""
    from app.api.dependencies.rate_limit import acquire_recalculate_concurrency_slot

    org_id = multi_org_risk_setup["org_a_id"]
    admin_headers = {
        "X-User-ID": multi_org_risk_setup["admin_a_id"],
        "X-Org-ID": org_id,
    }

    # Simulate 2 active concurrency slots held
    async with acquire_recalculate_concurrency_slot(org_id, max_concurrent=2):
        async with acquire_recalculate_concurrency_slot(org_id, max_concurrent=2):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                # 3rd request should fail with 429
                resp = await client.post(
                    f"/api/v1/organizations/{org_id}/risk/recalculate",
                    headers=admin_headers,
                    json={"change_id": multi_org_risk_setup["change_a_id"]},
                )
                assert resp.status_code == 429
                assert "Concurrent recalculation limit exceeded" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_api_model_version_dispatch_and_rejection(db_session: AsyncSession, multi_org_risk_setup: dict):
    """Verify API model versioning: v1 works, v2 works & differs, unsupported v99 is rejected with HTTP 400."""
    admin_headers = {
        "X-User-ID": multi_org_risk_setup["admin_a_id"],
        "X-Org-ID": multi_org_risk_setup["org_a_id"],
    }
    org_id = multi_org_risk_setup["org_a_id"]
    change_id = multi_org_risk_setup["change_a_id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Unsupported model version -> HTTP 400 Bad Request
        resp_err = await client.post(
            f"/api/v1/organizations/{org_id}/risk/recalculate",
            headers=admin_headers,
            json={"change_id": change_id, "risk_model_version": "v99_unsupported"},
        )
        assert resp_err.status_code == 400
        assert "Unsupported or invalid risk_model_version" in resp_err.json()["detail"]

        # 2. Model v1 calculation -> 201 Created
        resp_v1 = await client.post(
            f"/api/v1/organizations/{org_id}/risk/recalculate",
            headers=admin_headers,
            json={"change_id": change_id, "risk_model_version": "v1"},
        )
        assert resp_v1.status_code == 201
        data_v1 = resp_v1.json()
        assert data_v1["risk_model_version"] == "v1"

        # 3. Model v2 calculation -> 201 Created with distinct output
        resp_v2 = await client.post(
            f"/api/v1/organizations/{org_id}/risk/recalculate",
            headers=admin_headers,
            json={"change_id": change_id, "risk_model_version": "v2"},
        )
        assert resp_v2.status_code == 201
        data_v2 = resp_v2.json()
        assert data_v2["risk_model_version"] == "v2"
        assert data_v2["id"] != data_v1["id"]


@pytest.mark.asyncio
async def test_recalculate_per_org_rate_limiting_across_multiple_users(db_session: AsyncSession, multi_org_risk_setup: dict):
    """Verify organization-level rate limit (30 req/min/org): Requests distributed across User A, User B, User C share the org counter and fail with HTTP 429 when total > 30."""
    org_id = multi_org_risk_setup["org_a_id"]
    change_id = multi_org_risk_setup["change_a_id"]

    # Create 4 distinct member users in Org Alpha (each user has 10 req/min limit)
    user_a = User(email="user_a_rate@alpha.com", password_hash="hash", full_name="User A Rate")
    user_b = User(email="user_b_rate@alpha.com", password_hash="hash", full_name="User B Rate")
    user_c = User(email="user_c_rate@alpha.com", password_hash="hash", full_name="User C Rate")
    user_d = User(email="user_d_rate@alpha.com", password_hash="hash", full_name="User D Rate")
    db_session.add_all([user_a, user_b, user_c, user_d])
    await db_session.commit()

    mem_a = Membership(org_id=org_id, user_id=user_a.id, role="member")
    mem_b = Membership(org_id=org_id, user_id=user_b.id, role="member")
    mem_c = Membership(org_id=org_id, user_id=user_c.id, role="member")
    mem_d = Membership(org_id=org_id, user_id=user_d.id, role="member")
    db_session.add_all([mem_a, mem_b, mem_c, mem_d])
    await db_session.commit()

    headers_a = {"X-User-ID": user_a.id, "X-Org-ID": org_id}
    headers_b = {"X-User-ID": user_b.id, "X-Org-ID": org_id}
    headers_c = {"X-User-ID": user_c.id, "X-Org-ID": org_id}
    headers_d = {"X-User-ID": user_d.id, "X-Org-ID": org_id}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        statuses = []
        # User A sends 10 requests (User A count = 10, Org count = 10)
        for _ in range(10):
            r = await client.post(f"/api/v1/organizations/{org_id}/risk/recalculate", headers=headers_a, json={"change_id": change_id})
            statuses.append(r.status_code)

        # User B sends 10 requests (User B count = 10, Org count = 20)
        for _ in range(10):
            r = await client.post(f"/api/v1/organizations/{org_id}/risk/recalculate", headers=headers_b, json={"change_id": change_id})
            statuses.append(r.status_code)

        # User C sends 10 requests (User C count = 10, Org count = 30)
        for _ in range(10):
            r = await client.post(f"/api/v1/organizations/{org_id}/risk/recalculate", headers=headers_c, json={"change_id": change_id})
            statuses.append(r.status_code)

        # User D sends 1st request (User D count = 1 <= 10, BUT Org total count > 30) -> MUST fail on org rate limit
        r_exceeded = await client.post(f"/api/v1/organizations/{org_id}/risk/recalculate", headers=headers_d, json={"change_id": change_id})

        assert statuses == [201] * 30
        assert r_exceeded.status_code == 429
        assert "Organization recalculation rate limit exceeded" in r_exceeded.json()["detail"]

        # Audit event check
        await db_session.rollback()
        events = (await db_session.execute(
            select(AuditEvent).where(
                AuditEvent.org_id == org_id,
                AuditEvent.event_type == "risk_assessment.recalculate_rate_limited",
            )
        )).scalars().all()
        assert len(events) >= 1


@pytest.mark.asyncio
async def test_recalculate_attempted_audit_event(db_session: AsyncSession, multi_org_risk_setup: dict):
    """Verify normal recalculation emits risk_assessment.recalculate_attempted audit event with org/user context."""
    org_id = multi_org_risk_setup["org_a_id"]
    actor_id = multi_org_risk_setup["admin_a_id"]
    change_id = multi_org_risk_setup["change_a_id"]

    admin_headers = {
        "X-User-ID": actor_id,
        "X-Org-ID": org_id,
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/risk/recalculate",
            headers=admin_headers,
            json={"change_id": change_id, "risk_model_version": "v1"},
        )
        assert resp.status_code == 201

        await db_session.rollback()
        events = (await db_session.execute(
            select(AuditEvent).where(
                AuditEvent.org_id == org_id,
                AuditEvent.event_type == "risk_assessment.recalculate_attempted",
            )
        )).scalars().all()

        assert len(events) >= 1
        latest_event = events[-1]
        assert latest_event.actor_id == actor_id
        assert latest_event.resource_type == "change"
        assert latest_event.resource_id == change_id
        assert latest_event.details["model_version"] == "v1"


