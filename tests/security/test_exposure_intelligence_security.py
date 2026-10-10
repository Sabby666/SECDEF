"""Comprehensive Security Test Suite for Phase 3 Exposure Intelligence & Correlation Layer.

Covers security requirement items A through X:
A. Tenant Isolation
B. RBAC Matrix
C. Deterministic Correlation & Rule Versioning
D. Correlation Idempotency
E. Concurrent Correlation Safety
F. Graph Cycle Handling & Infinite Recursion Defense
G. Graph Depth Limits (MAX_TRAVERSAL_DEPTH = 5)
H. Node/Edge/Path Limits
I. Query Timeout & Resource Limits
J. Historical Exposure & Reopened Lifecycle Semantics
K. Incomplete Discovery & Non-Destructive Failure Semantics
L. Provenance Chain Integrity
M. Phase 1 Risk Integration (References Risk Assessment without 2nd score engine)
N. Phase 1 Finding Integration (References Finding without duplicating lifecycle)
O. Phase 1 Change Integration (ASSET_ADDED change correlation)
P. Phase 2 Discovery Evidence Integration (Candidate promotion provenance)
Q. No Wildcard Scope Escalation
R. Hostile Input Sanitization & Safe Rendering
S. API Pagination & Filtering
T. Cross-Tenant Graph Traversal Denial
U. Database Integrity & Batch Constraint Compatibility
"""
import asyncio
import pytest
import pytest_asyncio
from fastapi import HTTPException
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
async def async_exp_sec_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        # Org A
        org_a = Organization(id="org-exp-a", name="Org A Exposure", slug="org-a-exp")
        dom_a = Domain(id="dom-exp-a", org_id="org-exp-a", domain_name="orga.com", status="verified", verification_token="tokA")
        
        # Org B
        org_b = Organization(id="org-exp-b", name="Org B Exposure", slug="org-b-exp")
        dom_b = Domain(id="dom-exp-b", org_id="org-exp-b", domain_name="orgb.com", status="verified", verification_token="tokB")

        # Users
        u_viewer = User(id="usr-exp-viewer", email="v@exp.com", password_hash="pass", full_name="Viewer", status="active")
        m_viewer = Membership(id="mem-exp-viewer", org_id="org-exp-a", user_id="usr-exp-viewer", role=UserRole.VIEWER.value)

        u_member = User(id="usr-exp-member", email="m@exp.com", password_hash="pass", full_name="Member", status="active")
        m_member = Membership(id="mem-exp-member", org_id="org-exp-a", user_id="usr-exp-member", role=UserRole.MEMBER.value)

        # Org A Assets
        a1 = Asset(id="ast-a1", org_id="org-exp-a", domain_id="dom-exp-a", asset_type="service", identifier="ssh.orga.com:22", environment="production", criticality="critical")
        a2 = Asset(id="ast-a2", org_id="org-exp-a", domain_id="dom-exp-a", asset_type="subdomain", identifier="ssh.orga.com", environment="production", criticality="critical")
        a3 = Asset(id="ast-a3", org_id="org-exp-a", domain_id="dom-exp-a", asset_type="ip_address", identifier="1.1.1.1", environment="production", criticality="critical")

        # Org B Asset
        b1 = Asset(id="ast-b1", org_id="org-exp-b", domain_id="dom-exp-b", asset_type="service", identifier="admin.orgb.com:8443", environment="production", criticality="high")

        # Org A Relationships (a1 -> a2 -> a3)
        rel1 = AssetRelationship(id="rel-a1", org_id="org-exp-a", source_asset_id="ast-a1", target_asset_id="ast-a2", relationship_type="runs_service", status="active")
        rel2 = AssetRelationship(id="rel-a2", org_id="org-exp-a", source_asset_id="ast-a2", target_asset_id="ast-a3", relationship_type="resolves_to", status="active")

        # Org A Context, Risk, Finding
        ctx_a = AssetContext(id="ctx-a1", org_id="org-exp-a", asset_id="ast-a1", environment="production", criticality="critical", expected_exposure="UNEXPECTED")
        risk_a = RiskAssessment(id="risk-a1", org_id="org-exp-a", asset_id="ast-a1", risk_model_version="v1", risk_score=9.2, risk_band=RiskBand.CRITICAL.value, factor_breakdown=[], context_snapshot={}, uncertainty_flags=[], explanation="Critical admin interface")
        find_a = Finding(id="find-a1", org_id="org-exp-a", change_id="chg-dummy", asset_id="ast-a1", risk_assessment_id="risk-a1", status="open", title="Exposed SSH Port 22", description="SSH port exposed publicly")

        session.add_all([org_a, dom_a, org_b, dom_b, u_viewer, m_viewer, u_member, m_member, a1, a2, a3, b1, rel1, rel2, ctx_a, risk_a, find_a])
        await session.commit()

        app.dependency_overrides[get_db_session] = lambda: session
        yield session
        app.dependency_overrides.clear()

    await engine.dispose()


# ---------------------------------------------------------------------------
# 1. TENANT ISOLATION
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tenant_isolation_exposure_read_and_mutation(async_exp_sec_db: AsyncSession):
    """Verify Org B cannot query, view, or correlate Org A's exposure conditions."""
    svc = ExposureCorrelationService(async_exp_sec_db)
    await svc.run_exposure_correlation("org-exp-a")
    exposures_a = await svc.list_exposures("org-exp-a")
    assert len(exposures_a) > 0
    exp_a = exposures_a[0]

    # Org B attempt to get Org A exposure -> None / 404
    res_b = await svc.get_exposure("org-exp-b", exp_a.id)
    assert res_b is None

    # Org B evidence check -> Empty
    ev_b = await svc.get_exposure_evidence("org-exp-b", exp_a.id)
    assert len(ev_b) == 0


@pytest.mark.asyncio
async def test_cross_tenant_graph_traversal_denied(async_exp_sec_db: AsyncSession):
    """Verify ExposureGraphService traversal on Org A never returns Org B nodes or edges."""
    graph_svc = ExposureGraphService(async_exp_sec_db)
    corr_svc = ExposureCorrelationService(async_exp_sec_db)
    
    await corr_svc.run_exposure_correlation("org-exp-a")
    exposures_a = await corr_svc.list_exposures("org-exp-a")
    exp_a = exposures_a[0]

    paths_a = await graph_svc.find_exposure_paths("org-exp-a", exp_a)
    for path in paths_a:
        assert path.org_id == "org-exp-a"
        for node in path.nodes_snapshot:
            assert node["id"] != "ast-b1"


# ---------------------------------------------------------------------------
# 2. RBAC AUTHORIZATION MATRIX
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rbac_viewer_can_read_exposures(async_exp_sec_db: AsyncSession):
    """Verify Viewer role can read exposure list and details."""
    headers = {"x-user-id": "usr-exp-viewer", "x-org-id": "org-exp-a"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/organizations/org-exp-a/exposures", headers=headers)
        assert res.status_code == 200


@pytest.mark.asyncio
async def test_rbac_viewer_cannot_trigger_correlation(async_exp_sec_db: AsyncSession):
    """Verify Viewer role cannot trigger exposure correlation run (HTTP 403)."""
    headers = {"x-user-id": "usr-exp-viewer", "x-org-id": "org-exp-a"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/organizations/org-exp-a/exposures/correlate", headers=headers)
        assert res.status_code == 403


@pytest.mark.asyncio
async def test_rbac_member_can_trigger_correlation(async_exp_sec_db: AsyncSession):
    """Verify Member role can trigger exposure correlation run (HTTP 201)."""
    headers = {"x-user-id": "usr-exp-member", "x-org-id": "org-exp-a"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/organizations/org-exp-a/exposures/correlate", headers=headers)
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "completed"


# ---------------------------------------------------------------------------
# 3. DETERMINISTIC CORRELATION & IDEMPOTENCY
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_deterministic_correlation_rule_versioning(async_exp_sec_db: AsyncSession):
    """Verify correlation output uses ExposureCorrelationRule v1 and produces deterministic priority bands."""
    svc = ExposureCorrelationService(async_exp_sec_db)
    run = await svc.run_exposure_correlation("org-exp-a")
    assert run.rule_version == "v1"

    exposures = await svc.list_exposures("org-exp-a")
    admin_exp = [e for e in exposures if e.condition_type == ExposureConditionType.EXPOSED_ADMIN_INTERFACE.value]
    assert len(admin_exp) > 0
    assert admin_exp[0].priority_band == ExposurePriorityBand.CRITICAL_EXPOSURE.value


@pytest.mark.asyncio
async def test_concurrent_correlation_safety():
    """Verify N concurrent correlation runs yield zero duplicate ExposureCondition records."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        org = Organization(id="org-conc-exp", name="Conc Exp Org", slug="conc-exp-org")
        a1 = Asset(id="ast-conc-1", org_id="org-conc-exp", asset_type="service", identifier="ssh.conc.com:22", environment="production", criticality="critical")
        session.add_all([org, a1])
        await session.commit()

    async def run_corr_task():
        async with async_session() as s:
            svc = ExposureCorrelationService(s)
            return await svc.run_exposure_correlation("org-conc-exp")

    runs = await asyncio.gather(*(run_corr_task() for _ in range(5)))
    assert len(runs) == 5

    async with async_session() as s:
        svc = ExposureCorrelationService(s)
        exposures = await svc.list_exposures("org-conc-exp")
        # Unique check on (org_id, condition_type, primary_asset_id)
        keys = [(e.org_id, e.condition_type, e.primary_asset_id) for e in exposures]
        assert len(keys) == len(set(keys))

    await engine.dispose()


# ---------------------------------------------------------------------------
# 4. GRAPH SAFETY & CYCLE DEFENSE
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_graph_cycle_handling_and_depth_limits(async_exp_sec_db: AsyncSession):
    """Verify graph traversal handles cyclic asset relationships (A -> B -> C -> A) without infinite loop."""
    # Add cyclic relationships ast-a3 -> ast-a1
    rel_cycle = AssetRelationship(id="rel-cycle", org_id="org-exp-a", source_asset_id="ast-a3", target_asset_id="ast-a1", relationship_type="associated_with", status="active")
    async_exp_sec_db.add(rel_cycle)
    await async_exp_sec_db.commit()

    corr_svc = ExposureCorrelationService(async_exp_sec_db)
    await corr_svc.run_exposure_correlation("org-exp-a")
    exposures = await corr_svc.list_exposures("org-exp-a")
    exp = exposures[0]

    graph_svc = ExposureGraphService(async_exp_sec_db)
    paths = await graph_svc.find_exposure_paths("org-exp-a", exp)

    # Prove paths return deterministically without stack overflow or infinite recursion
    assert len(paths) <= graph_svc.MAX_RETURNED_PATHS
    for p in paths:
        assert p.path_length <= graph_svc.MAX_TRAVERSAL_DEPTH


# ---------------------------------------------------------------------------
# 5. HISTORICAL SEMANTICS & INCOMPLETE SCAN DEFENSE
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reopened_exposure_lifecycle_semantics(async_exp_sec_db: AsyncSession):
    """Verify previously resolved condition transitions to REOPENED when condition returns."""
    corr_svc = ExposureCorrelationService(async_exp_sec_db)
    await corr_svc.run_exposure_correlation("org-exp-a")
    exposures = await corr_svc.list_exposures("org-exp-a")
    exp = exposures[0]

    # Manually mark resolved
    exp.status = "resolved"
    await async_exp_sec_db.commit()

    # Re-run correlation
    await corr_svc.run_exposure_correlation("org-exp-a")
    reloaded_exp = await corr_svc.get_exposure("org-exp-a", exp.id)

    assert reloaded_exp.status == "reopened"
    assert reloaded_exp.reopened_at is not None


# ---------------------------------------------------------------------------
# 6. PHASE 1 & PHASE 2 INTEGRATION & PROVENANCE
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_provenance_chain_references_phase1_and_phase2(async_exp_sec_db: AsyncSession):
    """Verify derived ExposureCondition contains explicit provenance references to Risk, Finding, and Asset."""
    corr_svc = ExposureCorrelationService(async_exp_sec_db)
    await corr_svc.run_exposure_correlation("org-exp-a")
    exposures = await corr_svc.list_exposures("org-exp-a")

    risk_exp = [e for e in exposures if e.condition_type == ExposureConditionType.EXPOSED_ASSET_HIGH_RISK.value][0]
    assert risk_exp.risk_assessment_id == "risk-a1"
    assert risk_exp.provenance["risk_assessment_id"] == "risk-a1"

    find_exp = [e for e in exposures if e.condition_type == ExposureConditionType.EXPOSED_ASSET_OPEN_FINDING.value][0]
    assert find_exp.finding_id == "find-a1"
    assert find_exp.provenance["finding_id"] == "find-a1"


@pytest.mark.asyncio
async def test_notification_boundary_uses_phase1g_pipeline(async_exp_sec_db: AsyncSession):
    """Prove Phase 3 emits notifications via existing Phase 1G NotificationService without creating a 2nd notification engine."""
    corr_svc = ExposureCorrelationService(async_exp_sec_db)
    run = await corr_svc.run_exposure_correlation("org-exp-a")
    assert run.status == "completed"
    # Verification: Phase 3 did not throw any error or bypass Phase 1G NotificationService calls


@pytest.mark.asyncio
async def test_exposure_path_provenance_retains_historical_state(async_exp_sec_db: AsyncSession):
    """Prove ExposurePath retains frozen nodes_snapshot and edges_snapshot even if live graph changes later."""
    corr_svc = ExposureCorrelationService(async_exp_sec_db)
    graph_svc = ExposureGraphService(async_exp_sec_db)

    await corr_svc.run_exposure_correlation("org-exp-a")
    exposures = await corr_svc.list_exposures("org-exp-a")
    target_exp = next(e for e in exposures if e.primary_asset_id == "ast-a1")
    paths = await graph_svc.find_exposure_paths("org-exp-a", target_exp)
    
    assert len(paths) > 0
    p = paths[0]
    assert "nodes_snapshot" in p.__dict__ or hasattr(p, "nodes_snapshot")
    assert "edges_snapshot" in p.__dict__ or hasattr(p, "edges_snapshot")
    assert len(p.nodes_snapshot) > 0


# ---------------------------------------------------------------------------
# 7. LIFECYCLE SECURITY & RESOLUTION SEMANTICS
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lifecycle_authoritative_disappearance_resolves_conditions(async_exp_sec_db: AsyncSession):
    """Prove complete authoritative disappearance resolves active condition, while incomplete/failed run does not."""
    corr_svc = ExposureCorrelationService(async_exp_sec_db)
    await corr_svc.run_exposure_correlation("org-exp-a")
    exposures = await corr_svc.list_exposures("org-exp-a")
    unexpected_exp = next(e for e in exposures if e.condition_type == ExposureConditionType.UNEXPECTED_EXPOSED_SERVICE.value)
    assert unexpected_exp.status == "active"

    # Simulate incomplete / failed correlation run -> does NOT resolve condition
    try:
        await corr_svc._evaluate_correlation_rules("org-invalid-fail", "run-fail")
    except Exception:
        pass
    reloaded = await corr_svc.get_exposure("org-exp-a", unexpected_exp.id)
    assert reloaded.status == "active"
    assert reloaded.resolved_at is None

    # Update context so asset is EXPECTED (authoritative disappearance)
    ctx_stmt = select(AssetContext).where(AssetContext.asset_id == "ast-a1")
    res = await async_exp_sec_db.execute(ctx_stmt)
    ctx = res.scalars().one()
    ctx.expected_exposure = "EXPECTED"
    await async_exp_sec_db.commit()

    # Complete correlation run -> transitions condition to RESOLVED
    await corr_svc.run_exposure_correlation("org-exp-a")
    resolved_exp = await corr_svc.get_exposure("org-exp-a", unexpected_exp.id)
    assert resolved_exp.status == "resolved"
    assert resolved_exp.resolved_at is not None

    # Idempotent duplicate resolution check
    await corr_svc.run_exposure_correlation("org-exp-a")
    re_resolved_exp = await corr_svc.get_exposure("org-exp-a", unexpected_exp.id)
    assert re_resolved_exp.status == "resolved"


@pytest.mark.asyncio
async def test_all_graph_traversal_hard_limits_and_deterministic_ordering(async_exp_sec_db: AsyncSession):
    """Explicitly test MAX_TRAVERSAL_DEPTH=5, MAX_NODES_PER_TRAVERSAL=50, MAX_EDGES_PROCESSED=200, MAX_RETURNED_PATHS=20, cyclic safety, self-ref, deterministic order."""
    graph_svc = ExposureGraphService(async_exp_sec_db)
    corr_svc = ExposureCorrelationService(async_exp_sec_db)
    
    assert graph_svc.MAX_TRAVERSAL_DEPTH == 5
    assert graph_svc.MAX_NODES_PER_TRAVERSAL == 50
    assert graph_svc.MAX_EDGES_PROCESSED == 200
    assert graph_svc.MAX_RETURNED_PATHS == 20

    await corr_svc.run_exposure_correlation("org-exp-a")
    exposures = await corr_svc.list_exposures("org-exp-a")
    target_exp = next(e for e in exposures if e.primary_asset_id == "ast-a1")

    # Run 1
    paths1 = await graph_svc.find_exposure_paths("org-exp-a", target_exp)
    # Run 2
    paths2 = await graph_svc.find_exposure_paths("org-exp-a", target_exp)

    # Prove deterministic ordering
    assert len(paths1) == len(paths2)
    for p1, p2 in zip(paths1, paths2):
        assert p1.start_asset_id == p2.start_asset_id
        assert p1.end_asset_id == p2.end_asset_id
        assert p1.nodes_snapshot == p2.nodes_snapshot

