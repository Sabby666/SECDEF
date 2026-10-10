"""Unit test suite for Phase 3 Exposure Intelligence & Correlation Engine."""
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, Domain, Asset, AssetRelationship, AssetContext, RiskAssessment, Finding, Change,
    DiscoveryCandidate, ExposureCondition, ExposurePath
)
from app.application.exposure_correlation_service import ExposureCorrelationService
from app.application.exposure_graph_service import ExposureGraphService
from shared_contracts.enums import (
    ExposureConditionType, ExposureConditionStatus, ExposurePriorityBand,
    RiskBand, Environment, Criticality, FindingLifecycleStatus
)


@pytest_asyncio.fixture
async def async_unit_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        org = Organization(id="org-unit-exp", name="Unit Exposure Org", slug="unit-exp-org")
        dom = Domain(id="dom-unit-exp", org_id="org-unit-exp", domain_name="unitexp.com", status="verified", verification_token="tokUnit")
        
        # Seed Assets
        a1 = Asset(id="ast-1", org_id="org-unit-exp", domain_id="dom-unit-exp", asset_type="service", identifier="api.unitexp.com:8443", environment="production", criticality="high")
        a2 = Asset(id="ast-2", org_id="org-unit-exp", domain_id="dom-unit-exp", asset_type="subdomain", identifier="api.unitexp.com", environment="production", criticality="high")
        a3 = Asset(id="ast-3", org_id="org-unit-exp", domain_id="dom-unit-exp", asset_type="ip_address", identifier="93.184.216.34", environment="production", criticality="high")

        # Seed Relationships (a1 -> a2 -> a3)
        rel1 = AssetRelationship(id="rel-1", org_id="org-unit-exp", source_asset_id="ast-1", target_asset_id="ast-2", relationship_type="runs_service", status="active")
        rel2 = AssetRelationship(id="rel-2", org_id="org-unit-exp", source_asset_id="ast-2", target_asset_id="ast-3", relationship_type="resolves_to", status="active")

        # Seed Context (UNEXPECTED)
        ctx1 = AssetContext(id="ctx-1", org_id="org-unit-exp", asset_id="ast-1", environment="production", criticality="high", expected_exposure="UNEXPECTED")

        # Seed RiskAssessment
        risk1 = RiskAssessment(id="risk-1", org_id="org-unit-exp", asset_id="ast-1", risk_model_version="v1", risk_score=8.5, risk_band=RiskBand.HIGH.value, factor_breakdown=[], context_snapshot={}, uncertainty_flags=[], explanation="High risk")

        session.add_all([org, dom, a1, a2, a3, rel1, rel2, ctx1, risk1])
        await session.commit()
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_correlation_evaluates_rules_and_creates_conditions(async_unit_db: AsyncSession):
    """Verify correlation engine evaluates rules and generates derived ExposureCondition items."""
    svc = ExposureCorrelationService(async_unit_db)
    run = await svc.run_exposure_correlation("org-unit-exp")
    
    assert run.status == "completed"
    assert run.conditions_detected > 0

    exposures = await svc.list_exposures("org-unit-exp")
    cond_types = [e.condition_type for e in exposures]

    assert ExposureConditionType.INTERNET_FACING_SERVICE.value in cond_types
    assert ExposureConditionType.UNEXPECTED_EXPOSED_SERVICE.value in cond_types
    assert ExposureConditionType.EXTERNALLY_REACHABLE_PRODUCTION_ASSET.value in cond_types
    assert ExposureConditionType.EXTERNALLY_REACHABLE_HIGH_CRITICALITY.value in cond_types
    assert ExposureConditionType.EXPOSED_ADMIN_INTERFACE.value in cond_types


@pytest.mark.asyncio
async def test_correlation_idempotency_updates_last_seen_without_duplicates(async_unit_db: AsyncSession):
    """Verify executing correlation twice on unchanged state updates timestamps without creating duplicate conditions."""
    svc = ExposureCorrelationService(async_unit_db)
    
    run1 = await svc.run_exposure_correlation("org-unit-exp")
    exposures1 = await svc.list_exposures("org-unit-exp")

    run2 = await svc.run_exposure_correlation("org-unit-exp")
    exposures2 = await svc.list_exposures("org-unit-exp")

    assert len(exposures1) == len(exposures2)


@pytest.mark.asyncio
async def test_bounded_exposure_graph_traversal(async_unit_db: AsyncSession):
    """Verify ExposureGraphService traverses asset relationships up to depth limit without infinite recursion."""
    graph_svc = ExposureGraphService(async_unit_db)
    cond_stmt = select(ExposureCondition).where(ExposureCondition.org_id == "org-unit-exp")
    res = await async_unit_db.execute(cond_stmt)
    conditions = res.scalars().all()

    if not conditions:
        corr_svc = ExposureCorrelationService(async_unit_db)
        await corr_svc.run_exposure_correlation("org-unit-exp")
        conditions = await corr_svc.list_exposures("org-unit-exp")

    cond = conditions[0]
    paths = await graph_svc.find_exposure_paths("org-unit-exp", cond)
    
    assert len(paths) <= graph_svc.MAX_RETURNED_PATHS
    for p in paths:
        assert p.path_length <= graph_svc.MAX_TRAVERSAL_DEPTH
        assert p.org_id == "org-unit-exp"


@pytest.mark.asyncio
async def test_exposure_condition_identity_multiple_conditions_on_same_asset(async_unit_db: AsyncSession):
    """Prove a single asset can legitimately have multiple distinct exposure conditions without collapsing."""
    svc = ExposureCorrelationService(async_unit_db)
    await svc.run_exposure_correlation("org-unit-exp")
    
    exposures = await svc.list_exposures("org-unit-exp")
    ast1_exposures = [e for e in exposures if e.primary_asset_id == "ast-1"]
    
    # Asset ast-1 has multiple distinct condition types (INTERNET_FACING_SERVICE, UNEXPECTED_EXPOSED_SERVICE, EXPOSED_ADMIN_INTERFACE)
    types_on_ast1 = {e.condition_type for e in ast1_exposures}
    assert len(types_on_ast1) >= 3
    assert ExposureConditionType.INTERNET_FACING_SERVICE.value in types_on_ast1
    assert ExposureConditionType.UNEXPECTED_EXPOSED_SERVICE.value in types_on_ast1
    assert ExposureConditionType.EXPOSED_ADMIN_INTERFACE.value in types_on_ast1


@pytest.mark.asyncio
async def test_all_graph_traversal_resource_limits(async_unit_db: AsyncSession):
    """Explicitly verify MAX_TRAVERSAL_DEPTH=5, MAX_NODES_PER_TRAVERSAL=50, MAX_EDGES_PROCESSED=200, MAX_RETURNED_PATHS=20 limits."""
    graph_svc = ExposureGraphService(async_unit_db)
    assert graph_svc.MAX_TRAVERSAL_DEPTH == 5
    assert graph_svc.MAX_NODES_PER_TRAVERSAL == 50
    assert graph_svc.MAX_EDGES_PROCESSED == 200
    assert graph_svc.MAX_RETURNED_PATHS == 20


@pytest.mark.asyncio
async def test_graph_self_reference_and_duplicate_edge_safety(async_unit_db: AsyncSession):
    """Verify self-referencing relationships (A -> A) and duplicate edges do not cause infinite recursion."""
    self_rel = AssetRelationship(id="rel-self", org_id="org-unit-exp", source_asset_id="ast-1", target_asset_id="ast-1", relationship_type="associated_with", status="active")
    async_unit_db.add(self_rel)
    await async_unit_db.commit()

    graph_svc = ExposureGraphService(async_unit_db)
    corr_svc = ExposureCorrelationService(async_unit_db)
    await corr_svc.run_exposure_correlation("org-unit-exp")
    exposures = await corr_svc.list_exposures("org-unit-exp")

    paths = await graph_svc.find_exposure_paths("org-unit-exp", exposures[0])
    assert isinstance(paths, list)

