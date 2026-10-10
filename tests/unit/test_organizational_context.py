"""Phase 1E Unit Tests: Organizational Context, Expected State & Controlled Memory.

Tests cover:
- Asset context update (owner, team, environment, criticality)
- Decision creation & derived memory generation
- Scope-limited inheritance safety invariant (NO unassisted wildcard/global escalation)
- Scope precedence resolution (SERVICE > ASSET > HOSTNAME > DOMAIN > ORGANIZATION)
- Conflict detection (returns CONFLICT_REQUIRES_REVIEW when memories clash)
- Memory expiration (expired memories excluded from active context)
- Decision revocation & immutable transition history
- Deterministic resolution & explainability provenance
"""

import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, User, Membership, Domain, Asset,
    AssetContext, OrganizationalDecision, OrganizationalMemory, DecisionTransitionHistory
)
from app.application.context_service import OrganizationalContextService
from app.application.decision_service import DecisionService
from app.application.controlled_learning_service import ControlledLearningService
from app.application.context_resolver import ContextResolver
from shared_contracts.enums import (
    DecisionType, ScopeLevel, DecisionStatus, DomainStatus, Environment, Criticality, ClaimType
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
    from sqlalchemy.orm import sessionmaker
    async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session


@pytest_asyncio.fixture
async def seed_org(db_session: AsyncSession):
    org = Organization(name="Test Org 1E", slug="test-org-1e")
    admin = User(email="admin1e@test.com", password_hash="hash", full_name="Admin 1E")
    db_session.add_all([org, admin])
    await db_session.commit()

    mem = Membership(org_id=org.id, user_id=admin.id, role="admin")
    domain = Domain(
        org_id=org.id,
        domain_name="example.com",
        status=DomainStatus.VERIFIED,
        verification_token="token-1e",
        verified_at=datetime.now(timezone.utc),
    )
    db_session.add_all([mem, domain])
    await db_session.commit()

    asset = Asset(
        org_id=org.id,
        domain_id=domain.id,
        asset_type="subdomain",
        identifier="api.example.com",
        environment="unknown",
        criticality="medium",
        status="active",
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    db_session.add(asset)
    await db_session.commit()

    return {
        "org_id": org.id,
        "admin_id": admin.id,
        "domain_id": domain.id,
        "asset_id": asset.id,
    }


@pytest.mark.asyncio
class TestOrganizationalContextService:

    async def test_update_asset_context(self, db_session: AsyncSession, seed_org: dict):
        """Updating asset context updates Asset table & stores AssetContext record."""
        service = OrganizationalContextService(db_session)
        ctx = await service.update_asset_context(
            org_id=seed_org["org_id"],
            asset_id=seed_org["asset_id"],
            actor_id=seed_org["admin_id"],
            owner_id=seed_org["admin_id"],
            owner_team="Security Ops",
            environment="production",
            criticality="critical",
            business_purpose="Core API Gateway",
            expected_exposure="public",
        )
        await db_session.commit()

        assert ctx.environment == "production"
        assert ctx.criticality == "critical"
        assert ctx.owner_team == "Security Ops"

        # Verify canonical Asset model sync
        asset_res = await db_session.execute(select(Asset).where(Asset.id == seed_org["asset_id"]))
        asset = asset_res.scalars().first()
        assert asset.environment == "production"
        assert asset.criticality == "critical"
        assert asset.owner_id == seed_org["admin_id"]


@pytest.mark.asyncio
class TestDecisionAndLearningService:

    async def test_create_decision_and_derived_memory(self, db_session: AsyncSession, seed_org: dict):
        """Creating a decision derives a persistent, scope-limited memory."""
        service = DecisionService(db_session)
        decision = await service.create_decision(
            org_id=seed_org["org_id"],
            actor_id=seed_org["admin_id"],
            decision_type=DecisionType.MARK_EXPECTED.value,
            scope_level=ScopeLevel.SERVICE.value,
            subject_identifier="service:api.example.com:8443",
            subject_type="service",
            new_state={"expected_state": "EXPECTED"},
            reason="Approved staging proxy port",
        )
        await db_session.commit()

        assert decision.status == DecisionStatus.ACTIVE
        assert decision.scope_level == ScopeLevel.SERVICE.value

        # Verify derived memory
        learning_service = ControlledLearningService(db_session)
        memories, total = await learning_service.list_memories(
            org_id=seed_org["org_id"],
            scope_level=ScopeLevel.SERVICE.value,
        )
        assert total == 1
        assert memories[0].decision_id == decision.id
        assert memories[0].scope_identifier == "service:api.example.com:8443"
        assert memories[0].memory_value["decision_type"] == DecisionType.MARK_EXPECTED.value

    async def test_scope_limited_inheritance_safety_invariant(self, db_session: AsyncSession, seed_org: dict):
        """Decision on api.example.com:8443 DOES NOT auto-escalate to port 80 or wildcard domain."""
        service = DecisionService(db_session)
        await service.create_decision(
            org_id=seed_org["org_id"],
            actor_id=seed_org["admin_id"],
            decision_type=DecisionType.MARK_EXPECTED.value,
            scope_level=ScopeLevel.SERVICE.value,
            subject_identifier="service:api.example.com:8443",
            new_state={"expected_state": "EXPECTED"},
            reason="Approved port 8443",
        )
        await db_session.commit()

        resolver = ContextResolver(db_session)

        # 1. Exact match on port 8443 -> EXPECTED
        res_8443 = await resolver.resolve_context(
            org_id=seed_org["org_id"],
            target_type="service",
            target_identifier="api.example.com:8443",
            domain_name="example.com",
        )
        assert res_8443.expected_state == "EXPECTED"

        # 2. Port 80 on same host -> UNSPECIFIED (no scope escalation)
        res_80 = await resolver.resolve_context(
            org_id=seed_org["org_id"],
            target_type="service",
            target_identifier="api.example.com:80",
            domain_name="example.com",
        )
        assert res_80.expected_state == "UNSPECIFIED"

        # 3. Different subdomain on port 8443 -> UNSPECIFIED (no wildcard domain escalation)
        res_other = await resolver.resolve_context(
            org_id=seed_org["org_id"],
            target_type="service",
            target_identifier="other.example.com:8443",
            domain_name="example.com",
        )
        assert res_other.expected_state == "UNSPECIFIED"

    async def test_scope_precedence_resolution(self, db_session: AsyncSession, seed_org: dict):
        """SERVICE scope memory overrides broader DOMAIN scope memory."""
        service = DecisionService(db_session)

        # Broader domain-level decision: MARK_EXPECTED
        await service.create_decision(
            org_id=seed_org["org_id"],
            actor_id=seed_org["admin_id"],
            decision_type=DecisionType.MARK_EXPECTED.value,
            scope_level=ScopeLevel.DOMAIN.value,
            subject_identifier="domain:example.com",
            new_state={"expected_state": "EXPECTED"},
            reason="Domain baseline",
        )

        # Specific service-level decision: MARK_UNEXPECTED
        await service.create_decision(
            org_id=seed_org["org_id"],
            actor_id=seed_org["admin_id"],
            decision_type=DecisionType.MARK_UNEXPECTED.value,
            scope_level=ScopeLevel.SERVICE.value,
            subject_identifier="service:api.example.com:22",
            new_state={"expected_state": "UNEXPECTED"},
            reason="SSH port 22 is forbidden",
        )
        await db_session.commit()

        resolver = ContextResolver(db_session)
        res = await resolver.resolve_context(
            org_id=seed_org["org_id"],
            target_type="service",
            target_identifier="api.example.com:22",
            domain_name="example.com",
        )

        # SERVICE scope (precedence 50) overrides DOMAIN scope (precedence 20)
        assert res.expected_state == "UNEXPECTED"
        assert res.provenance[0].scope_level == ScopeLevel.SERVICE

    async def test_conflict_detection(self, db_session: AsyncSession, seed_org: dict):
        """Two clashing active decisions at the same top precedence level trigger CONFLICT_REQUIRES_REVIEW."""
        service = DecisionService(db_session)

        # Decision 1: Mark EXPECTED
        await service.create_decision(
            org_id=seed_org["org_id"],
            actor_id=seed_org["admin_id"],
            decision_type=DecisionType.MARK_EXPECTED.value,
            scope_level=ScopeLevel.SERVICE.value,
            subject_identifier="service:api.example.com:8443",
            new_state={"expected_state": "EXPECTED"},
            reason="Decision A",
        )

        # Decision 2: Mark UNEXPECTED at same scope
        await service.create_decision(
            org_id=seed_org["org_id"],
            actor_id=seed_org["admin_id"],
            decision_type=DecisionType.MARK_UNEXPECTED.value,
            scope_level=ScopeLevel.SERVICE.value,
            subject_identifier="service:api.example.com:8443",
            new_state={"expected_state": "UNEXPECTED"},
            reason="Decision B",
        )
        await db_session.commit()

        resolver = ContextResolver(db_session)
        res = await resolver.resolve_context(
            org_id=seed_org["org_id"],
            target_type="service",
            target_identifier="api.example.com:8443",
            domain_name="example.com",
        )

        assert res.conflict_detected is True
        assert res.expected_state == "CONFLICT_REQUIRES_REVIEW"
        assert res.resolution_status == "conflict_detected"
        assert len(res.provenance) >= 2

    async def test_memory_expiration(self, db_session: AsyncSession, seed_org: dict):
        """Expired decisions (valid_until in past) are ignored by context resolver."""
        service = DecisionService(db_session)
        past_time = datetime.now(timezone.utc) - timedelta(days=1)

        await service.create_decision(
            org_id=seed_org["org_id"],
            actor_id=seed_org["admin_id"],
            decision_type=DecisionType.MARK_EXPECTED.value,
            scope_level=ScopeLevel.SERVICE.value,
            subject_identifier="service:api.example.com:8443",
            new_state={"expected_state": "EXPECTED"},
            reason="Temporary approval",
            valid_until=past_time,
        )
        await db_session.commit()

        resolver = ContextResolver(db_session)
        res = await resolver.resolve_context(
            org_id=seed_org["org_id"],
            target_type="service",
            target_identifier="api.example.com:8443",
        )

        # Expired memory is ignored -> fallback to UNSPECIFIED
        assert res.expected_state == "UNSPECIFIED"

    async def test_decision_revocation(self, db_session: AsyncSession, seed_org: dict):
        """Revoking a decision deactivates derived memory & logs transition history."""
        service = DecisionService(db_session)
        decision = await service.create_decision(
            org_id=seed_org["org_id"],
            actor_id=seed_org["admin_id"],
            decision_type=DecisionType.MARK_EXPECTED.value,
            scope_level=ScopeLevel.SERVICE.value,
            subject_identifier="service:api.example.com:8443",
            new_state={"expected_state": "EXPECTED"},
            reason="Initial approval",
        )
        await db_session.commit()

        # Revoke decision
        revoked = await service.revoke_decision(
            org_id=seed_org["org_id"],
            decision_id=decision.id,
            actor_id=seed_org["admin_id"],
            reason="Security policy change",
        )
        await db_session.commit()

        assert revoked.status == DecisionStatus.REVOKED

        # Verify append-only transition log
        trans_res = await db_session.execute(
            select(DecisionTransitionHistory).where(
                DecisionTransitionHistory.decision_id == decision.id
            )
        )
        history = trans_res.scalars().all()
        assert len(history) == 1
        assert history[0].from_status == DecisionStatus.ACTIVE
        assert history[0].to_status == DecisionStatus.REVOKED

        # Verify resolver no longer sees revoked memory
        resolver = ContextResolver(db_session)
        res = await resolver.resolve_context(
            org_id=seed_org["org_id"],
            target_type="service",
            target_identifier="api.example.com:8443",
        )
        assert res.expected_state == "UNSPECIFIED"
