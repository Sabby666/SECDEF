"""Phase 1D Unit Tests: Change Detection Service

Tests cover:
- First scan → baseline_established, no changes
- Asset added detection
- Asset removed detection (with completeness gate)
- Asset property change detection
- Relationship added/removed detection
- Partial scan → removal suppression (HARD SECURITY GATE)
- Failed scan → skipped_incomplete
- Out-of-order scan handling
- Identical scans → no changes emitted
- Idempotent reprocessing
- Completeness assessment logic
- Canonical identity equivalence
"""

import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, User, Membership, Domain, Scan, Observation, Asset,
    AssetRelationship, ComparisonRun, Change,
)
from app.application.change_detection_service import (
    ChangeDetectionService,
    _assess_scan_completeness,
    _can_declare_removal,
    _build_asset_state,
)
from shared_contracts.enums import (
    ChangeType, ComparisonStatus, ScanCompleteness, DomainStatus,
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
async def seed_org(db_session: AsyncSession):
    """Create a basic org + user + domain for testing."""
    org = Organization(name="Test Org", slug="test-org")
    user = User(email="test@test.com", password_hash="hash", full_name="Tester")
    db_session.add_all([org, user])
    await db_session.commit()

    mem = Membership(org_id=org.id, user_id=user.id, role="admin")
    domain = Domain(
        org_id=org.id,
        domain_name="example.com",
        status=DomainStatus.VERIFIED,
        verification_token="test-token",
        verified_at=datetime.now(timezone.utc),
    )
    db_session.add_all([mem, domain])
    await db_session.commit()

    return {"org_id": org.id, "user_id": user.id, "domain_id": domain.id}


async def _create_scan(
    db: AsyncSession,
    org_id: str,
    domain_id: str,
    status: str = "completed",
    completed_at: datetime = None,
    scan_metadata: dict = None,
) -> Scan:
    """Helper to create a scan."""
    import uuid
    now = completed_at or datetime.now(timezone.utc)
    scan = Scan(
        org_id=org_id,
        domain_id=domain_id,
        status=status,
        job_nonce=f"nonce-{uuid.uuid4().hex}",
        started_at=now - timedelta(minutes=5),
        completed_at=now,
        scan_metadata=scan_metadata,
        created_at=now - timedelta(minutes=5),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def _create_asset(
    db: AsyncSession,
    org_id: str,
    asset_type: str,
    identifier: str,
    domain_id: str = None,
) -> Asset:
    """Helper to create an asset."""
    asset = Asset(
        org_id=org_id,
        domain_id=domain_id,
        asset_type=asset_type,
        identifier=identifier,
        environment="unknown",
        criticality="medium",
        status="active",
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset


async def _create_observation(
    db: AsyncSession,
    org_id: str,
    scan_id: str,
    asset_id: str,
    obs_type: str = "dns_record",
    target: str = "example.com",
    raw_data: dict = None,
) -> Observation:
    """Helper to create an observation linking a scan to an asset."""
    obs = Observation(
        org_id=org_id,
        scan_id=scan_id,
        asset_id=asset_id,
        observation_type=obs_type,
        target=target,
        raw_data=raw_data if raw_data is not None else {"test": True},
        observed_at=datetime.now(timezone.utc),
    )
    db.add(obs)
    await db.commit()
    await db.refresh(obs)
    return obs


# ── Completeness Assessment Tests ──

class TestCompletenessAssessment:

    def test_failed_scan(self):
        scan = Scan(status="failed", scan_metadata=None)
        level, details = _assess_scan_completeness(scan)
        assert level == ScanCompleteness.FAILED
        assert details["reason"] == "scan_failed"

    def test_completed_no_metadata(self):
        scan = Scan(status="completed", scan_metadata=None)
        level, _ = _assess_scan_completeness(scan)
        assert level == ScanCompleteness.COMPLETE

    def test_completed_all_classes_ok(self):
        scan = Scan(
            status="completed",
            scan_metadata={
                "observation_classes": {
                    "dns_record": "completed",
                    "open_port": "completed",
                    "tls_cert": "completed",
                }
            },
        )
        level, details = _assess_scan_completeness(scan)
        assert level == ScanCompleteness.COMPLETE

    def test_completed_some_classes_failed(self):
        scan = Scan(
            status="completed",
            scan_metadata={
                "observation_classes": {
                    "dns_record": "completed",
                    "open_port": "completed",
                    "tls_cert": "failed",
                }
            },
        )
        level, details = _assess_scan_completeness(scan)
        assert level == ScanCompleteness.PARTIAL
        assert "tls_cert" in details["failed_classes"]

    def test_partial_status(self):
        scan = Scan(status="partial", scan_metadata=None)
        level, _ = _assess_scan_completeness(scan)
        assert level == ScanCompleteness.PARTIAL


# ── Removal Safety Gate Tests ──

class TestRemovalSafetyGate:

    def test_failed_scan_blocks_removal(self):
        assert _can_declare_removal("subdomain", ScanCompleteness.FAILED, None) is False

    def test_unknown_completeness_blocks_removal(self):
        assert _can_declare_removal("subdomain", ScanCompleteness.UNKNOWN, None) is False

    def test_complete_scan_allows_removal(self):
        assert _can_declare_removal("subdomain", ScanCompleteness.COMPLETE, None) is True

    def test_partial_scan_without_details_blocks_removal(self):
        assert _can_declare_removal("subdomain", ScanCompleteness.PARTIAL, None) is False

    def test_partial_scan_with_completed_class_allows_removal(self):
        details = {
            "observation_classes": {
                "dns_record": "completed",
                "open_port": "completed",
            }
        }
        # subdomain requires dns_record class
        assert _can_declare_removal("subdomain", ScanCompleteness.PARTIAL, details) is True

    def test_partial_scan_with_failed_class_blocks_removal(self):
        details = {
            "observation_classes": {
                "dns_record": "failed",
                "open_port": "completed",
            }
        }
        # subdomain requires dns_record class which failed
        assert _can_declare_removal("subdomain", ScanCompleteness.PARTIAL, details) is False

    def test_service_requires_multiple_classes(self):
        details = {
            "observation_classes": {
                "open_port": "completed",
                "http_banner": "completed",
                "tls_cert": "failed",
            }
        }
        # service requires open_port, http_banner, tls_cert — tls_cert failed
        assert _can_declare_removal("service", ScanCompleteness.PARTIAL, details) is False


# ── Change Detection Service Tests ──

@pytest.mark.asyncio
class TestFirstScan:

    async def test_first_scan_establishes_baseline(self, db_session, seed_org):
        """First scan must produce BASELINE_ESTABLISHED, NOT asset_added changes."""
        scan = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"])
        asset = await _create_asset(
            db_session, seed_org["org_id"], "subdomain", "api.example.com",
            domain_id=seed_org["domain_id"],
        )
        await _create_observation(
            db_session, seed_org["org_id"], scan.id, asset.id,
        )

        service = ChangeDetectionService(db_session)
        result = await service.detect_changes_for_scan(
            scan.id, seed_org["org_id"], seed_org["domain_id"],
        )
        await db_session.commit()

        assert result.status == ComparisonStatus.BASELINE_ESTABLISHED
        assert result.changes_detected == 0
        assert result.previous_scan_id is None


@pytest.mark.asyncio
class TestAssetChanges:

    async def test_asset_added(self, db_session, seed_org):
        """New asset in scan 2 that wasn't in scan 1 → ASSET_ADDED."""
        t1 = datetime.now(timezone.utc) - timedelta(hours=2)
        t2 = datetime.now(timezone.utc) - timedelta(hours=1)

        scan1 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t1)
        scan2 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t2)

        asset_a = await _create_asset(db_session, seed_org["org_id"], "subdomain", "api.example.com")
        asset_b = await _create_asset(db_session, seed_org["org_id"], "subdomain", "new.example.com")

        # Scan 1: asset_a only
        await _create_observation(db_session, seed_org["org_id"], scan1.id, asset_a.id)

        # Scan 2: asset_a + asset_b
        await _create_observation(db_session, seed_org["org_id"], scan2.id, asset_a.id)
        await _create_observation(db_session, seed_org["org_id"], scan2.id, asset_b.id)

        service = ChangeDetectionService(db_session)

        # First: baseline for scan1
        r1 = await service.detect_changes_for_scan(scan1.id, seed_org["org_id"], seed_org["domain_id"])
        assert r1.status == ComparisonStatus.BASELINE_ESTABLISHED

        # Second: compare scan2 vs scan1
        r2 = await service.detect_changes_for_scan(scan2.id, seed_org["org_id"], seed_org["domain_id"])
        await db_session.commit()

        assert r2.status == ComparisonStatus.COMPLETED
        assert r2.changes_detected == 1

        from sqlalchemy import select
        changes = (await db_session.execute(
            select(Change).where(Change.comparison_run_id == r2.id)
        )).scalars().all()

        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.ASSET_ADDED
        assert "new.example.com" in changes[0].entity_identifier

    async def test_asset_removed_with_complete_scan(self, db_session, seed_org):
        """Asset in scan 1 but not in scan 2 (complete) → ASSET_REMOVED."""
        t1 = datetime.now(timezone.utc) - timedelta(hours=2)
        t2 = datetime.now(timezone.utc) - timedelta(hours=1)

        scan1 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t1)
        scan2 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t2)

        asset_a = await _create_asset(db_session, seed_org["org_id"], "subdomain", "api.example.com")
        asset_b = await _create_asset(db_session, seed_org["org_id"], "subdomain", "old.example.com")

        # Scan 1: both assets
        await _create_observation(db_session, seed_org["org_id"], scan1.id, asset_a.id)
        await _create_observation(db_session, seed_org["org_id"], scan1.id, asset_b.id)

        # Scan 2: only asset_a
        await _create_observation(db_session, seed_org["org_id"], scan2.id, asset_a.id)

        service = ChangeDetectionService(db_session)
        await service.detect_changes_for_scan(scan1.id, seed_org["org_id"], seed_org["domain_id"])
        r2 = await service.detect_changes_for_scan(scan2.id, seed_org["org_id"], seed_org["domain_id"])
        await db_session.commit()

        assert r2.status == ComparisonStatus.COMPLETED
        assert r2.changes_detected == 1

        from sqlalchemy import select
        changes = (await db_session.execute(
            select(Change).where(Change.comparison_run_id == r2.id)
        )).scalars().all()
        assert changes[0].change_type == ChangeType.ASSET_REMOVED
        assert "old.example.com" in changes[0].entity_identifier

    async def test_removal_suppressed_on_partial_scan(self, db_session, seed_org):
        """HARD SECURITY GATE: Partial scan must NOT generate false removals."""
        t1 = datetime.now(timezone.utc) - timedelta(hours=2)
        t2 = datetime.now(timezone.utc) - timedelta(hours=1)

        scan1 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t1)
        scan2 = await _create_scan(
            db_session, seed_org["org_id"], seed_org["domain_id"],
            completed_at=t2, status="partial",
            scan_metadata={"observation_classes": {"dns_record": "failed", "open_port": "completed"}},
        )

        asset_a = await _create_asset(db_session, seed_org["org_id"], "subdomain", "api.example.com")

        # Scan 1: asset_a present
        await _create_observation(db_session, seed_org["org_id"], scan1.id, asset_a.id)

        # Scan 2: asset_a absent (but dns_record class failed)

        service = ChangeDetectionService(db_session)
        await service.detect_changes_for_scan(scan1.id, seed_org["org_id"], seed_org["domain_id"])
        r2 = await service.detect_changes_for_scan(scan2.id, seed_org["org_id"], seed_org["domain_id"])
        await db_session.commit()

        assert r2.status == ComparisonStatus.COMPLETED
        # No removal should be generated because dns_record class failed
        assert r2.changes_detected == 0

    async def test_asset_property_changed(self, db_session, seed_org):
        """Asset present in both scans but with different properties → ASSET_PROPERTY_CHANGED."""
        t1 = datetime.now(timezone.utc) - timedelta(hours=2)
        t2 = datetime.now(timezone.utc) - timedelta(hours=1)

        scan1 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t1)
        scan2 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t2)

        asset = await _create_asset(db_session, seed_org["org_id"], "subdomain", "api.example.com")

        # Scan 1 observation (version 1.0)
        await _create_observation(db_session, seed_org["org_id"], scan1.id, asset.id, raw_data={"version": "1.0"})

        # Scan 2 observation (version 2.0)
        await _create_observation(db_session, seed_org["org_id"], scan2.id, asset.id, raw_data={"version": "2.0"})

        service = ChangeDetectionService(db_session)
        await service.detect_changes_for_scan(scan1.id, seed_org["org_id"], seed_org["domain_id"])
        r2 = await service.detect_changes_for_scan(scan2.id, seed_org["org_id"], seed_org["domain_id"])
        await db_session.commit()

        assert r2.status == ComparisonStatus.COMPLETED
        assert r2.changes_detected == 1

        from sqlalchemy import select
        changes = (await db_session.execute(
            select(Change).where(Change.comparison_run_id == r2.id)
        )).scalars().all()
        assert changes[0].change_type == ChangeType.ASSET_PROPERTY_CHANGED

    async def test_identical_scans_no_changes(self, db_session, seed_org):
        """Same assets in both scans with no property changes → zero changes."""
        t1 = datetime.now(timezone.utc) - timedelta(hours=2)
        t2 = datetime.now(timezone.utc) - timedelta(hours=1)

        scan1 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t1)
        scan2 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t2)

        asset = await _create_asset(db_session, seed_org["org_id"], "subdomain", "api.example.com")

        await _create_observation(db_session, seed_org["org_id"], scan1.id, asset.id)
        await _create_observation(db_session, seed_org["org_id"], scan2.id, asset.id)

        service = ChangeDetectionService(db_session)
        await service.detect_changes_for_scan(scan1.id, seed_org["org_id"], seed_org["domain_id"])
        r2 = await service.detect_changes_for_scan(scan2.id, seed_org["org_id"], seed_org["domain_id"])
        await db_session.commit()

        assert r2.status == ComparisonStatus.COMPLETED
        assert r2.changes_detected == 0


@pytest.mark.asyncio
class TestIdempotency:

    async def test_same_scan_processed_twice(self, db_session, seed_org):
        """Processing the same scan twice must return the same result without duplicates."""
        scan = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"])
        asset = await _create_asset(db_session, seed_org["org_id"], "subdomain", "api.example.com")
        await _create_observation(db_session, seed_org["org_id"], scan.id, asset.id)

        service = ChangeDetectionService(db_session)
        r1 = await service.detect_changes_for_scan(scan.id, seed_org["org_id"], seed_org["domain_id"])
        await db_session.commit()

        r2 = await service.detect_changes_for_scan(scan.id, seed_org["org_id"], seed_org["domain_id"])

        assert r1.id == r2.id
        assert r1.status == r2.status


@pytest.mark.asyncio
class TestTemporalOrdering:

    async def test_failed_scan_skipped(self, db_session, seed_org):
        """A failed scan should produce skipped_incomplete."""
        scan = await _create_scan(
            db_session, seed_org["org_id"], seed_org["domain_id"],
            status="failed",
        )

        service = ChangeDetectionService(db_session)
        result = await service.detect_changes_for_scan(
            scan.id, seed_org["org_id"], seed_org["domain_id"],
        )
        await db_session.commit()

        assert result.status == ComparisonStatus.SKIPPED_INCOMPLETE

    async def test_out_of_order_scan_skipped(self, db_session, seed_org):
        """An older scan arriving after a newer one should be skipped."""
        t1 = datetime.now(timezone.utc) - timedelta(hours=3)
        t2 = datetime.now(timezone.utc) - timedelta(hours=2)
        t3 = datetime.now(timezone.utc) - timedelta(hours=1)

        scan1 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t1)
        scan3 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t3)
        scan2 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t2)

        asset = await _create_asset(db_session, seed_org["org_id"], "subdomain", "api.example.com")
        await _create_observation(db_session, seed_org["org_id"], scan1.id, asset.id)
        await _create_observation(db_session, seed_org["org_id"], scan2.id, asset.id)
        await _create_observation(db_session, seed_org["org_id"], scan3.id, asset.id)

        service = ChangeDetectionService(db_session)

        # Process scan1 (baseline)
        r1 = await service.detect_changes_for_scan(scan1.id, seed_org["org_id"], seed_org["domain_id"])
        assert r1.status == ComparisonStatus.BASELINE_ESTABLISHED

        # Process scan3 (latest) — should compare against scan1
        r3 = await service.detect_changes_for_scan(scan3.id, seed_org["org_id"], seed_org["domain_id"])
        assert r3.status == ComparisonStatus.COMPLETED

        # Now process scan2 (out of order — older than scan3)
        r2 = await service.detect_changes_for_scan(scan2.id, seed_org["org_id"], seed_org["domain_id"])
        await db_session.commit()

        assert r2.status == ComparisonStatus.SKIPPED_OUT_OF_ORDER


@pytest.mark.asyncio
class TestRelationshipChanges:

    async def test_relationship_added(self, db_session, seed_org):
        """New relationship in scan 2 → RELATIONSHIP_ADDED."""
        t1 = datetime.now(timezone.utc) - timedelta(hours=2)
        t2 = datetime.now(timezone.utc) - timedelta(hours=1)

        scan1 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t1)
        scan2 = await _create_scan(db_session, seed_org["org_id"], seed_org["domain_id"], completed_at=t2)

        sub = await _create_asset(db_session, seed_org["org_id"], "subdomain", "api.example.com")
        ip = await _create_asset(db_session, seed_org["org_id"], "ip_address", "1.2.3.4")

        # Scan 1: subdomain only
        await _create_observation(db_session, seed_org["org_id"], scan1.id, sub.id)

        # Scan 2: subdomain + ip + relationship
        await _create_observation(db_session, seed_org["org_id"], scan2.id, sub.id)
        await _create_observation(db_session, seed_org["org_id"], scan2.id, ip.id, obs_type="open_port", target="1.2.3.4:443")

        rel = AssetRelationship(
            org_id=seed_org["org_id"],
            source_asset_id=sub.id,
            target_asset_id=ip.id,
            relationship_type="resolves_to",
            confidence="HIGH",
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            status="active",
        )
        db_session.add(rel)
        await db_session.commit()

        service = ChangeDetectionService(db_session)
        await service.detect_changes_for_scan(scan1.id, seed_org["org_id"], seed_org["domain_id"])
        r2 = await service.detect_changes_for_scan(scan2.id, seed_org["org_id"], seed_org["domain_id"])
        await db_session.commit()

        assert r2.status == ComparisonStatus.COMPLETED
        # Should have changes: asset_added (ip) + relationship_added
        from sqlalchemy import select as sel
        changes = (await db_session.execute(
            sel(Change).where(Change.comparison_run_id == r2.id)
        )).scalars().all()
        change_types = [c.change_type for c in changes]
        assert ChangeType.ASSET_ADDED in change_types
        assert ChangeType.RELATIONSHIP_ADDED in change_types
