"""Phase 1D: Deterministic scan-over-scan change detection service.

This service implements the COMPARE → DETECT portion of the ASM product loop.

CRITICAL SECURITY PRINCIPLES:
1. A missing observation is NOT automatically a removal.
2. Absence can only become removal when scan completeness is validated.
3. All comparisons are tenant-isolated (org_id scoped).
4. Change detection is deterministic and reproducible.
5. First scan establishes baseline — no false "added" changes.
6. Out-of-order scans are handled safely via temporal ordering.
7. Processing is idempotent — same scan twice produces identical results.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.infrastructure.db.models import (
    Asset, AssetRelationship, ComparisonRun, Change, Observation, Scan,
)
from shared_contracts.enums import (
    ChangeType, ComparisonStatus, ScanCompleteness,
)

logger = logging.getLogger(__name__)


# Observation types that discover each asset type.
# Used to verify whether the observation class was executed before
# concluding that absence means removal.
ASSET_TYPE_OBSERVATION_CLASSES: Dict[str, Set[str]] = {
    "subdomain": {"dns_record"},
    "ip_address": {"dns_record", "open_port"},
    "service": {"open_port", "http_banner", "tls_cert"},
    "certificate": {"tls_cert"},
}


def _assess_scan_completeness(scan: Scan) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Assess scan completeness from status and scan_metadata.

    Returns:
        (completeness_level, completeness_details)
    """
    if scan.status == "failed":
        return ScanCompleteness.FAILED, {"reason": "scan_failed"}

    metadata = scan.scan_metadata or {}
    obs_classes = metadata.get("observation_classes")

    if scan.status == "completed" and obs_classes is None:
        # Legacy scan without per-class tracking — assume complete
        return ScanCompleteness.COMPLETE, {"reason": "status_completed_no_class_data"}

    if scan.status == "completed" and obs_classes is not None:
        # Check if all classes succeeded
        failed_classes = {k: v for k, v in obs_classes.items() if v != "completed"}
        if not failed_classes:
            return ScanCompleteness.COMPLETE, {"observation_classes": obs_classes}
        else:
            return ScanCompleteness.PARTIAL, {
                "observation_classes": obs_classes,
                "failed_classes": list(failed_classes.keys()),
            }

    if scan.status == "partial":
        return ScanCompleteness.PARTIAL, {
            "reason": "scan_status_partial",
            "observation_classes": obs_classes,
        }

    return ScanCompleteness.UNKNOWN, {"reason": f"unrecognized_status_{scan.status}"}


def _can_declare_removal(
    asset_type: str,
    completeness: str,
    completeness_details: Optional[Dict[str, Any]],
) -> bool:
    """Determine whether absence of an asset type can be declared as removal.

    This is the HARD SECURITY GATE: a missing observation is NOT automatically
    a removal unless the relevant observation class was successfully completed.

    Args:
        asset_type: The type of asset that is absent
        completeness: The overall scan completeness level
        completeness_details: Per-observation-class results

    Returns:
        True only if it is safe to declare this asset type as removed.
    """
    if completeness == ScanCompleteness.FAILED:
        return False

    if completeness == ScanCompleteness.UNKNOWN:
        return False

    if completeness == ScanCompleteness.COMPLETE:
        return True

    # PARTIAL completeness — check per-class data
    if completeness_details is None:
        return False

    obs_classes = completeness_details.get("observation_classes")
    if obs_classes is None:
        return False

    # Get the observation classes that would detect this asset type
    required_classes = ASSET_TYPE_OBSERVATION_CLASSES.get(asset_type, set())
    if not required_classes:
        return False

    # ALL required observation classes must have completed successfully
    for cls in required_classes:
        if obs_classes.get(cls) != "completed":
            return False

    return True


def _build_asset_state(asset: Asset, observation: Optional[Observation] = None) -> Dict[str, Any]:
    """Build a deterministic state snapshot of an asset for comparison."""
    state = {
        "asset_type": asset.asset_type,
        "identifier": asset.identifier,
        "status": asset.status,
        "environment": asset.environment,
        "criticality": asset.criticality,
    }
    if observation and observation.raw_data:
        state["raw_data"] = observation.raw_data
    return state


def _build_relationship_identifier(
    source_type: str, source_id: str,
    target_type: str, target_id: str,
    rel_type: str,
) -> str:
    """Build a canonical deterministic identifier for a relationship edge."""
    return f"{source_type}:{source_id}|{rel_type}|{target_type}:{target_id}"


class ChangeDetectionService:
    """Deterministic, tenant-isolated, scan-over-scan change detection.

    Comparison Model:
    - Comparable scan: A scan with status 'completed' or 'partial', scoped to
      the same (org_id, domain_id).
    - Previous scan: The most recent comparable scan with completed_at before
      the current scan's completed_at. Ordered by completed_at, NOT by arrival.
    - Comparison scope: All assets/relationships linked via observations to
      the given scan within the tenant.

    Completeness Semantics:
    - Scan completeness is derived from scan.status + scan.scan_metadata.
    - Removal is only declared when the relevant observation class completed.

    First Scan Semantics:
    - If no previous comparable scan exists, status is BASELINE_ESTABLISHED.
    - No ASSET_ADDED changes are emitted for the first scan.

    Idempotency:
    - Unique constraint (org_id, domain_id, current_scan_id) on ComparisonRun
      prevents duplicate processing.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def detect_changes_for_scan(
        self,
        scan_id: str,
        org_id: str,
        domain_id: str,
    ) -> ComparisonRun:
        """Execute deterministic change detection for a completed scan.

        All operations are tenant-isolated via org_id.
        Processing is idempotent: if a ComparisonRun already exists for this
        scan, the existing record is returned without reprocessing.

        Args:
            scan_id: The current scan to compare
            org_id: Tenant organization ID (isolation boundary)
            domain_id: Domain scope for comparison

        Returns:
            ComparisonRun record with detection results
        """
        now = datetime.now(timezone.utc)

        # 1. TENANT ISOLATION: Validate scan belongs to org_id
        current_scan = await self._get_scan_with_tenant_check(scan_id, org_id)
        if current_scan is None:
            raise ValueError(
                f"Scan {scan_id} not found or does not belong to org {org_id}"
            )

        # 2. IDEMPOTENCY: Check if comparison already exists
        existing = await self._get_existing_comparison(org_id, domain_id, scan_id)
        if existing is not None:
            logger.info(
                "change_detection_idempotent_skip",
                extra={
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "comparison_run_id": existing.id,
                },
            )
            return existing

        # 3. COMPLETENESS ASSESSMENT
        completeness, completeness_details = _assess_scan_completeness(current_scan)

        if completeness == ScanCompleteness.FAILED:
            return await self._create_comparison_run(
                org_id=org_id,
                domain_id=domain_id,
                current_scan_id=scan_id,
                previous_scan_id=None,
                status=ComparisonStatus.SKIPPED_INCOMPLETE,
                completeness=completeness,
                completeness_details=completeness_details,
                changes_detected=0,
                now=now,
            )

        # 4. FIND PREVIOUS COMPARABLE SCAN
        previous_scan = await self._find_previous_scan(
            org_id, domain_id, current_scan
        )

        # 5. FIRST SCAN: No previous baseline
        if previous_scan is None:
            return await self._create_comparison_run(
                org_id=org_id,
                domain_id=domain_id,
                current_scan_id=scan_id,
                previous_scan_id=None,
                status=ComparisonStatus.BASELINE_ESTABLISHED,
                completeness=completeness,
                completeness_details=completeness_details,
                changes_detected=0,
                now=now,
            )

        # 6. TEMPORAL ORDERING: Check for out-of-order scans
        latest_comparison = await self._get_latest_comparison(org_id, domain_id)
        if latest_comparison is not None:
            # Check if the current scan is temporally older than the latest
            # already-compared scan
            latest_compared_scan = await self._get_scan_with_tenant_check(
                latest_comparison.current_scan_id, org_id
            )
            if (
                latest_compared_scan is not None
                and latest_compared_scan.completed_at is not None
                and current_scan.completed_at is not None
                and current_scan.completed_at < latest_compared_scan.completed_at
                and latest_comparison.status
                in (ComparisonStatus.COMPLETED, ComparisonStatus.BASELINE_ESTABLISHED)
            ):
                return await self._create_comparison_run(
                    org_id=org_id,
                    domain_id=domain_id,
                    current_scan_id=scan_id,
                    previous_scan_id=previous_scan.id,
                    status=ComparisonStatus.SKIPPED_OUT_OF_ORDER,
                    completeness=completeness,
                    completeness_details=completeness_details,
                    changes_detected=0,
                    now=now,
                )

        # 7. PERFORM COMPARISON
        changes = await self._compare_scans(
            org_id=org_id,
            domain_id=domain_id,
            current_scan=current_scan,
            previous_scan=previous_scan,
            completeness=completeness,
            completeness_details=completeness_details,
            now=now,
        )

        # 8. PERSIST COMPARISON RUN AND CHANGES
        comparison_run = await self._create_comparison_run(
            org_id=org_id,
            domain_id=domain_id,
            current_scan_id=scan_id,
            previous_scan_id=previous_scan.id,
            status=ComparisonStatus.COMPLETED,
            completeness=completeness,
            completeness_details=completeness_details,
            changes_detected=len(changes),
            now=now,
        )

        # Persist individual changes
        for change_data in changes:
            change = Change(
                org_id=org_id,
                comparison_run_id=comparison_run.id,
                asset_id=change_data.get("asset_id"),
                change_type=change_data["change_type"],
                entity_type=change_data["entity_type"],
                entity_identifier=change_data["entity_identifier"],
                previous_state=change_data.get("previous_state"),
                current_state=change_data.get("current_state"),
                previous_scan_id=previous_scan.id,
                current_scan_id=scan_id,
                evidence=change_data.get("evidence"),
                detected_at=now,
            )
            self.db.add(change)

        comparison_run.changes_detected = len(changes)

        logger.info(
            "change_detection_completed",
            extra={
                "scan_id": scan_id,
                "org_id": org_id,
                "domain_id": domain_id,
                "comparison_run_id": comparison_run.id,
                "previous_scan_id": previous_scan.id,
                "changes_detected": len(changes),
                "completeness": completeness,
            },
        )

        return comparison_run

    async def _compare_scans(
        self,
        org_id: str,
        domain_id: str,
        current_scan: Scan,
        previous_scan: Scan,
        completeness: str,
        completeness_details: Optional[Dict[str, Any]],
        now: datetime,
    ) -> List[Dict[str, Any]]:
        """Compare two scans and produce deterministic change records.

        Returns a list of change data dicts (not yet persisted).
        """
        changes: List[Dict[str, Any]] = []

        # Collect assets observed in each scan
        current_assets = await self._get_assets_for_scan(org_id, current_scan.id)
        previous_assets = await self._get_assets_for_scan(org_id, previous_scan.id)

        # Build lookup maps by canonical identity: (asset_type, identifier)
        current_map: Dict[Tuple[str, str], Tuple[Asset, Optional[Observation]]] = {}
        for asset, obs in current_assets:
            key = (asset.asset_type, asset.identifier)
            if key not in current_map:
                current_map[key] = (asset, obs)

        previous_map: Dict[Tuple[str, str], Tuple[Asset, Optional[Observation]]] = {}
        for asset, obs in previous_assets:
            key = (asset.asset_type, asset.identifier)
            if key not in previous_map:
                previous_map[key] = (asset, obs)

        current_keys = set(current_map.keys())
        previous_keys = set(previous_map.keys())

        # ASSET_ADDED: present in current, absent in previous
        for key in sorted(current_keys - previous_keys):
            asset, obs = current_map[key]
            changes.append({
                "change_type": ChangeType.ASSET_ADDED,
                "entity_type": "asset",
                "entity_identifier": f"{key[0]}:{key[1]}",
                "asset_id": asset.id,
                "previous_state": None,
                "current_state": _build_asset_state(asset, obs),
                "evidence": {
                    "reason": "asset_observed_in_current_scan_not_in_previous",
                    "current_scan_id": current_scan.id,
                    "previous_scan_id": previous_scan.id,
                },
            })

        # ASSET_REMOVED: present in previous, absent in current
        # HARD SECURITY GATE: Only if completeness allows
        for key in sorted(previous_keys - current_keys):
            asset, obs = previous_map[key]
            asset_type = key[0]

            if _can_declare_removal(asset_type, completeness, completeness_details):
                changes.append({
                    "change_type": ChangeType.ASSET_REMOVED,
                    "entity_type": "asset",
                    "entity_identifier": f"{key[0]}:{key[1]}",
                    "asset_id": asset.id,
                    "previous_state": _build_asset_state(asset, obs),
                    "current_state": None,
                    "evidence": {
                        "reason": "asset_absent_in_current_scan_with_valid_completeness",
                        "current_scan_id": current_scan.id,
                        "previous_scan_id": previous_scan.id,
                        "completeness": completeness,
                        "asset_type": asset_type,
                    },
                })
            else:
                logger.info(
                    "change_detection_removal_suppressed",
                    extra={
                        "org_id": org_id,
                        "scan_id": current_scan.id,
                        "asset_identifier": key[1],
                        "asset_type": asset_type,
                        "completeness": completeness,
                        "reason": "insufficient_completeness_for_removal",
                    },
                )

        # ASSET_PROPERTY_CHANGED: present in both, observable properties differ
        for key in sorted(current_keys & previous_keys):
            curr_asset, curr_obs = current_map[key]
            prev_asset, prev_obs = previous_map[key]

            prev_state = _build_asset_state(prev_asset, prev_obs)
            curr_state = _build_asset_state(curr_asset, curr_obs)

            if prev_state != curr_state:
                # Compute property diff
                diff = {}
                all_prop_keys = set(prev_state.keys()) | set(curr_state.keys())
                for prop_key in all_prop_keys:
                    if prev_state.get(prop_key) != curr_state.get(prop_key):
                        diff[prop_key] = {
                            "previous": prev_state.get(prop_key),
                            "current": curr_state.get(prop_key),
                        }

                changes.append({
                    "change_type": ChangeType.ASSET_PROPERTY_CHANGED,
                    "entity_type": "asset",
                    "entity_identifier": f"{key[0]}:{key[1]}",
                    "asset_id": curr_asset.id,
                    "previous_state": prev_state,
                    "current_state": curr_state,
                    "evidence": {
                        "reason": "asset_properties_changed",
                        "changed_properties": diff,
                        "current_scan_id": current_scan.id,
                        "previous_scan_id": previous_scan.id,
                    },
                })

        # RELATIONSHIP CHANGES
        rel_changes = await self._compare_relationships(
            org_id=org_id,
            current_scan=current_scan,
            previous_scan=previous_scan,
            completeness=completeness,
            completeness_details=completeness_details,
        )
        changes.extend(rel_changes)

        return changes

    async def _compare_relationships(
        self,
        org_id: str,
        current_scan: Scan,
        previous_scan: Scan,
        completeness: str,
        completeness_details: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Compare relationship edges between two scans.

        Relationships are identified by their canonical edge identity:
        (source_asset_type:source_identifier, relationship_type, target_asset_type:target_identifier)
        """
        changes: List[Dict[str, Any]] = []

        current_rels = await self._get_relationships_for_scan(org_id, current_scan.id)
        previous_rels = await self._get_relationships_for_scan(org_id, previous_scan.id)

        # Build maps by canonical relationship identity
        def _rel_key(rel: dict) -> str:
            return _build_relationship_identifier(
                rel["source_asset_type"], rel["source_identifier"],
                rel["target_asset_type"], rel["target_identifier"],
                rel["relationship_type"],
            )

        current_rel_map = {_rel_key(r): r for r in current_rels}
        previous_rel_map = {_rel_key(r): r for r in previous_rels}

        current_rel_keys = set(current_rel_map.keys())
        previous_rel_keys = set(previous_rel_map.keys())

        # RELATIONSHIP_ADDED
        for key in sorted(current_rel_keys - previous_rel_keys):
            rel = current_rel_map[key]
            changes.append({
                "change_type": ChangeType.RELATIONSHIP_ADDED,
                "entity_type": "relationship",
                "entity_identifier": key,
                "asset_id": None,
                "previous_state": None,
                "current_state": {
                    "source": f"{rel['source_asset_type']}:{rel['source_identifier']}",
                    "target": f"{rel['target_asset_type']}:{rel['target_identifier']}",
                    "relationship_type": rel["relationship_type"],
                },
                "evidence": {
                    "reason": "relationship_observed_in_current_scan_not_in_previous",
                    "current_scan_id": current_scan.id,
                    "previous_scan_id": previous_scan.id,
                },
            })

        # RELATIONSHIP_REMOVED — with completeness gate
        for key in sorted(previous_rel_keys - current_rel_keys):
            rel = previous_rel_map[key]
            # For relationship removals, check if both endpoint asset types'
            # observation classes completed
            source_removable = _can_declare_removal(
                rel["source_asset_type"], completeness, completeness_details
            )
            target_removable = _can_declare_removal(
                rel["target_asset_type"], completeness, completeness_details
            )

            if source_removable and target_removable:
                changes.append({
                    "change_type": ChangeType.RELATIONSHIP_REMOVED,
                    "entity_type": "relationship",
                    "entity_identifier": key,
                    "asset_id": None,
                    "previous_state": {
                        "source": f"{rel['source_asset_type']}:{rel['source_identifier']}",
                        "target": f"{rel['target_asset_type']}:{rel['target_identifier']}",
                        "relationship_type": rel["relationship_type"],
                    },
                    "current_state": None,
                    "evidence": {
                        "reason": "relationship_absent_in_current_scan_with_valid_completeness",
                        "current_scan_id": current_scan.id,
                        "previous_scan_id": previous_scan.id,
                        "completeness": completeness,
                    },
                })

        return changes

    # ── Data access methods (all tenant-isolated) ──

    async def _get_scan_with_tenant_check(
        self, scan_id: str, org_id: str
    ) -> Optional[Scan]:
        """Fetch scan with explicit tenant isolation."""
        result = await self.db.execute(
            select(Scan).where(
                and_(Scan.id == scan_id, Scan.org_id == org_id)
            )
        )
        return result.scalars().first()

    async def _get_existing_comparison(
        self, org_id: str, domain_id: str, current_scan_id: str
    ) -> Optional[ComparisonRun]:
        """Check for existing comparison (idempotency)."""
        result = await self.db.execute(
            select(ComparisonRun).where(
                and_(
                    ComparisonRun.org_id == org_id,
                    ComparisonRun.domain_id == domain_id,
                    ComparisonRun.current_scan_id == current_scan_id,
                )
            )
        )
        return result.scalars().first()

    async def _find_previous_scan(
        self, org_id: str, domain_id: str, current_scan: Scan
    ) -> Optional[Scan]:
        """Find the most recent comparable scan before the current one.

        Uses completed_at for temporal ordering, NOT ingestion order.
        Only considers scans with status 'completed' or 'partial'.
        """
        if current_scan.completed_at is None:
            return None

        result = await self.db.execute(
            select(Scan)
            .where(
                and_(
                    Scan.org_id == org_id,
                    Scan.domain_id == domain_id,
                    Scan.id != current_scan.id,
                    Scan.status.in_(["completed", "partial"]),
                    Scan.completed_at.isnot(None),
                    Scan.completed_at < current_scan.completed_at,
                )
            )
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
        return result.scalars().first()

    async def _get_latest_comparison(
        self, org_id: str, domain_id: str
    ) -> Optional[ComparisonRun]:
        """Get the most recent completed comparison for temporal ordering check."""
        result = await self.db.execute(
            select(ComparisonRun)
            .where(
                and_(
                    ComparisonRun.org_id == org_id,
                    ComparisonRun.domain_id == domain_id,
                    ComparisonRun.status.in_([
                        ComparisonStatus.COMPLETED,
                        ComparisonStatus.BASELINE_ESTABLISHED,
                    ]),
                )
            )
            .order_by(ComparisonRun.created_at.desc())
            .limit(1)
        )
        return result.scalars().first()

    async def _get_assets_for_scan(
        self, org_id: str, scan_id: str
    ) -> List[Tuple[Asset, Optional[Observation]]]:
        """Get all assets observed in a specific scan (via observation linkage).

        This provides scan-scoped comparison with clear provenance.
        Returns tuples of (Asset, Observation) so observed raw_data is available.
        """
        result = await self.db.execute(
            select(Asset, Observation)
            .join(Observation, Observation.asset_id == Asset.id)
            .where(
                and_(
                    Observation.scan_id == scan_id,
                    Observation.org_id == org_id,
                    Asset.org_id == org_id,
                )
            )
        )
        items = []
        for row in result.all():
            items.append((row[0], row[1]))
        return items

    async def _get_relationships_for_scan(
        self, org_id: str, scan_id: str
    ) -> List[Dict[str, Any]]:
        """Get relationship data for assets observed in a specific scan.

        Returns dicts with canonical identity info for comparison.
        Relationships are included if BOTH source and target assets have
        observations in the given scan.
        """
        # Get asset IDs observed in this scan
        asset_result = await self.db.execute(
            select(Observation.asset_id)
            .where(
                and_(
                    Observation.scan_id == scan_id,
                    Observation.org_id == org_id,
                    Observation.asset_id.isnot(None),
                )
            )
            .distinct()
        )
        scan_asset_ids = set(row[0] for row in asset_result.fetchall())

        if not scan_asset_ids:
            return []

        # Get relationships where BOTH endpoints are in the scan's asset set
        rel_result = await self.db.execute(
            select(AssetRelationship)
            .where(
                and_(
                    AssetRelationship.org_id == org_id,
                    AssetRelationship.source_asset_id.in_(scan_asset_ids),
                    AssetRelationship.target_asset_id.in_(scan_asset_ids),
                )
            )
        )
        relationships = rel_result.scalars().all()

        # Resolve asset identities for canonical comparison
        result = []
        for rel in relationships:
            source = await self._get_asset_by_id(org_id, rel.source_asset_id)
            target = await self._get_asset_by_id(org_id, rel.target_asset_id)
            if source and target:
                result.append({
                    "relationship_id": rel.id,
                    "source_asset_type": source.asset_type,
                    "source_identifier": source.identifier,
                    "target_asset_type": target.asset_type,
                    "target_identifier": target.identifier,
                    "relationship_type": rel.relationship_type,
                })

        return result

    async def _get_asset_by_id(
        self, org_id: str, asset_id: str
    ) -> Optional[Asset]:
        """Get a single asset with tenant isolation."""
        result = await self.db.execute(
            select(Asset).where(
                and_(Asset.id == asset_id, Asset.org_id == org_id)
            )
        )
        return result.scalars().first()

    async def _create_comparison_run(
        self,
        org_id: str,
        domain_id: str,
        current_scan_id: str,
        previous_scan_id: Optional[str],
        status: str,
        completeness: str,
        completeness_details: Optional[Dict[str, Any]],
        changes_detected: int,
        now: datetime,
    ) -> ComparisonRun:
        """Create a ComparisonRun record."""
        import uuid
        comparison_run = ComparisonRun(
            id=str(uuid.uuid4()),
            org_id=org_id,
            domain_id=domain_id,
            current_scan_id=current_scan_id,
            previous_scan_id=previous_scan_id,
            status=status,
            current_scan_completeness=completeness,
            completeness_details=completeness_details,
            changes_detected=changes_detected,
            comparison_metadata={
                "detection_version": "1.0",
                "detected_at": now.isoformat(),
            },
            created_at=now,
        )
        self.db.add(comparison_run)
        await self.db.flush()
        return comparison_run
