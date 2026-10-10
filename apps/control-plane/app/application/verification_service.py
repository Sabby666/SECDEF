import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.infrastructure.db.models import (
    Finding, FindingStateTransition, VerificationResult, ComparisonRun, Scan, Change, Observation, Asset
)
from app.application.audit_service import AuditService
from shared_contracts.enums import FindingLifecycleStatus, VerificationStatus, ScanCompleteness, ComparisonStatus


class VerificationService:
    """Phase 1G: Evidence-backed remediation verification service."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def verify_finding(
        self,
        org_id: str,
        finding_id: str,
        target_scan_id: Optional[str] = None,
        target_comparison_run_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> VerificationResult:
        """
        Perform deterministic, evidence-backed verification for a security finding.
        Enforces tenant isolation and scan completeness safety gating.
        """
        # 1. Tenant-scoped finding lookup
        finding_stmt = select(Finding).where(Finding.org_id == org_id, Finding.id == finding_id)
        res_finding = await self.db.execute(finding_stmt)
        finding = res_finding.scalars().first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found for organization {org_id}")

        # 2. Fetch original change record
        change_stmt = select(Change).where(Change.org_id == org_id, Change.id == finding.change_id)
        res_change = await self.db.execute(change_stmt)
        change = res_change.scalars().first()
        if not change:
            raise ValueError(f"Associated change {finding.change_id} not found for finding {finding_id}")

        # 3. Resolve target ComparisonRun or latest ComparisonRun for domain
        comparison_run = None
        if target_comparison_run_id:
            comp_stmt = select(ComparisonRun).where(
                ComparisonRun.org_id == org_id,
                ComparisonRun.id == target_comparison_run_id
            )
            res_comp = await self.db.execute(comp_stmt)
            comparison_run = res_comp.scalars().first()
        elif target_scan_id:
            comp_stmt = select(ComparisonRun).where(
                ComparisonRun.org_id == org_id,
                ComparisonRun.current_scan_id == target_scan_id
            )
            res_comp = await self.db.execute(comp_stmt)
            comparison_run = res_comp.scalars().first()
        else:
            # Fetch latest comparison run for change's comparison run domain
            orig_comp_stmt = select(ComparisonRun).where(
                ComparisonRun.org_id == org_id,
                ComparisonRun.id == change.comparison_run_id
            )
            res_orig = await self.db.execute(orig_comp_stmt)
            orig_comp = res_orig.scalars().first()
            if orig_comp:
                latest_stmt = select(ComparisonRun).where(
                    ComparisonRun.org_id == org_id,
                    ComparisonRun.domain_id == orig_comp.domain_id
                ).order_by(ComparisonRun.created_at.desc())
                res_latest = await self.db.execute(latest_stmt)
                comparison_run = res_latest.scalars().first()

        if not comparison_run:
            raise ValueError(f"No valid comparison run found for verification of finding {finding_id}")

        # Idempotency check: check if verification already executed for (org_id, finding_id, comparison_run.id)
        existing_ver_stmt = select(VerificationResult).where(
            VerificationResult.org_id == org_id,
            VerificationResult.finding_id == finding_id,
            VerificationResult.comparison_run_id == comparison_run.id
        )
        res_existing = await self.db.execute(existing_ver_stmt)
        existing_ver = res_existing.scalars().first()
        if existing_ver:
            return existing_ver

        # 4. Fetch current Scan
        current_scan_stmt = select(Scan).where(Scan.org_id == org_id, Scan.id == comparison_run.current_scan_id)
        res_scan = await self.db.execute(current_scan_stmt)
        current_scan = res_scan.scalars().first()
        if not current_scan:
            raise ValueError(f"Current scan {comparison_run.current_scan_id} not found")

        AuditService.log_event(
            db_session=self.db,
            event_type="verification.started",
            resource_type="finding",
            resource_id=finding.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"comparison_run_id": comparison_run.id, "scan_id": current_scan.id}
        )

        # 5. Temporal Safety Check: Stale scan protection
        # Target scan must not be older than the finding creation scan
        def ensure_utc(dt):
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)

        if ensure_utc(current_scan.created_at) < ensure_utc(change.detected_at):
            ver_result = VerificationResult(
                id=str(uuid.uuid4()),
                org_id=org_id,
                finding_id=finding.id,
                comparison_run_id=comparison_run.id,
                current_scan_id=current_scan.id,
                status=VerificationStatus.UNKNOWN.value,
                method="scan_observation_comparison",
                previous_observed_state=change.previous_state,
                current_observed_state=change.current_state,
                evidence={"reason": "Stale scan: target scan created before finding detection timestamp"},
                verified_at=datetime.now(timezone.utc)
            )
            self.db.add(ver_result)
            await self.db.flush()
            return ver_result

        # 6. Safety Gating: Completeness check
        # Incomplete, partial, or failed scans CANNOT produce RESOLVED verdict!
        completeness = comparison_run.current_scan_completeness.lower()
        if current_scan.status != "completed" or completeness not in [ScanCompleteness.COMPLETE.value, "complete"]:
            ver_result = VerificationResult(
                id=str(uuid.uuid4()),
                org_id=org_id,
                finding_id=finding.id,
                comparison_run_id=comparison_run.id,
                current_scan_id=current_scan.id,
                status=VerificationStatus.INCOMPLETE.value,
                method="scan_observation_comparison",
                previous_observed_state=change.previous_state,
                current_observed_state=change.current_state,
                evidence={
                    "reason": "Scan coverage incomplete or scan failed. Verification cannot guarantee resolution.",
                    "scan_status": current_scan.status,
                    "completeness": comparison_run.current_scan_completeness
                },
                verified_at=datetime.now(timezone.utc)
            )
            self.db.add(ver_result)

            AuditService.log_event(
                db_session=self.db,
                event_type="verification.incomplete",
                resource_type="finding",
                resource_id=finding.id,
                org_id=org_id,
                actor_id=actor_id,
                ip_address=ip_address,
                details={"reason": "Scan incomplete", "completeness": comparison_run.current_scan_completeness}
            )

            await self.db.flush()
            return ver_result

        # 7. Evidence-backed verification evaluation
        # Check observations from target current scan for entity_identifier
        obs_stmt = select(Observation).where(
            Observation.org_id == org_id,
            Observation.scan_id == current_scan.id,
            Observation.target == change.entity_identifier
        )
        res_obs = await self.db.execute(obs_stmt)
        matching_obs = res_obs.scalars().all()

        current_evidence: Dict[str, Any] = {
            "observation_count": len(matching_obs),
            "entity_identifier": change.entity_identifier,
            "change_type": change.change_type
        }

        # Check if condition is still present vs resolved
        is_resolved = False
        if change.change_type in ["asset_added", "relationship_added", "asset_property_changed"]:
            # If entity is no longer observed in fresh complete scan -> RESOLVED
            is_resolved = (len(matching_obs) == 0)
        elif change.change_type in ["asset_removed", "relationship_removed"]:
            # If removal condition was previously detected and now entity is re-observed -> returned / STILL_PRESENT
            is_resolved = (len(matching_obs) > 0)
        else:
            is_resolved = (len(matching_obs) == 0)

        ver_status = VerificationStatus.RESOLVED.value if is_resolved else VerificationStatus.STILL_PRESENT.value

        ver_result = VerificationResult(
            id=str(uuid.uuid4()),
            org_id=org_id,
            finding_id=finding.id,
            comparison_run_id=comparison_run.id,
            current_scan_id=current_scan.id,
            status=ver_status,
            method="scan_observation_comparison",
            previous_observed_state=change.previous_state,
            current_observed_state={"matching_observations": len(matching_obs)},
            evidence=current_evidence,
            verified_at=datetime.now(timezone.utc)
        )
        self.db.add(ver_result)

        # 8. State transition side-effects on Finding
        old_status = finding.status
        if ver_status == VerificationStatus.RESOLVED.value:
            finding.status = FindingLifecycleStatus.RESOLVED.value
            finding.resolved_at = datetime.now(timezone.utc)
            finding.updated_at = datetime.now(timezone.utc)

            transition = FindingStateTransition(
                id=str(uuid.uuid4()),
                org_id=org_id,
                finding_id=finding.id,
                actor_id=actor_id,
                from_status=old_status,
                to_status=FindingLifecycleStatus.RESOLVED.value,
                reason="Fresh scan evidence verified that condition is no longer present.",
                evidence_snapshot=current_evidence,
                created_at=datetime.now(timezone.utc)
            )
            self.db.add(transition)

            AuditService.log_event(
                db_session=self.db,
                event_type="finding.resolved",
                resource_type="finding",
                resource_id=finding.id,
                org_id=org_id,
                actor_id=actor_id,
                ip_address=ip_address,
                details={"verdict": "RESOLVED", "scan_id": current_scan.id}
            )

        elif ver_status == VerificationStatus.STILL_PRESENT.value and old_status == FindingLifecycleStatus.RESOLVED.value:
            # Reopen previously resolved finding if condition returns!
            finding.status = FindingLifecycleStatus.REOPENED.value
            finding.reopened_at = datetime.now(timezone.utc)
            finding.updated_at = datetime.now(timezone.utc)

            transition = FindingStateTransition(
                id=str(uuid.uuid4()),
                org_id=org_id,
                finding_id=finding.id,
                actor_id=actor_id,
                from_status=old_status,
                to_status=FindingLifecycleStatus.REOPENED.value,
                reason="Previously resolved condition observed again in fresh scan.",
                evidence_snapshot=current_evidence,
                created_at=datetime.now(timezone.utc)
            )
            self.db.add(transition)

            AuditService.log_event(
                db_session=self.db,
                event_type="finding.reopened",
                resource_type="finding",
                resource_id=finding.id,
                org_id=org_id,
                actor_id=actor_id,
                ip_address=ip_address,
                details={"verdict": "REOPENED", "scan_id": current_scan.id}
            )

        AuditService.log_event(
            db_session=self.db,
            event_type="verification.completed",
            resource_type="finding",
            resource_id=finding.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"verification_status": ver_status, "scan_id": current_scan.id}
        )

        await self.db.flush()
        return ver_result
