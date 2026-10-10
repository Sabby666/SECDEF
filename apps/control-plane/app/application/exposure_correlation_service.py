"""Phase 3 Exposure Correlation Engine Service.

Executes ExposureCorrelationRule v1 to evaluate authoritative inputs from Phase 1
(Asset Graph, Relationships, Changes, Context, Risk, Findings) and Phase 2
(Discovery Candidates & Provenance), producing derived ExposureCondition and ExposurePath records.
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from sqlalchemy.exc import IntegrityError
from app.infrastructure.db.models import (
    generate_uuid, Asset, AssetRelationship, Change, AssetContext, RiskAssessment, Finding,
    DiscoveryCandidate, DiscoveryEvidence, ExposureCorrelationRun, ExposureCondition,
    ExposureConditionEvidence
)


from app.application.exposure_graph_service import ExposureGraphService
from app.application.notification_service import NotificationService
from shared_contracts.enums import (
    ExposureConditionType, ExposureConditionStatus, ExposurePriorityBand,
    ExposureCorrelationRunStatus, NotificationTriggerType, FindingLifecycleStatus,
    RiskBand, Environment, Criticality
)

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExposureCorrelationService:
    """Deterministic correlation engine executing ExposureCorrelationRule v1."""

    RULE_VERSION: str = "v1"

    def __init__(self, db: AsyncSession):
        self.db = db
        self.graph_service = ExposureGraphService(db)

    async def run_exposure_correlation(self, org_id: str) -> ExposureCorrelationRun:
        """Run complete exposure correlation pipeline for an organization."""
        run = ExposureCorrelationRun(
            org_id=org_id,
            rule_version=self.RULE_VERSION,
            status=ExposureCorrelationRunStatus.RUNNING.value,
            started_at=utc_now(),
        )
        self.db.add(run)
        await self.db.flush()

        try:
            detected_conditions = await self._evaluate_correlation_rules(org_id, run.id)
            
            # Generate exposure paths for all active/reopened conditions
            path_count = 0
            for cond in detected_conditions:
                paths = await self.graph_service.find_exposure_paths(org_id, cond)
                path_count += len(paths)

            run.status = ExposureCorrelationRunStatus.COMPLETED.value
            run.completed_at = utc_now()
            run.conditions_detected = len(detected_conditions)
            run.paths_detected = path_count
            await self.db.commit()
            return run
        except Exception as exc:
            logger.exception("Exposure correlation run failed for org %s", org_id)
            run.status = ExposureCorrelationRunStatus.FAILED.value
            run.completed_at = utc_now()
            run.error_message = str(exc)
            await self.db.commit()
            raise

    async def _evaluate_correlation_rules(self, org_id: str, run_id: str) -> List[ExposureCondition]:
        """Evaluate deterministic rules against org assets, changes, risk, findings, context, discovery."""
        # 1. Fetch active assets for tenant
        asset_stmt = select(Asset).where(Asset.org_id == org_id, Asset.status == "active")
        asset_res = await self.db.execute(asset_stmt)
        assets = asset_res.scalars().all()

        # 2. Fetch contexts for tenant
        ctx_stmt = select(AssetContext).where(AssetContext.org_id == org_id)
        ctx_res = await self.db.execute(ctx_stmt)
        contexts_by_asset = {c.asset_id: c for c in ctx_res.scalars().all()}

        # 3. Fetch latest risk assessments for tenant
        risk_stmt = select(RiskAssessment).where(RiskAssessment.org_id == org_id)
        risk_res = await self.db.execute(risk_stmt)
        risks_by_asset = {r.asset_id: r for r in risk_res.scalars().all() if r.asset_id}

        # 4. Fetch open findings for tenant
        finding_stmt = select(Finding).where(
            Finding.org_id == org_id,
            Finding.status.in_([FindingLifecycleStatus.OPEN.value, FindingLifecycleStatus.REOPENED.value])
        )
        finding_res = await self.db.execute(finding_stmt)
        findings_by_asset = {f.asset_id: f for f in finding_res.scalars().all() if f.asset_id}

        # 5. Fetch recent changes for tenant
        change_stmt = select(Change).where(Change.org_id == org_id)
        change_res = await self.db.execute(change_stmt)
        changes_by_asset = {c.asset_id: c for c in change_res.scalars().all() if c.asset_id}

        # 6. Fetch promoted discovery candidates for tenant
        disc_stmt = select(DiscoveryCandidate).where(
            DiscoveryCandidate.org_id == org_id,
            DiscoveryCandidate.promoted_asset_id.isnot(None)
        )
        disc_res = await self.db.execute(disc_stmt)
        disc_by_asset = {dc.promoted_asset_id: dc for dc in disc_res.scalars().all() if dc.promoted_asset_id}

        detected_conditions: List[ExposureCondition] = []

        for asset in assets:
            ctx = contexts_by_asset.get(asset.id)
            risk = risks_by_asset.get(asset.id)
            finding = findings_by_asset.get(asset.id)
            change = changes_by_asset.get(asset.id)
            disc_cand = disc_by_asset.get(asset.id)

            # Rule 1: INTERNET_FACING_SERVICE
            if asset.asset_type in ["service", "ip_address"]:
                cond = await self._upsert_condition(
                    org_id=org_id,
                    condition_type=ExposureConditionType.INTERNET_FACING_SERVICE.value,
                    primary_asset=asset,
                    priority=ExposurePriorityBand.MEDIUM_EXPOSURE.value,
                    title=f"Internet-Facing {asset.asset_type.capitalize()}: {asset.identifier}",
                    description=f"Asset {asset.identifier} is externally reachable on the public network.",
                    explanation=f"Asset {asset.identifier} of type {asset.asset_type} is active and internet-accessible.",
                    risk_assessment=risk,
                    finding=finding,
                    change=change,
                    disc_cand=disc_cand
                )
                detected_conditions.append(cond)

            # Rule 2: UNEXPECTED_EXPOSED_SERVICE
            if ctx and ctx.expected_exposure and ctx.expected_exposure.upper() == "UNEXPECTED":
                cond = await self._upsert_condition(
                    org_id=org_id,
                    condition_type=ExposureConditionType.UNEXPECTED_EXPOSED_SERVICE.value,
                    primary_asset=asset,
                    priority=ExposurePriorityBand.HIGH_EXPOSURE.value,
                    title=f"Unexpected Exposed Service: {asset.identifier}",
                    description=f"Asset {asset.identifier} is exposed but designated UNEXPECTED by organizational context.",
                    explanation=f"Asset {asset.identifier} has expected_exposure='UNEXPECTED' in organizational context.",
                    risk_assessment=risk,
                    finding=finding,
                    change=change,
                    disc_cand=disc_cand
                )
                detected_conditions.append(cond)

            # Rule 3: NEWLY_EXPOSED_SERVICE
            if change and change.change_type == "asset_added":
                cond = await self._upsert_condition(
                    org_id=org_id,
                    condition_type=ExposureConditionType.NEWLY_EXPOSED_SERVICE.value,
                    primary_asset=asset,
                    priority=ExposurePriorityBand.MEDIUM_EXPOSURE.value,
                    title=f"Newly Exposed Service: {asset.identifier}",
                    description=f"Asset {asset.identifier} was newly added in a recent observation scan.",
                    explanation=f"Asset {asset.identifier} created via scan change {change.id}.",
                    risk_assessment=risk,
                    finding=finding,
                    change=change,
                    disc_cand=disc_cand
                )
                detected_conditions.append(cond)

            # Rule 4: EXTERNALLY_REACHABLE_PRODUCTION_ASSET
            if asset.environment == Environment.PRODUCTION.value or (ctx and ctx.environment == Environment.PRODUCTION.value):
                cond = await self._upsert_condition(
                    org_id=org_id,
                    condition_type=ExposureConditionType.EXTERNALLY_REACHABLE_PRODUCTION_ASSET.value,
                    primary_asset=asset,
                    priority=ExposurePriorityBand.HIGH_EXPOSURE.value,
                    title=f"Externally Reachable Production Asset: {asset.identifier}",
                    description=f"Production asset {asset.identifier} is exposed externally to the public network.",
                    explanation=f"Asset {asset.identifier} belongs to environment 'production' and is reachable.",
                    risk_assessment=risk,
                    finding=finding,
                    change=change,
                    disc_cand=disc_cand
                )
                detected_conditions.append(cond)

            # Rule 5: EXTERNALLY_REACHABLE_HIGH_CRITICALITY
            if asset.criticality in [Criticality.CRITICAL.value, Criticality.HIGH.value] or (ctx and ctx.criticality in [Criticality.CRITICAL.value, Criticality.HIGH.value]):
                priority = ExposurePriorityBand.CRITICAL_EXPOSURE.value if (asset.criticality == Criticality.CRITICAL.value or (ctx and ctx.criticality == Criticality.CRITICAL.value)) else ExposurePriorityBand.HIGH_EXPOSURE.value
                cond = await self._upsert_condition(
                    org_id=org_id,
                    condition_type=ExposureConditionType.EXTERNALLY_REACHABLE_HIGH_CRITICALITY.value,
                    primary_asset=asset,
                    priority=priority,
                    title=f"High-Criticality Exposed Asset: {asset.identifier}",
                    description=f"Asset {asset.identifier} has criticality {asset.criticality.upper()} and is exposed.",
                    explanation=f"Asset {asset.identifier} is designated as high/critical criticality.",
                    risk_assessment=risk,
                    finding=finding,
                    change=change,
                    disc_cand=disc_cand
                )
                detected_conditions.append(cond)

            # Rule 6: EXPOSED_ADMIN_INTERFACE
            admin_ports = ["22", "3389", "8443", "9200", "27017"]
            if any(port in asset.identifier for port in admin_ports) or "admin" in asset.identifier.lower():
                cond = await self._upsert_condition(
                    org_id=org_id,
                    condition_type=ExposureConditionType.EXPOSED_ADMIN_INTERFACE.value,
                    primary_asset=asset,
                    priority=ExposurePriorityBand.CRITICAL_EXPOSURE.value,
                    title=f"Exposed Administrative Interface: {asset.identifier}",
                    description=f"Asset {asset.identifier} appears to run an administrative interface or remote management port.",
                    explanation=f"Asset identifier {asset.identifier} matches admin interface pattern or port.",
                    risk_assessment=risk,
                    finding=finding,
                    change=change,
                    disc_cand=disc_cand
                )
                detected_conditions.append(cond)

            # Rule 7: EXPOSED_ASSET_HIGH_RISK
            if risk and risk.risk_band in [RiskBand.CRITICAL.value, RiskBand.HIGH.value]:
                priority = ExposurePriorityBand.CRITICAL_EXPOSURE.value if risk.risk_band == RiskBand.CRITICAL.value else ExposurePriorityBand.HIGH_EXPOSURE.value
                cond = await self._upsert_condition(
                    org_id=org_id,
                    condition_type=ExposureConditionType.EXPOSED_ASSET_HIGH_RISK.value,
                    primary_asset=asset,
                    priority=priority,
                    title=f"Exposed Asset with High Contextual Risk: {asset.identifier}",
                    description=f"Asset {asset.identifier} has a Phase 1 contextual risk assessment of {risk.risk_band}.",
                    explanation=f"Contextual risk assessment {risk.id} evaluates risk score to {risk.risk_score:.2f} ({risk.risk_band}).",
                    risk_assessment=risk,
                    finding=finding,
                    change=change,
                    disc_cand=disc_cand
                )
                detected_conditions.append(cond)

            # Rule 8: EXPOSED_ASSET_OPEN_FINDING
            if finding:
                cond = await self._upsert_condition(
                    org_id=org_id,
                    condition_type=ExposureConditionType.EXPOSED_ASSET_OPEN_FINDING.value,
                    primary_asset=asset,
                    priority=ExposurePriorityBand.HIGH_EXPOSURE.value,
                    title=f"Exposed Asset with Open Finding: {asset.identifier}",
                    description=f"Asset {asset.identifier} is exposed and has an active security finding ({finding.title}).",
                    explanation=f"Finding {finding.id} ({finding.status}) is attached to asset {asset.identifier}.",
                    risk_assessment=risk,
                    finding=finding,
                    change=change,
                    disc_cand=disc_cand
                )
                detected_conditions.append(cond)

            # Rule 9: CERTIFICATE_LINKED_EXPOSURE
            if disc_cand and disc_cand.source_type == "certificate_transparency":
                cond = await self._upsert_condition(
                    org_id=org_id,
                    condition_type=ExposureConditionType.CERTIFICATE_LINKED_EXPOSURE.value,
                    primary_asset=asset,
                    priority=ExposurePriorityBand.MEDIUM_EXPOSURE.value,
                    title=f"Certificate-Linked Exposure: {asset.identifier}",
                    description=f"Asset {asset.identifier} was discovered via Certificate Transparency log expansion.",
                    explanation=f"Promoted from candidate {disc_cand.id} discovered by source {disc_cand.source_type}.",
                    risk_assessment=risk,
                    finding=finding,
                    change=change,
                    disc_cand=disc_cand
                )
                detected_conditions.append(cond)

        detected_keys = {(c.org_id, c.condition_type, c.primary_asset_id) for c in detected_conditions}

        # Resolve active or reopened conditions no longer detected in authoritative state
        existing_stmt = select(ExposureCondition).where(
            ExposureCondition.org_id == org_id,
            ExposureCondition.status.in_([ExposureConditionStatus.ACTIVE.value, ExposureConditionStatus.REOPENED.value])
        )
        existing_res = await self.db.execute(existing_stmt)
        now = utc_now()
        for existing in existing_res.scalars().all():
            key = (existing.org_id, existing.condition_type, existing.primary_asset_id)
            if key not in detected_keys:
                existing.status = ExposureConditionStatus.RESOLVED.value
                existing.resolved_at = now

        return detected_conditions

    async def _upsert_condition(
        self,
        org_id: str,
        condition_type: str,
        primary_asset: Asset,
        priority: str,
        title: str,
        description: str,
        explanation: str,
        risk_assessment: Optional[RiskAssessment] = None,
        finding: Optional[Finding] = None,
        change: Optional[Change] = None,
        disc_cand: Optional[DiscoveryCandidate] = None
    ) -> ExposureCondition:
        now = utc_now()

        new_id = generate_uuid()

        provenance_data = {
            "organization_id": org_id,
            "correlation_rule_version": self.RULE_VERSION,
            "primary_asset": {
                "id": primary_asset.id,
                "type": primary_asset.asset_type,
                "identifier": primary_asset.identifier,
                "environment": primary_asset.environment,
                "criticality": primary_asset.criticality,
            },
            "risk_assessment_id": risk_assessment.id if risk_assessment else None,
            "finding_id": finding.id if finding else None,
            "change_id": change.id if change else None,
            "discovery_candidate_id": disc_cand.id if disc_cand else None,
        }

        insert_stmt = sqlite_insert(ExposureCondition).values(

            id=new_id,
            org_id=org_id,
            condition_type=condition_type,
            status=ExposureConditionStatus.ACTIVE.value,
            priority_band=priority,
            title=title,
            description=description,
            explanation=explanation,
            primary_asset_id=primary_asset.id,
            risk_assessment_id=risk_assessment.id if risk_assessment else None,
            finding_id=finding.id if finding else None,
            change_id=change.id if change else None,
            rule_version=self.RULE_VERSION,
            first_seen_at=now,
            last_seen_at=now,
            provenance=provenance_data
        ).on_conflict_do_update(
            index_elements=['org_id', 'condition_type', 'primary_asset_id'],
            set_={
                'last_seen_at': now,
                'priority_band': priority,
                'title': title,
                'description': description,
                'explanation': explanation,
                'provenance': provenance_data,
                'risk_assessment_id': risk_assessment.id if risk_assessment else ExposureCondition.risk_assessment_id,
                'finding_id': finding.id if finding else ExposureCondition.finding_id,
                'change_id': change.id if change else ExposureCondition.change_id,
            }
        )
        await self.db.execute(insert_stmt)
        await self.db.flush()

        # Re-select updated or inserted condition record
        stmt = select(ExposureCondition).where(
            ExposureCondition.org_id == org_id,
            ExposureCondition.condition_type == condition_type,
            ExposureCondition.primary_asset_id == primary_asset.id
        )
        res = await self.db.execute(stmt)
        cond = res.scalars().one()

        if cond.status == ExposureConditionStatus.RESOLVED.value:
            cond.status = ExposureConditionStatus.REOPENED.value
            cond.reopened_at = now




        # Add evidence item link
        ev_link = ExposureConditionEvidence(
            org_id=org_id,
            condition_id=cond.id,
            evidence_type="asset",
            evidence_ref_id=primary_asset.id,
            details={"identifier": primary_asset.identifier, "asset_type": primary_asset.asset_type},
            observed_at=utc_now()
        )
        self.db.add(ev_link)
        await self.db.flush()


        # Emit notification if high/critical exposure
        if priority in [ExposurePriorityBand.CRITICAL_EXPOSURE.value, ExposurePriorityBand.HIGH_EXPOSURE.value]:
            notif_service = NotificationService(self.db)
            trigger = (
                NotificationTriggerType.UNEXPECTED_EXPOSED_SERVICE.value
                if condition_type == ExposureConditionType.UNEXPECTED_EXPOSED_SERVICE.value
                else NotificationTriggerType.CRITICAL_CONTEXTUAL_RISK.value
            )
            try:
                await notif_service.evaluate_and_notify(
                    org_id=org_id,
                    trigger_type=trigger,
                    source_id=cond.id,
                    finding_id=finding.id if finding else None,
                    risk_assessment_id=risk_assessment.id if risk_assessment else None,
                    change_id=change.id if change else None
                )
            except Exception as e:
                logger.warning("Failed to emit exposure notification: %s", str(e))

        return cond


    async def list_exposures(
        self,
        org_id: str,
        status: Optional[str] = None,
        condition_type: Optional[str] = None,
        priority_band: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[ExposureCondition]:
        """List tenant-scoped exposure conditions."""
        stmt = select(ExposureCondition).where(ExposureCondition.org_id == org_id)
        if status:
            stmt = stmt.where(ExposureCondition.status == status)
        if condition_type:
            stmt = stmt.where(ExposureCondition.condition_type == condition_type)
        if priority_band:
            stmt = stmt.where(ExposureCondition.priority_band == priority_band)

        stmt = stmt.order_by(ExposureCondition.last_seen_at.desc()).limit(limit).offset(offset)
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def get_exposure(self, org_id: str, exposure_id: str) -> Optional[ExposureCondition]:
        """Fetch tenant-scoped exposure condition detail."""
        stmt = select(ExposureCondition).where(
            ExposureCondition.id == exposure_id,
            ExposureCondition.org_id == org_id
        )
        res = await self.db.execute(stmt)
        return res.scalars().first()

    async def get_exposure_evidence(self, org_id: str, exposure_id: str) -> List[ExposureConditionEvidence]:
        """Fetch tenant-scoped exposure evidence links."""
        stmt = select(ExposureConditionEvidence).where(
            ExposureConditionEvidence.condition_id == exposure_id,
            ExposureConditionEvidence.org_id == org_id
        )
        res = await self.db.execute(stmt)
        return res.scalars().all()
