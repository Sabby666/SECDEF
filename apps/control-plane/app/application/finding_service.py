import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.infrastructure.db.models import Finding, FindingStateTransition, Change, RiskAssessment, Asset
from app.application.audit_service import AuditService
from shared_contracts.enums import FindingLifecycleStatus


class FindingService:
    """Phase 1G: Managing security findings derived from detected changes and risk assessments."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_or_create_finding_for_change(
        self,
        org_id: str,
        change_id: str,
        risk_assessment_id: Optional[str] = None
    ) -> Finding:
        """
        Get or create a deterministic Finding record for a Change.
        Enforces tenant isolation by verifying org_id.
        """
        # 1. Tenant-scoped lookup
        stmt = select(Finding).where(Finding.org_id == org_id, Finding.change_id == change_id)
        res = await self.db.execute(stmt)
        existing = res.scalars().first()
        if existing:
            return existing

        # 2. Fetch Change ensuring org_id
        change_stmt = select(Change).where(Change.org_id == org_id, Change.id == change_id)
        res_change = await self.db.execute(change_stmt)
        change = res_change.scalars().first()
        if not change:
            raise ValueError(f"Change {change_id} not found for org {org_id}")

        # 3. Look up RiskAssessment if provided or fetch existing
        risk_assessment = None
        if risk_assessment_id:
            risk_stmt = select(RiskAssessment).where(
                RiskAssessment.org_id == org_id,
                RiskAssessment.id == risk_assessment_id
            )
            res_risk = await self.db.execute(risk_stmt)
            risk_assessment = res_risk.scalars().first()

        title = f"Security Change: {change.change_type} on {change.entity_identifier}"
        description = (
            f"Detected {change.change_type} for entity '{change.entity_identifier}' "
            f"(Entity Type: {change.entity_type})."
        )
        if risk_assessment:
            description += f" Contextual Risk Band: {risk_assessment.risk_band} (Score: {risk_assessment.risk_score:.1f})."

        finding = Finding(
            id=str(uuid.uuid4()),
            org_id=org_id,
            change_id=change_id,
            asset_id=change.asset_id,
            risk_assessment_id=risk_assessment.id if risk_assessment else None,
            status=FindingLifecycleStatus.OPEN.value,
            title=title,
            description=description,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        self.db.add(finding)

        # Initial state transition record
        transition = FindingStateTransition(
            id=str(uuid.uuid4()),
            org_id=org_id,
            finding_id=finding.id,
            actor_id=None,
            from_status="none",
            to_status=FindingLifecycleStatus.OPEN.value,
            reason="Finding automatically created from security change detection.",
            evidence_snapshot={
                "change_type": change.change_type,
                "entity_identifier": change.entity_identifier,
                "risk_band": risk_assessment.risk_band if risk_assessment else None,
                "risk_score": risk_assessment.risk_score if risk_assessment else None
            },
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(transition)

        await self.db.flush()
        return finding

    async def get_finding(self, org_id: str, finding_id: str) -> Optional[Finding]:
        """Tenant-isolated finding lookup."""
        stmt = select(Finding).where(Finding.org_id == org_id, Finding.id == finding_id)
        res = await self.db.execute(stmt)
        return res.scalars().first()

    async def list_findings(
        self,
        org_id: str,
        status: Optional[str] = None,
        asset_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[Finding], int]:
        """Tenant-isolated finding list query with pagination."""
        stmt = select(Finding).where(Finding.org_id == org_id)
        count_stmt = select(func.count(Finding.id)).where(Finding.org_id == org_id)

        if status:
            stmt = stmt.where(Finding.status == status)
            count_stmt = count_stmt.where(Finding.status == status)

        if asset_id:
            stmt = stmt.where(Finding.asset_id == asset_id)
            count_stmt = count_stmt.where(Finding.asset_id == asset_id)

        count_res = await self.db.execute(count_stmt)
        total = count_res.scalar() or 0

        res = await self.db.execute(stmt.order_by(Finding.created_at.desc()).limit(limit).offset(offset))
        findings = res.scalars().all()

        return list(findings), total

    async def acknowledge_finding(
        self,
        org_id: str,
        finding_id: str,
        actor_id: str,
        reason: str,
        ip_address: str = "127.0.0.1"
    ) -> Finding:
        """
        Transition finding state to ACKNOWLEDGED.
        ACKNOWLEDGEMENT != RESOLUTION.
        """
        finding = await self.get_finding(org_id, finding_id)
        if not finding:
            raise ValueError(f"Finding {finding_id} not found for organization {org_id}")

        if finding.status not in [FindingLifecycleStatus.OPEN.value, FindingLifecycleStatus.REOPENED.value]:
            raise ValueError(f"Cannot acknowledge finding in status '{finding.status}'")

        old_status = finding.status
        finding.status = FindingLifecycleStatus.ACKNOWLEDGED.value
        finding.acknowledged_by = actor_id
        finding.acknowledged_at = datetime.now(timezone.utc)
        finding.updated_at = datetime.now(timezone.utc)

        transition = FindingStateTransition(
            id=str(uuid.uuid4()),
            org_id=org_id,
            finding_id=finding.id,
            actor_id=actor_id,
            from_status=old_status,
            to_status=FindingLifecycleStatus.ACKNOWLEDGED.value,
            reason=reason,
            evidence_snapshot={"acknowledged_by": actor_id},
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(transition)

        AuditService.log_event(
            db_session=self.db,
            event_type="finding.acknowledged",
            resource_type="finding",
            resource_id=finding.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"from_status": old_status, "reason": reason}
        )

        await self.db.flush()
        return finding

    async def mark_in_progress(
        self,
        org_id: str,
        finding_id: str,
        actor_id: str,
        reason: str,
        ip_address: str = "127.0.0.1"
    ) -> Finding:
        """Transition finding state to IN_PROGRESS."""
        finding = await self.get_finding(org_id, finding_id)
        if not finding:
            raise ValueError(f"Finding {finding_id} not found for organization {org_id}")

        if finding.status in [FindingLifecycleStatus.RESOLVED.value]:
            raise ValueError(f"Cannot set resolved finding {finding_id} to in_progress without reopening")

        old_status = finding.status
        finding.status = FindingLifecycleStatus.IN_PROGRESS.value
        finding.updated_at = datetime.now(timezone.utc)

        transition = FindingStateTransition(
            id=str(uuid.uuid4()),
            org_id=org_id,
            finding_id=finding.id,
            actor_id=actor_id,
            from_status=old_status,
            to_status=FindingLifecycleStatus.IN_PROGRESS.value,
            reason=reason,
            evidence_snapshot={"actor_id": actor_id},
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(transition)

        AuditService.log_event(
            db_session=self.db,
            event_type="finding.in_progress",
            resource_type="finding",
            resource_id=finding.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"from_status": old_status, "reason": reason}
        )

        await self.db.flush()
        return finding
