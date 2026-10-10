"""Phase 1F: Contextual Risk Engine Service.

Coordinates change retrieval, context resolution via ContextResolver,
deterministic risk evaluation via RiskModelV1, context snapshotting, and idempotent DB persistence.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.infrastructure.db.models import (
    RiskAssessment,
    Change,
    Asset,
)
from app.application.context_resolver import ContextResolver
from app.application.audit_service import AuditService
from app.application.risk_model import RiskModelV1, get_risk_model
from shared_contracts.enums import RiskModelVersion, RiskBand

logger = logging.getLogger(__name__)


class RiskEngineService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.context_resolver = ContextResolver(db)

    async def get_assessment(self, org_id: str, assessment_id: str) -> Optional[RiskAssessment]:
        """Fetch risk assessment with strict tenant isolation."""
        res = await self.db.execute(
            select(RiskAssessment).where(
                and_(
                    RiskAssessment.id == assessment_id,
                    RiskAssessment.org_id == org_id,
                )
            )
        )
        return res.scalars().first()

    async def assess_change_risk(
        self,
        org_id: str,
        change_id: str,
        risk_model_version: str = RiskModelVersion.V1.value,
        ip_address: str = "127.0.0.1",
    ) -> RiskAssessment:
        """Calculate and store a deterministic risk assessment for a detected change.

        - Idempotent: Returns existing assessment if (org_id, change_id, model_version) already exists.
        - Immutable: Captures context snapshot at assessment time.
        - Tenant-Isolated: Enforces org_id predicate on all DB queries.
        """
        # 1. Check idempotency: already assessed under this model version?
        existing = await self.db.execute(
            select(RiskAssessment).where(
                and_(
                    RiskAssessment.org_id == org_id,
                    RiskAssessment.change_id == change_id,
                    RiskAssessment.risk_model_version == risk_model_version,
                )
            )
        )
        existing_rec = existing.scalars().first()
        if existing_rec:
            return existing_rec

        # 2. Fetch Change record
        change_res = await self.db.execute(
            select(Change).where(
                and_(
                    Change.id == change_id,
                    Change.org_id == org_id,
                )
            )
        )
        change = change_res.scalars().first()
        if not change:
            raise ValueError(f"Change {change_id} not found for organization {org_id}")

        # 3. Resolve context for entity
        context_res = await self.context_resolver.resolve_context(
            org_id=org_id,
            target_type=change.entity_type,
            target_identifier=change.entity_identifier,
        )

        # 4. Dispatch risk calculation to selected risk model version
        model_cls = get_risk_model(risk_model_version)
        (
            risk_score,
            risk_band,
            confidence,
            factor_breakdown,
            context_snapshot,
            uncertainty_flags,
            explanation,
        ) = model_cls.calculate_risk(
            change_type=change.change_type,
            entity_type=change.entity_type,
            entity_identifier=change.entity_identifier,
            context_res=context_res,
            evidence_payload=change.evidence,
        )

        now = datetime.now(timezone.utc)
        assessment = RiskAssessment(
            id=str(uuid.uuid4()),
            org_id=org_id,
            change_id=change_id,
            asset_id=change.asset_id,
            risk_model_version=risk_model_version,
            risk_score=risk_score,
            risk_band=risk_band.value,
            confidence=confidence,
            factor_breakdown=[f.model_dump() for f in factor_breakdown],
            context_snapshot=context_snapshot,
            uncertainty_flags=uncertainty_flags,
            explanation=explanation,
            created_at=now,
            updated_at=now,
        )
        try:
            self.db.add(assessment)
            await self.db.flush()
        except IntegrityError:
            await self.db.rollback()
            existing = await self.db.execute(
                select(RiskAssessment).where(
                    and_(
                        RiskAssessment.org_id == org_id,
                        RiskAssessment.change_id == change_id,
                        RiskAssessment.risk_model_version == risk_model_version,
                    )
                )
            )
            return existing.scalars().first()

        # 5. Audit Logging
        AuditService.log_event(
            db_session=self.db,
            event_type="risk_assessment.created",
            resource_type="risk_assessment",
            resource_id=assessment.id,
            org_id=org_id,
            actor_id="system",
            ip_address=ip_address,
            details={
                "change_id": change_id,
                "asset_id": change.asset_id,
                "risk_score": risk_score,
                "risk_band": risk_band.value,
                "model_version": risk_model_version,
            },
        )

        logger.info(
            "contextual_risk_assessed",
            extra={
                "org_id": org_id,
                "change_id": change_id,
                "risk_score": risk_score,
                "risk_band": risk_band.value,
                "model_version": risk_model_version,
            },
        )

        return assessment

    async def list_assessments(
        self,
        org_id: str,
        risk_band: Optional[str] = None,
        asset_id: Optional[str] = None,
        change_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[RiskAssessment], int]:
        """List tenant risk assessments with filtering and pagination."""
        query = select(RiskAssessment).where(RiskAssessment.org_id == org_id)

        if risk_band:
            query = query.where(RiskAssessment.risk_band == risk_band)
        if asset_id:
            query = query.where(RiskAssessment.asset_id == asset_id)
        if change_id:
            query = query.where(RiskAssessment.change_id == change_id)

        query = query.order_by(RiskAssessment.created_at.desc())

        from sqlalchemy import func
        count_query = select(func.count()).select_from(RiskAssessment).where(RiskAssessment.org_id == org_id)
        if risk_band:
            count_query = count_query.where(RiskAssessment.risk_band == risk_band)
        if asset_id:
            count_query = count_query.where(RiskAssessment.asset_id == asset_id)
        if change_id:
            count_query = count_query.where(RiskAssessment.change_id == change_id)

        total_res = await self.db.execute(count_query)
        total = total_res.scalar() or 0

        res = await self.db.execute(query.limit(limit).offset(offset))
        assessments = list(res.scalars().all())

        return assessments, total
