"""Phase 1E: Decision Service.

Manages auditable human security decisions, decision revocations, expiration evaluation,
and append-only lifecycle transition logging.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.infrastructure.db.models import (
    OrganizationalDecision,
    DecisionTransitionHistory,
)
from app.application.audit_service import AuditService
from app.application.controlled_learning_service import ControlledLearningService
from shared_contracts.enums import (
    DecisionType,
    ScopeLevel,
    DecisionStatus,
)

logger = logging.getLogger(__name__)


class DecisionService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.learning_service = ControlledLearningService(db)

    async def get_decision(self, org_id: str, decision_id: str) -> Optional[OrganizationalDecision]:
        """Fetch decision with strict tenant isolation."""
        result = await self.db.execute(
            select(OrganizationalDecision).where(
                and_(
                    OrganizationalDecision.id == decision_id,
                    OrganizationalDecision.org_id == org_id,
                )
            )
        )
        return result.scalars().first()

    async def create_decision(
        self,
        org_id: str,
        actor_id: str,
        decision_type: str,
        scope_level: str,
        subject_identifier: str,
        new_state: Dict[str, Any],
        reason: str,
        subject_type: str = "asset",
        previous_state: Optional[Dict[str, Any]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        valid_until: Optional[datetime] = None,
        review_at: Optional[datetime] = None,
        ip_address: str = "127.0.0.1",
    ) -> OrganizationalDecision:
        """Create a structured, immutable human security decision event.

        - Enforces tenant isolation and explicit scope bounds.
        - Automatically derives a scope-limited OrganizationalMemory item.
        - Logs an audit event for governance.
        """
        now = datetime.now(timezone.utc)

        # Validate enums
        if decision_type not in [e.value for e in DecisionType]:
            raise ValueError(f"Invalid decision_type '{decision_type}'")
        if scope_level not in [e.value for e in ScopeLevel]:
            raise ValueError(f"Invalid scope_level '{scope_level}'")

        decision_id = str(uuid.uuid4())
        decision = OrganizationalDecision(
            id=decision_id,
            org_id=org_id,
            actor_id=actor_id,
            subject_type=subject_type,
            subject_identifier=subject_identifier,
            decision_type=decision_type,
            scope_level=scope_level,
            previous_state=previous_state,
            new_state=new_state,
            reason=reason,
            evidence=evidence,
            valid_from=now,
            valid_until=valid_until,
            review_at=review_at,
            status=DecisionStatus.ACTIVE,
            created_at=now,
        )
        self.db.add(decision)
        await self.db.flush()

        # Derive controlled organizational memory record
        await self.learning_service.derive_memory_from_decision(decision)

        # Audit logging
        AuditService.log_event(
            db_session=self.db,
            event_type="security_decision.created",
            resource_type="decision",
            resource_id=decision.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={
                "decision_type": decision_type,
                "scope_level": scope_level,
                "subject_identifier": subject_identifier,
                "reason": reason,
                "valid_until": valid_until.isoformat() if valid_until else None,
            },
        )

        logger.info(
            "security_decision_created",
            extra={
                "org_id": org_id,
                "decision_id": decision.id,
                "actor_id": actor_id,
                "decision_type": decision_type,
                "scope_level": scope_level,
                "subject_identifier": subject_identifier,
            },
        )

        return decision

    async def revoke_decision(
        self,
        org_id: str,
        decision_id: str,
        actor_id: str,
        reason: str,
        ip_address: str = "127.0.0.1",
    ) -> OrganizationalDecision:
        """Revoke an active decision cleanly without destroying historical record.

        - Creates an append-only DecisionTransitionHistory entry.
        - Updates decision status to REVOKED.
        - Deactivates any derived OrganizationalMemory.
        - Logs audit event.
        """
        now = datetime.now(timezone.utc)

        decision = await self.get_decision(org_id, decision_id)
        if not decision:
            raise ValueError(f"Decision {decision_id} not found or does not belong to org {org_id}")

        if decision.status == DecisionStatus.REVOKED:
            return decision

        from_status = decision.status
        decision.status = DecisionStatus.REVOKED

        # Record append-only transition history
        transition = DecisionTransitionHistory(
            id=str(uuid.uuid4()),
            org_id=org_id,
            decision_id=decision_id,
            actor_id=actor_id,
            from_status=from_status,
            to_status=DecisionStatus.REVOKED,
            reason=reason,
            created_at=now,
        )
        self.db.add(transition)

        # Deactivate derived memory
        await self.learning_service.revoke_memory_for_decision(org_id, decision_id)

        await self.db.flush()

        # Audit logging
        AuditService.log_event(
            db_session=self.db,
            event_type="security_decision.revoked",
            resource_type="decision",
            resource_id=decision.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"from_status": from_status, "reason": reason},
        )

        logger.info(
            "security_decision_revoked",
            extra={
                "org_id": org_id,
                "decision_id": decision_id,
                "actor_id": actor_id,
                "reason": reason,
            },
        )

        return decision

    async def list_decisions(
        self,
        org_id: str,
        decision_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[OrganizationalDecision], int]:
        """List tenant decisions with pagination and filtering."""
        query = select(OrganizationalDecision).where(OrganizationalDecision.org_id == org_id)
        if decision_type:
            query = query.where(OrganizationalDecision.decision_type == decision_type)
        if status:
            query = query.where(OrganizationalDecision.status == status)

        query = query.order_by(OrganizationalDecision.created_at.desc())

        # Count total
        from sqlalchemy import func
        count_query = select(func.count()).select_from(OrganizationalDecision).where(OrganizationalDecision.org_id == org_id)
        if decision_type:
            count_query = count_query.where(OrganizationalDecision.decision_type == decision_type)
        if status:
            count_query = count_query.where(OrganizationalDecision.status == status)

        total_res = await self.db.execute(count_query)
        total = total_res.scalar() or 0

        result = await self.db.execute(query.limit(limit).offset(offset))
        decisions = list(result.scalars().all())

        return decisions, total
