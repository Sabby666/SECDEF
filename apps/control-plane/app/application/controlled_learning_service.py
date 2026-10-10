"""Phase 1E: Controlled Learning Service.

Derives persistent, tenant-isolated, explainable OrganizationalMemory items from
validated human security decisions while enforcing strict scope-limited inheritance safety rules.

SAFETY INVARIANTS ENFORCED:
1. No unassisted wildcard expansion: Single-asset decisions NEVER produce wildcard memory.
2. No scope escalation: Derived memory scope matches decision scope EXACTLY.
3. No automatic trust escalation: Repeated events do NOT trigger global rule creation.
4. Tenant isolation: Memory NEVER crosses tenant boundaries.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, update

from app.infrastructure.db.models import (
    OrganizationalMemory,
    OrganizationalDecision,
)
from shared_contracts.enums import (
    MemoryCategory,
    DecisionType,
    DecisionStatus,
)

logger = logging.getLogger(__name__)


# Map DecisionType to MemoryCategory and memory_key
DECISION_MEMORY_MAPPING: Dict[str, tuple[str, str]] = {
    DecisionType.MARK_EXPECTED: (MemoryCategory.EXPECTATION, "expected_state"),
    DecisionType.MARK_UNEXPECTED: (MemoryCategory.EXPECTATION, "expected_state"),
    DecisionType.ACCEPT_RISK: (MemoryCategory.DECISION, "risk_acceptance"),
    DecisionType.MARK_FALSE_POSITIVE: (MemoryCategory.DECISION, "false_positive"),
    DecisionType.ASSIGN_OWNER: (MemoryCategory.CONTEXT, "owner"),
    DecisionType.SET_ENVIRONMENT: (MemoryCategory.CONTEXT, "environment"),
    DecisionType.SET_CRITICALITY: (MemoryCategory.CONTEXT, "criticality"),
    DecisionType.ACKNOWLEDGE: (MemoryCategory.DECISION, "acknowledgement"),
}


class ControlledLearningService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def derive_memory_from_decision(
        self, decision: OrganizationalDecision
    ) -> Optional[OrganizationalMemory]:
        """Derive a persistent, scope-limited OrganizationalMemory item from a decision.

        Scope Non-Escalation Rule:
        The derived memory's scope_level and scope_identifier match the decision's
        explicit scope EXACTLY. No wildcard expansion occurs.
        """
        now = datetime.now(timezone.utc)

        category, memory_key = DECISION_MEMORY_MAPPING.get(
            decision.decision_type, (MemoryCategory.DECISION, "decision_record")
        )

        memory_id = str(uuid.uuid4())
        memory = OrganizationalMemory(
            id=memory_id,
            org_id=decision.org_id,
            decision_id=decision.id,
            category=category,
            scope_level=decision.scope_level,
            scope_identifier=decision.subject_identifier,
            memory_key=memory_key,
            memory_value={
                "decision_type": decision.decision_type,
                "new_state": decision.new_state,
                "reason": decision.reason,
            },
            confidence=1.0,
            source=f"human_decision:{decision.actor_id}",
            evidence={
                "decision_id": decision.id,
                "actor_id": decision.actor_id,
                "reason": decision.reason,
                "evidence_payload": decision.evidence,
            },
            valid_from=decision.valid_from,
            valid_until=decision.valid_until,
            status="active",
            created_at=now,
            updated_at=now,
        )
        self.db.add(memory)
        await self.db.flush()

        logger.info(
            "controlled_memory_derived",
            extra={
                "org_id": decision.org_id,
                "memory_id": memory.id,
                "decision_id": decision.id,
                "category": category,
                "scope_level": memory.scope_level,
                "scope_identifier": memory.scope_identifier,
            },
        )

        return memory

    async def revoke_memory_for_decision(
        self, org_id: str, decision_id: str
    ) -> int:
        """Deactivate all derived memories associated with a revoked decision."""
        result = await self.db.execute(
            select(OrganizationalMemory).where(
                and_(
                    OrganizationalMemory.org_id == org_id,
                    OrganizationalMemory.decision_id == decision_id,
                    OrganizationalMemory.status == "active",
                )
            )
        )
        memories = result.scalars().all()
        now = datetime.now(timezone.utc)
        count = 0

        for mem in memories:
            mem.status = "revoked"
            mem.updated_at = now
            count += 1

        await self.db.flush()
        return count

    async def list_memories(
        self,
        org_id: str,
        category: Optional[str] = None,
        scope_level: Optional[str] = None,
        status: Optional[str] = "active",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[OrganizationalMemory], int]:
        """List tenant memories with strict tenant isolation and pagination."""
        query = select(OrganizationalMemory).where(OrganizationalMemory.org_id == org_id)

        if category:
            query = query.where(OrganizationalMemory.category == category)
        if scope_level:
            query = query.where(OrganizationalMemory.scope_level == scope_level)
        if status:
            query = query.where(OrganizationalMemory.status == status)

        query = query.order_by(OrganizationalMemory.created_at.desc())

        from sqlalchemy import func
        count_query = select(func.count()).select_from(OrganizationalMemory).where(OrganizationalMemory.org_id == org_id)
        if category:
            count_query = count_query.where(OrganizationalMemory.category == category)
        if scope_level:
            count_query = count_query.where(OrganizationalMemory.scope_level == scope_level)
        if status:
            count_query = count_query.where(OrganizationalMemory.status == status)

        total_res = await self.db.execute(count_query)
        total = total_res.scalar() or 0

        res = await self.db.execute(query.limit(limit).offset(offset))
        memories = list(res.scalars().all())

        return memories, total
