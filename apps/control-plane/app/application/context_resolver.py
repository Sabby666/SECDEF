"""Phase 1E: Deterministic Context Resolver.

Answers: "What organizational context and expected state applies to this asset/service/change?"

RULES & PRECEDENCE:
1. Scope Precedence: SERVICE (highest) > ASSET > HOSTNAME > DOMAIN > ORGANIZATION (lowest).
2. Exact Scope Matching: No fuzzy matching, no unassisted wildcard matching.
3. Expiration Check: Expired memories (valid_until < now) are excluded from active evaluation.
4. Conflict Handling: Conflicting memories at the highest matching precedence return CONFLICT_REQUIRES_REVIEW.
5. Explainability: Resolves full provenance trace explaining why an asset/service has a given expected_state/context.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.infrastructure.db.models import (
    Asset,
    AssetContext,
    OrganizationalMemory,
)
from shared_contracts.enums import (
    ScopeLevel,
    ClaimType,
    Environment,
    Criticality,
)
from shared_contracts.schemas import (
    ContextResolutionResponse,
    ProvenanceExplanation,
    MemoryResponse,
)

logger = logging.getLogger(__name__)

# Scope precedence weights (higher number = higher priority)
SCOPE_PRECEDENCE: Dict[str, int] = {
    ScopeLevel.SERVICE.value: 50,
    ScopeLevel.RELATIONSHIP.value: 45,
    ScopeLevel.ASSET.value: 40,
    ScopeLevel.HOSTNAME.value: 30,
    ScopeLevel.DOMAIN.value: 20,
    ScopeLevel.ORGANIZATION.value: 10,
}


class ContextResolver:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def resolve_context(
        self,
        org_id: str,
        target_type: str,
        target_identifier: str,
        domain_name: Optional[str] = None,
    ) -> ContextResolutionResponse:
        """Resolve expected state and organizational context with explainable provenance.

        All queries are tenant-isolated via org_id.
        """
        now = datetime.now(timezone.utc)

        # 1. Build applicable scope candidate keys
        scope_candidates: List[Tuple[str, str]] = []
        if target_type == "service":
            scope_candidates.append((ScopeLevel.SERVICE.value, f"service:{target_identifier}"))
        scope_candidates.append((ScopeLevel.ASSET.value, f"{target_type}:{target_identifier}"))

        if target_type in ("subdomain", "service", "hostname") and ":" in target_identifier:
            host_part = target_identifier.split(":")[0]
            scope_candidates.append((ScopeLevel.HOSTNAME.value, f"hostname:{host_part}"))
        elif target_type in ("subdomain", "hostname"):
            scope_candidates.append((ScopeLevel.HOSTNAME.value, f"hostname:{target_identifier}"))

        if domain_name:
            scope_candidates.append((ScopeLevel.DOMAIN.value, f"domain:{domain_name}"))
        scope_candidates.append((ScopeLevel.ORGANIZATION.value, f"organization:{org_id}"))

        # 2. Query tenant memories matching scope candidates
        matched_memories: List[OrganizationalMemory] = []
        for scope_lvl, scope_id in scope_candidates:
            res = await self.db.execute(
                select(OrganizationalMemory).where(
                    and_(
                        OrganizationalMemory.org_id == org_id,
                        OrganizationalMemory.scope_level == scope_lvl,
                        OrganizationalMemory.scope_identifier == scope_id,
                        OrganizationalMemory.status == "active",
                    )
                )
            )
            for mem in res.scalars().all():
                # Filter out expired memories
                if mem.valid_until:
                    v_until = mem.valid_until
                    if v_until.tzinfo is None:
                        v_until = v_until.replace(tzinfo=timezone.utc)
                    if v_until <= now:
                        continue
                matched_memories.append(mem)

        # Sort memories by scope precedence descending, then created_at descending
        matched_memories.sort(
            key=lambda m: (SCOPE_PRECEDENCE.get(m.scope_level, 0), m.created_at.timestamp()),
            reverse=True,
        )

        # 3. Resolve Expected State
        expected_state = "UNSPECIFIED"
        conflict_detected = False
        resolution_status = "resolved"
        provenance: List[ProvenanceExplanation] = []

        exp_memories = [m for m in matched_memories if m.memory_key == "expected_state"]
        if exp_memories:
            # Find the highest scope precedence level present
            top_precedence = SCOPE_PRECEDENCE.get(exp_memories[0].scope_level, 0)
            top_level_memories = [
                m for m in exp_memories
                if SCOPE_PRECEDENCE.get(m.scope_level, 0) == top_precedence
            ]

            # Check for conflicting assertions at top precedence level
            assertions = set()
            for m in top_level_memories:
                val = m.memory_value.get("decision_type")
                if val == "mark_expected":
                    assertions.add("EXPECTED")
                elif val == "mark_unexpected":
                    assertions.add("UNEXPECTED")

            if len(assertions) > 1:
                conflict_detected = True
                expected_state = "CONFLICT_REQUIRES_REVIEW"
                resolution_status = "conflict_detected"
                for m in top_level_memories:
                    provenance.append(
                        ProvenanceExplanation(
                            claim_type=ClaimType.DECISION,
                            source_type=m.source,
                            source_id=m.decision_id,
                            scope_level=ScopeLevel(m.scope_level),
                            scope_identifier=m.scope_identifier,
                            reason=f"Conflicting decision recorded: {m.memory_value.get('reason', 'N/A')}",
                            confidence=m.confidence,
                        )
                    )
            else:
                winning_mem = top_level_memories[0]
                dec_type = winning_mem.memory_value.get("decision_type")
                expected_state = "EXPECTED" if dec_type == "mark_expected" else "UNEXPECTED"
                provenance.append(
                    ProvenanceExplanation(
                        claim_type=ClaimType.EXPECTATION,
                        source_type=winning_mem.source,
                        source_id=winning_mem.decision_id,
                        scope_level=ScopeLevel(winning_mem.scope_level),
                        scope_identifier=winning_mem.scope_identifier,
                        reason=winning_mem.memory_value.get("reason", "Marked by security decision"),
                        confidence=winning_mem.confidence,
                    )
                )

        # 4. Resolve Context Metadata (environment, criticality, owner)
        environment = Environment.UNKNOWN.value
        criticality = Criticality.MEDIUM.value
        owner_id = None
        owner_team = None

        # Check Asset and AssetContext in DB first
        asset_res = await self.db.execute(
            select(Asset).where(
                and_(
                    Asset.org_id == org_id,
                    Asset.asset_type == target_type,
                    Asset.identifier == target_identifier,
                )
            )
        )
        asset = asset_res.scalars().first()
        if asset:
            environment = asset.environment
            criticality = asset.criticality
            owner_id = asset.owner_id
            owner_team = asset.owner_team
            provenance.append(
                ProvenanceExplanation(
                    claim_type=ClaimType.FACT,
                    source_type="asset_inventory",
                    source_id=asset.id,
                    scope_level=ScopeLevel.ASSET,
                    scope_identifier=f"{asset.asset_type}:{asset.identifier}",
                    reason="Resolved from asset inventory state",
                    confidence=1.0,
                )
            )

        # Apply any memory context overrides if present
        env_mem = next((m for m in matched_memories if m.memory_key == "environment"), None)
        if env_mem:
            environment = env_mem.memory_value.get("new_state", {}).get("environment", environment)
            provenance.append(
                ProvenanceExplanation(
                    claim_type=ClaimType.CONTEXT,
                    source_type=env_mem.source,
                    source_id=env_mem.decision_id,
                    scope_level=ScopeLevel(env_mem.scope_level),
                    scope_identifier=env_mem.scope_identifier,
                    reason=f"Environment context memory: {env_mem.memory_value.get('reason', '')}",
                    confidence=env_mem.confidence,
                )
            )

        crit_mem = next((m for m in matched_memories if m.memory_key == "criticality"), None)
        if crit_mem:
            criticality = crit_mem.memory_value.get("new_state", {}).get("criticality", criticality)
            provenance.append(
                ProvenanceExplanation(
                    claim_type=ClaimType.CONTEXT,
                    source_type=crit_mem.source,
                    source_id=crit_mem.decision_id,
                    scope_level=ScopeLevel(crit_mem.scope_level),
                    scope_identifier=crit_mem.scope_identifier,
                    reason=f"Criticality context memory: {crit_mem.memory_value.get('reason', '')}",
                    confidence=crit_mem.confidence,
                )
            )

        memory_dtos = [
            MemoryResponse.model_validate(m, from_attributes=True)
            for m in matched_memories
        ]

        logger.info(
            "context_resolved",
            extra={
                "org_id": org_id,
                "target_identifier": target_identifier,
                "expected_state": expected_state,
                "conflict_detected": conflict_detected,
                "matched_memories_count": len(matched_memories),
            },
        )

        return ContextResolutionResponse(
            target_identifier=target_identifier,
            target_type=target_type,
            expected_state=expected_state,
            environment=environment,
            criticality=criticality,
            owner_id=owner_id,
            owner_team=owner_team,
            conflict_detected=conflict_detected,
            resolution_status=resolution_status,
            matched_memories=memory_dtos,
            provenance=provenance,
        )
