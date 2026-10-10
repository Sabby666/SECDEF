"""Candidate validation and Phase 1 asset promotion service."""
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.models import DiscoveryCandidate, DiscoveryRun, Domain, Asset
from app.application.asset_resolution_service import AssetResolutionService
from shared_contracts.enums import ValidationState, DomainStatus

logger = logging.getLogger(__name__)


class CandidateValidationService:
    """Handles deterministic validation and promotion of discovery candidates into authoritative assets."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def validate_candidate(
        self, candidate_id: str, org_id: str, validation_override: Optional[str] = None
    ) -> DiscoveryCandidate:
        """Validate candidate and promote to Phase 1 Asset graph."""
        # 1. Tenant-scoped candidate lookup
        stmt = select(DiscoveryCandidate).where(
            DiscoveryCandidate.id == candidate_id,
            DiscoveryCandidate.org_id == org_id,
        )
        result = await self.db.execute(stmt)
        candidate = result.scalars().first()

        if not candidate:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Candidate '{candidate_id}' not found for organization",
            )

        # 2. Discovery run lookup
        run_stmt = select(DiscoveryRun).where(
            DiscoveryRun.id == candidate.discovery_run_id,
            DiscoveryRun.org_id == org_id,
        )
        run_res = await self.db.execute(run_stmt)
        run = run_res.scalars().first()
        domain_id = run.domain_id if run else None

        # 3. Validation state update
        target_state = validation_override or ValidationState.DNS_CONFIRMED.value
        candidate.validation_state = target_state

        # 4. Promote candidate to authoritative Phase 1 Asset
        asset_resolver = AssetResolutionService(self.db)
        asset = await asset_resolver.resolve_or_create_asset(
            org_id=org_id,
            asset_type=candidate.candidate_type,
            raw_identifier=candidate.canonical_identifier,
            domain_id=domain_id,
        )

        candidate.promoted_asset_id = asset.id
        candidate.last_seen_at = datetime.now(timezone.utc)

        # Update run stats if run exists
        if run:
            run.candidates_validated += 1

        await self.db.commit()
        await self.db.refresh(candidate)
        return candidate

    async def reject_candidate(self, candidate_id: str, org_id: str) -> DiscoveryCandidate:
        """Mark a discovery candidate as rejected."""
        stmt = select(DiscoveryCandidate).where(
            DiscoveryCandidate.id == candidate_id,
            DiscoveryCandidate.org_id == org_id,
        )
        result = await self.db.execute(stmt)
        candidate = result.scalars().first()

        if not candidate:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Candidate '{candidate_id}' not found for organization",
            )

        candidate.validation_state = ValidationState.REJECTED.value
        candidate.last_seen_at = datetime.now(timezone.utc)

        # Update run stats if run exists
        run_stmt = select(DiscoveryRun).where(
            DiscoveryRun.id == candidate.discovery_run_id,
            DiscoveryRun.org_id == org_id,
        )
        run_res = await self.db.execute(run_stmt)
        run = run_res.scalars().first()
        if run:
            run.candidates_rejected += 1

        await self.db.commit()
        await self.db.refresh(candidate)
        return candidate
