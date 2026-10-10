"""Discovery orchestration service managing sources, runs, candidate correlation, and evidence."""
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.infrastructure.db.models import (
    DiscoverySource,
    DiscoveryRun,
    DiscoveryCandidate,
    DiscoveryEvidence,
    Domain,
)
from app.application.discovery_providers.ct_provider import CertificateTransparencyProvider
from app.application.discovery_providers.passive_dns_provider import PassiveDNSProvider
from app.application.discovery_providers.active_dns_provider import ActiveDNSDiscoveryProvider
from app.application.candidate_correlation_service import CandidateCorrelationService
from shared_contracts.enums import (
    DiscoverySourceType,
    DiscoveryRunStatus,
    DomainStatus,
)

logger = logging.getLogger(__name__)


PROVIDERS = {
    DiscoverySourceType.CERTIFICATE_TRANSPARENCY.value: CertificateTransparencyProvider(),
    DiscoverySourceType.PASSIVE_DNS.value: PassiveDNSProvider(),
    DiscoverySourceType.ACTIVE_DNS.value: ActiveDNSDiscoveryProvider(),
}


class DiscoveryService:
    """Orchestrates discovery sources, execution runs, candidate correlation, and evidence tracking."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_source(
        self, org_id: str, source_type: str, name: str, config: Optional[Dict[str, Any]] = None
    ) -> DiscoverySource:
        """Create or configure a new discovery source for organization (Admin operation)."""
        source = DiscoverySource(
            org_id=org_id,
            source_type=source_type,
            name=name,
            is_active=True,
            config=config or {},
        )
        self.db.add(source)
        await self.db.commit()
        await self.db.refresh(source)
        return source

    async def get_or_create_default_sources(self, org_id: str) -> List[DiscoverySource]:

        """Ensure standard discovery sources exist for the organization."""
        defaults = [
            (DiscoverySourceType.CERTIFICATE_TRANSPARENCY.value, "Certificate Transparency Log Monitor"),
            (DiscoverySourceType.PASSIVE_DNS.value, "Passive DNS Historical Sensor"),
            (DiscoverySourceType.ACTIVE_DNS.value, "Active DNS Expansion Sensor"),
        ]

        sources = []
        for src_type, name in defaults:
            stmt = select(DiscoverySource).where(
                DiscoverySource.org_id == org_id,
                DiscoverySource.source_type == src_type,
            )
            res = await self.db.execute(stmt)
            existing = res.scalars().first()

            if not existing:
                existing = DiscoverySource(
                    org_id=org_id,
                    source_type=src_type,
                    name=name,
                    is_active=True,
                    config={"rate_limit": 100, "bounded_records": 1000},
                )
                self.db.add(existing)
                await self.db.flush()

            sources.append(existing)

        await self.db.commit()
        return sources

    async def start_discovery_run(
        self,
        org_id: str,
        domain_id: str,
        source_type: str,
        config_override: Optional[Dict[str, Any]] = None,
    ) -> DiscoveryRun:
        """Execute a discovery run for an organization domain using a specific source provider."""
        # 1. Verify organization domain
        dom_stmt = select(Domain).where(Domain.id == domain_id, Domain.org_id == org_id)
        dom_res = await self.db.execute(dom_stmt)
        domain = dom_res.scalars().first()

        if not domain:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Domain '{domain_id}' not found for organization",
            )

        # 2. Get discovery source record
        src_stmt = select(DiscoverySource).where(
            DiscoverySource.org_id == org_id,
            DiscoverySource.source_type == source_type,
        )
        src_res = await self.db.execute(src_stmt)
        source = src_res.scalars().first()

        if not source:
            await self.get_or_create_default_sources(org_id)
            src_res = await self.db.execute(src_stmt)
            source = src_res.scalars().first()

        if not source:
            source = DiscoverySource(
                org_id=org_id,
                source_type=source_type,
                name=f"Custom Provider ({source_type})",
                is_active=True,
            )
            self.db.add(source)
            await self.db.flush()

        now = datetime.now(timezone.utc)


        # 3. Create DiscoveryRun record
        run = DiscoveryRun(
            org_id=org_id,
            source_id=source.id,
            domain_id=domain.id,
            status=DiscoveryRunStatus.RUNNING.value,
            started_at=now,
            run_metadata={"domain_name": domain.domain_name, "source_type": source_type},
        )
        self.db.add(run)
        await self.db.commit()
        await self.db.refresh(run)

        provider = PROVIDERS.get(source_type)
        if not provider:
            run.status = DiscoveryRunStatus.FAILED.value
            run.error_message = f"Unsupported discovery provider '{source_type}'"
            run.completed_at = datetime.now(timezone.utc)
            await self.db.commit()
            return run

        # 4. Execute provider discovery with exception safety
        try:
            merged_config = {**(source.config or {}), **(config_override or {})}
            raw_evidences = await provider.execute_discovery(
                org_id=org_id, domain_name=domain.domain_name, config=merged_config
            )

            # Synchronously run correlation via underlying sync session if needed
            # For AsyncSession compatibility, we perform atomic candidate inserts directly
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert
            import uuid

            discovered_count = 0
            for ev in raw_evidences:
                ident = ev.canonical_identifier.strip().lower().rstrip(".")
                cand_type = ev.candidate_type.strip().lower()

                # Atomic upsert using unique constraint on (org_id, candidate_type, canonical_identifier)
                cand_id = str(uuid.uuid4())
                upsert_stmt = (
                    sqlite_insert(DiscoveryCandidate)
                    .values(
                        id=cand_id,
                        org_id=org_id,
                        discovery_run_id=run.id,
                        canonical_identifier=ident,
                        candidate_type=cand_type,
                        source_type=source_type,
                        validation_state="unvalidated",
                        confidence=ev.confidence,
                        exposure_state=ev.exposure_state,
                        first_seen_at=ev.observed_at,
                        last_seen_at=ev.observed_at,
                        candidate_metadata={"initial_source": source_type, "provenance": ev.provenance},
                    )
                    .on_conflict_do_update(
                        index_elements=["org_id", "candidate_type", "canonical_identifier"],
                        set_={"last_seen_at": ev.observed_at},
                    )
                )
                res = await self.db.execute(upsert_stmt)
                # If a new row was inserted (matched id == cand_id), increment count
                
                # Fetch resolved single candidate
                cand_res = await self.db.execute(
                    select(DiscoveryCandidate).where(
                        DiscoveryCandidate.org_id == org_id,
                        DiscoveryCandidate.candidate_type == cand_type,
                        DiscoveryCandidate.canonical_identifier == ident,
                    )
                )
                candidate = cand_res.scalars().one()
                if candidate.id == cand_id:
                    discovered_count += 1

                # Insert evidence record
                evidence_rec = DiscoveryEvidence(
                    org_id=org_id,
                    candidate_id=candidate.id,
                    source_type=source_type,
                    raw_data=ev.raw_data,
                    provenance=ev.provenance,
                    observed_at=ev.observed_at,
                )
                self.db.add(evidence_rec)


            run.status = DiscoveryRunStatus.COMPLETED.value
            run.candidates_discovered = discovered_count
            run.completed_at = datetime.now(timezone.utc)
            source.last_run_at = run.completed_at

        except Exception as e:
            logger.exception(f"Discovery run {run.id} failed for source {source_type}: {e}")
            run.status = DiscoveryRunStatus.FAILED.value
            run.error_message = str(e)
            run.completed_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(run)
        return run

    async def list_sources(self, org_id: str) -> List[DiscoverySource]:
        """List discovery sources for organization."""
        await self.get_or_create_default_sources(org_id)
        stmt = select(DiscoverySource).where(DiscoverySource.org_id == org_id)
        res = await self.db.execute(stmt)
        return list(res.scalars().all())

    async def list_runs(
        self, org_id: str, domain_id: Optional[str] = None, limit: int = 50
    ) -> List[DiscoveryRun]:
        """List discovery runs for organization."""
        stmt = select(DiscoveryRun).where(DiscoveryRun.org_id == org_id)
        if domain_id:
            stmt = stmt.where(DiscoveryRun.domain_id == domain_id)
        stmt = stmt.order_by(desc(DiscoveryRun.created_at)).limit(limit)
        res = await self.db.execute(stmt)
        return list(res.scalars().all())

    async def get_run(self, run_id: str, org_id: str) -> DiscoveryRun:
        """Get single discovery run by ID with tenant check."""
        stmt = select(DiscoveryRun).where(DiscoveryRun.id == run_id, DiscoveryRun.org_id == org_id)
        res = await self.db.execute(stmt)
        run = res.scalars().first()
        if not run:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Discovery run '{run_id}' not found for organization",
            )
        return run

    async def list_candidates(
        self,
        org_id: str,
        validation_state: Optional[str] = None,
        candidate_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[DiscoveryCandidate]:
        """List candidates scoped by tenant and optional validation/type filters."""
        stmt = select(DiscoveryCandidate).where(DiscoveryCandidate.org_id == org_id)
        if validation_state:
            stmt = stmt.where(DiscoveryCandidate.validation_state == validation_state)
        if candidate_type:
            stmt = stmt.where(DiscoveryCandidate.candidate_type == candidate_type)
        stmt = stmt.order_by(desc(DiscoveryCandidate.last_seen_at)).limit(limit)
        res = await self.db.execute(stmt)
        return list(res.scalars().all())

    async def get_candidate(self, candidate_id: str, org_id: str) -> DiscoveryCandidate:
        """Get candidate details with evidence items and tenant scoping."""
        stmt = select(DiscoveryCandidate).where(
            DiscoveryCandidate.id == candidate_id, DiscoveryCandidate.org_id == org_id
        )
        res = await self.db.execute(stmt)
        cand = res.scalars().first()
        if not cand:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Candidate '{candidate_id}' not found for organization",
            )
        return cand

    async def get_candidate_evidence(self, candidate_id: str, org_id: str) -> List[DiscoveryEvidence]:
        """Get all evidence provenance items for a candidate."""
        # Check candidate ownership first
        await self.get_candidate(candidate_id, org_id)
        stmt = (
            select(DiscoveryEvidence)
            .where(DiscoveryEvidence.candidate_id == candidate_id, DiscoveryEvidence.org_id == org_id)
            .order_by(desc(DiscoveryEvidence.observed_at))
        )
        res = await self.db.execute(stmt)
        return list(res.scalars().all())
