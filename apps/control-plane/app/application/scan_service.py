import logging
import uuid
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.models import Scan, Domain, Observation
from app.application.audit_service import AuditService
from shared_contracts.enums import DomainStatus

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_scan_job(
        self,
        org_id: str,
        domain_id: str,
        actor_id: str,
        ip_address: str
    ) -> Scan:
        """
        Creates a scan job for a target domain.
        TARGET AUTHORIZATION GATE: Strictly verifies domain status == VERIFIED.
        """
        # 1. Target Authorization Check
        result = await self.db.execute(
            select(Domain).where(Domain.id == domain_id, Domain.org_id == org_id)
        )
        domain = result.scalars().first()

        if not domain:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not found or does not belong to organization"
            )

        if domain.status != DomainStatus.VERIFIED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target Authorization Failed: Domain status is '{domain.status}'. Only verified domains can be scanned."
            )

        # 2. Create Scan Record
        job_nonce = f"nonce-{uuid.uuid4().hex}"
        scan = Scan(
            org_id=org_id,
            domain_id=domain_id,
            status="queued",
            job_nonce=job_nonce,
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(scan)

        # 3. Log Audit Event
        AuditService.log_event(
            db_session=self.db,
            event_type="scan.created",
            resource_type="scan",
            resource_id=scan.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"domain_name": domain.domain_name, "job_nonce": job_nonce}
        )

        await self.db.commit()
        await self.db.refresh(scan)

        return scan

    async def get_scan(self, org_id: str, scan_id: str) -> Optional[Scan]:
        """Fetch scan record ensuring org_id tenant isolation."""
        result = await self.db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id)
        )
        return result.scalars().first()

    async def get_scans_for_org(self, org_id: str) -> List[Scan]:
        """Fetch all scans for organization."""
        result = await self.db.execute(
            select(Scan).where(Scan.org_id == org_id).order_by(Scan.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_observations_for_scan(self, org_id: str, scan_id: str) -> List[Observation]:
        """Fetch all raw observations for a scan."""
        result = await self.db.execute(
            select(Observation).where(Observation.scan_id == scan_id, Observation.org_id == org_id)
        )
        return list(result.scalars().all())
