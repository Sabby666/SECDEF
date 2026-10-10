"""Phase 4 Intelligence Ingestion Service.

Handles ingestion, normalization, validation, deduplication, and atomic storage of external intelligence feed data.
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.infrastructure.db.models import (
    generate_uuid, IntelligenceSource, IntelligenceRun, IntelligenceRecord
)
from app.application.intelligence_providers.base_provider import (
    BaseIntelligenceProvider, sanitize_text, ProviderValidationError
)
from app.application.intelligence_providers.nvd_provider import NvdIntelligenceProvider
from app.application.intelligence_providers.kev_provider import CisaKevIntelligenceProvider
from app.application.intelligence_providers.epss_provider import FirstEpssIntelligenceProvider
from app.application.audit_service import AuditService
from shared_contracts.enums import (
    IntelligenceSourceType, IntelligenceRunStatus, FreshnessStatus
)

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IntelligenceIngestionService:
    """Service managing threat & vulnerability intelligence feed ingestion and canonical storage."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_or_create_source(
        self,
        org_id: str,
        source_name: str,
        source_type: str,
        config: Optional[Dict[str, Any]] = None
    ) -> IntelligenceSource:
        """Fetch or create tenant-scoped IntelligenceSource configuration."""
        stmt = select(IntelligenceSource).where(
            IntelligenceSource.org_id == org_id,
            IntelligenceSource.source_name == source_name
        )
        res = await self.db.execute(stmt)
        source = res.scalars().first()

        if not source:
            source = IntelligenceSource(
                org_id=org_id,
                source_name=source_name,
                source_type=source_type,
                config=config or {},
                is_enabled=True,
                created_at=utc_now(),
                updated_at=utc_now()
            )
            self.db.add(source)
            await self.db.flush()

        return source

    async def ingest_feed_payload(
        self,
        org_id: str,
        source_name: str,
        source_type: str,
        payload_content: str,
        actor_id: Optional[str] = None
    ) -> IntelligenceRun:
        """Ingest, validate, normalize, and store external intelligence feed payload."""
        source = await self.get_or_create_source(org_id, source_name, source_type)

        run = IntelligenceRun(
            org_id=org_id,
            source_id=source.id,
            status=IntelligenceRunStatus.RUNNING.value,
            started_at=utc_now(),
            records_ingested=0,
            records_updated=0
        )
        self.db.add(run)
        await self.db.flush()

        try:
            # Instantiate provider adapter
            provider: BaseIntelligenceProvider
            if source_type == IntelligenceSourceType.NVD.value:
                provider = NvdIntelligenceProvider(config=source.config)
            elif source_type == IntelligenceSourceType.CISA_KEV.value:
                provider = CisaKevIntelligenceProvider(config=source.config)
            elif source_type == IntelligenceSourceType.FIRST_EPSS.value:
                provider = FirstEpssIntelligenceProvider(config=source.config)
            else:
                provider = BaseIntelligenceProvider(source_name=source_name, source_type=source_type, config=source.config)

            # Parse and extract
            parsed_data = provider.parse_raw_payload(payload_content)
            extracted_records = provider.extract_records(parsed_data)

            ingested_count = 0
            updated_count = 0

            for rec_dict in extracted_records:
                ext_id = rec_dict["external_id"]
                new_rec_id = generate_uuid()
                now = utc_now()

                # Atomic upsert via SQLite ON CONFLICT DO UPDATE
                insert_stmt = sqlite_insert(IntelligenceRecord).values(
                    id=new_rec_id,
                    org_id=org_id,
                    source_id=source.id,
                    external_id=ext_id,
                    title=rec_dict.get("title", f"Record {ext_id}"),
                    description=rec_dict.get("description", ""),
                    severity=rec_dict.get("severity", "medium"),
                    cvss_v3_score=rec_dict.get("cvss_v3_score"),
                    cvss_vector=rec_dict.get("cvss_vector"),
                    cwe_ids=rec_dict.get("cwe_ids", []),
                    affected_product=rec_dict.get("affected_product", "unknown"),
                    affected_vendor=rec_dict.get("affected_vendor", "unknown"),
                    affected_cpe=rec_dict.get("affected_cpe"),
                    affected_version_range=rec_dict.get("affected_version_range"),
                    epss_score=rec_dict.get("epss_score"),
                    epss_percentile=rec_dict.get("epss_percentile"),
                    is_cisa_kev=rec_dict.get("is_cisa_kev", False),
                    exploit_availability=rec_dict.get("exploit_availability", "none"),
                    published_at=rec_dict.get("published_at", now),
                    updated_at=now,
                    retrieved_at=now,
                    freshness_status=FreshnessStatus.CURRENT.value,
                    raw_data=rec_dict.get("raw_data", {}),
                    provenance=rec_dict.get("provenance", {})
                ).on_conflict_do_update(
                    index_elements=['org_id', 'source_id', 'external_id'],
                    set_={
                        'title': rec_dict.get("title", f"Record {ext_id}"),
                        'description': rec_dict.get("description", ""),
                        'severity': rec_dict.get("severity", "medium"),
                        'cvss_v3_score': rec_dict.get("cvss_v3_score"),
                        'cvss_vector': rec_dict.get("cvss_vector"),
                        'cwe_ids': rec_dict.get("cwe_ids", []),
                        'affected_product': rec_dict.get("affected_product", "unknown"),
                        'affected_vendor': rec_dict.get("affected_vendor", "unknown"),
                        'affected_cpe': rec_dict.get("affected_cpe"),
                        'affected_version_range': rec_dict.get("affected_version_range"),
                        'epss_score': rec_dict.get("epss_score"),
                        'epss_percentile': rec_dict.get("epss_percentile"),
                        'is_cisa_kev': rec_dict.get("is_cisa_kev", False),
                        'exploit_availability': rec_dict.get("exploit_availability", "none"),
                        'updated_at': now,
                        'retrieved_at': now,
                        'freshness_status': FreshnessStatus.CURRENT.value,
                        'raw_data': rec_dict.get("raw_data", {}),
                        'provenance': rec_dict.get("provenance", {})
                    }
                )

                res = await self.db.execute(insert_stmt)
                ingested_count += 1

            source.last_retrieved_at = utc_now()
            source.updated_at = utc_now()

            run.status = IntelligenceRunStatus.COMPLETED.value
            run.completed_at = utc_now()
            run.records_ingested = len(extracted_records)
            run.records_updated = len(extracted_records)
            await self.db.commit()

            # Audit event
            AuditService.log_event(
                db_session=self.db,
                event_type="intelligence_ingestion_completed",
                resource_type="intelligence_source",
                ip_address="127.0.0.1",
                org_id=org_id,
                actor_id=actor_id,
                resource_id=source.id,
                details={
                    "source_name": source_name,
                    "records_ingested": len(extracted_records),
                    "run_id": run.id
                }
            )
            return run

        except Exception as exc:
            logger.exception("Intelligence feed ingestion failed for source %s, org %s", source_name, org_id)
            run.status = IntelligenceRunStatus.FAILED.value
            run.completed_at = utc_now()
            run.error_message = str(exc)
            await self.db.commit()

            AuditService.log_event(
                db_session=self.db,
                event_type="intelligence_ingestion_failed",
                resource_type="intelligence_source",
                ip_address="127.0.0.1",
                org_id=org_id,
                actor_id=actor_id,
                resource_id=source.id,
                details={"source_name": source_name, "error": str(exc), "run_id": run.id}
            )
            raise

    async def list_records(
        self,
        org_id: str,
        source_id: Optional[str] = None,
        affected_vendor: Optional[str] = None,
        affected_product: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[IntelligenceRecord]:
        """Fetch tenant-scoped intelligence records."""
        stmt = select(IntelligenceRecord).where(IntelligenceRecord.org_id == org_id)
        if source_id:
            stmt = stmt.where(IntelligenceRecord.source_id == source_id)
        if affected_vendor:
            stmt = stmt.where(IntelligenceRecord.affected_vendor.ilike(f"%{affected_vendor}%"))
        if affected_product:
            stmt = stmt.where(IntelligenceRecord.affected_product.ilike(f"%{affected_product}%"))

        stmt = stmt.order_by(IntelligenceRecord.retrieved_at.desc()).limit(limit).offset(offset)
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def get_record(self, org_id: str, record_id: str) -> Optional[IntelligenceRecord]:
        """Fetch tenant-scoped intelligence record detail."""
        stmt = select(IntelligenceRecord).where(
            IntelligenceRecord.id == record_id,
            IntelligenceRecord.org_id == org_id
        )
        res = await self.db.execute(stmt)
        return res.scalars().first()
