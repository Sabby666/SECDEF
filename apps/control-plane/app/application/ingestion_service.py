import hmac
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.models import Scan, Observation
from app.application.audit_service import AuditService
from app.application.asset_resolution_service import AssetResolutionService
from app.application.change_detection_service import ChangeDetectionService
from shared_contracts.events import ScanResultPayload

logger = logging.getLogger(__name__)


SCANNER_HMAC_SECRET = os.getenv("SCANNER_HMAC_SECRET", "dev-scanner-hmac-secret-key")
MAX_QUEUE_PAYLOAD_BYTES = 50 * 1024 * 1024  # 50 MB hard cap payload limit


def verify_hmac_signature(secret: str, scan_id: str, org_id: str, job_nonce: str, signature: str) -> bool:
    """Constant-time HMAC-SHA256 signature verification."""
    message = f"{scan_id}:{org_id}:{job_nonce}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


class IngestionService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def ingest_scan_result(
        self,
        payload: ScanResultPayload,
        client_ip: str,
        hmac_secret: str = SCANNER_HMAC_SECRET
    ) -> Scan:
        """
        Ingests untrusted scanner worker result payload:
        1. HMAC Signature Verification (constant-time).
        2. Schema Version Enforcer (v1.0).
        3. Replay / Idempotency Check (job_nonce & scan_id match).
        4. Payload Size Cap (50 MB Limit).
        5. Data Sanitization & Persistence into Observations table.
        6. Phase 1C: Asset Resolution & Relationship Graph update.
        7. Phase 1D: Deterministic Change Detection.
        """
        # 1. HMAC Signature Check
        if not verify_hmac_signature(hmac_secret, payload.scan_id, payload.org_id, payload.job_nonce, payload.signature):
            logger.warning(f"HMAC Signature Verification Failed for scan result {payload.scan_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid worker payload HMAC signature"
            )

        # 2. Schema Version Check
        if payload.schema_version != "1.0":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported contract schema_version '{payload.schema_version}'"
            )

        # 3. Payload Cap Limit Check
        payload_str = payload.model_dump_json()
        if len(payload_str.encode("utf-8")) > MAX_QUEUE_PAYLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Result payload exceeds 50 MB payload cap limit"
            )

        # 4. Fetch Scan & Replay/Idempotency Check
        result = await self.db.execute(
            select(Scan).where(Scan.id == payload.scan_id, Scan.org_id == payload.org_id)
        )
        scan = result.scalars().first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan job not found or organization mismatch"
            )

        if scan.job_nonce != payload.job_nonce:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Replay Defense: Invalid job_nonce or replayed result payload"
            )

        if scan.status == "completed":
            logger.info(f"Idempotent skip: Scan {scan.id} is already completed.")
            return scan

        # 5. Sanitize & Persist Observations
        scan.status = payload.status if payload.status in ("completed", "failed") else "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = payload.error_message

        created_observations = []
        for obs in payload.observations:
            observation_type = str(obs.get("observation_type", "unknown"))[:50]
            target = str(obs.get("target", payload.target_domain))[:255]
            raw_data = obs.get("raw_data", {})

            observation = Observation(
                org_id=payload.org_id,
                scan_id=scan.id,
                observation_type=observation_type,
                target=target,
                raw_data=raw_data,
                observed_at=datetime.now(timezone.utc)
            )
            self.db.add(observation)
            created_observations.append(observation)

        # Log audit event
        AuditService.log_event(
            db_session=self.db,
            event_type="scan.completed" if scan.status == "completed" else "scan.failed",
            resource_type="scan",
            resource_id=scan.id,
            org_id=payload.org_id,
            actor_id=f"worker-{payload.worker_id}",
            ip_address=client_ip,
            details={"observation_count": len(payload.observations), "worker_id": payload.worker_id}
        )

        # 6. Run Phase 1C Asset Resolution & Relationship Graph update
        if created_observations:
            resolver = AssetResolutionService(self.db)
            await resolver.resolve_observations_for_scan(
                scan_id=scan.id,
                org_id=scan.org_id,
                domain_id=scan.domain_id,
                observations=created_observations
            )

        # 7. Run Phase 1D Change Detection
        # Only for completed or partial scans; failed scans skip comparison
        if scan.status in ("completed", "partial"):
            try:
                change_detector = ChangeDetectionService(self.db)
                await change_detector.detect_changes_for_scan(
                    scan_id=scan.id,
                    org_id=scan.org_id,
                    domain_id=scan.domain_id,
                )
            except Exception as e:
                # Change detection errors must not fail ingestion pipeline
                # Log and continue — the scan data is already persisted
                logger.error(
                    "change_detection_error",
                    extra={
                        "scan_id": scan.id,
                        "org_id": scan.org_id,
                        "error": str(e),
                    },
                )

        await self.db.commit()
        await self.db.refresh(scan)

        return scan
