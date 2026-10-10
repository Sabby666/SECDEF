from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_admin, require_viewer
from app.api.dependencies.rate_limit import check_rate_limit
from app.application.scan_service import ScanService
from app.application.ingestion_service import IngestionService
from shared_contracts.schemas import ScanResponse, ObservationResponse
from shared_contracts.events import ScanResultPayload

router = APIRouter(tags=["Scans"])


@router.post(
    "/organizations/{org_id}/domains/{domain_id}/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED
)
async def trigger_domain_scan(
    org_id: str,
    domain_id: str,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Triggers a new scan for a verified domain.
    Requires Admin or Owner role. Rate limited.
    """
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    await check_rate_limit(key=f"trigger_scan_org:{org_id}", limit=10, window=900)

    service = ScanService(db)
    client_ip = req.client.host if req.client else "unknown"

    scan = await service.create_scan_job(
        org_id=org_id,
        domain_id=domain_id,
        actor_id=auth_ctx["user"].id,
        ip_address=client_ip
    )
    return scan


@router.get(
    "/organizations/{org_id}/scans",
    response_model=List[ScanResponse]
)
async def list_organization_scans(
    org_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    """List all scans for an organization."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = ScanService(db)
    scans = await service.get_scans_for_org(org_id)
    return scans


@router.get(
    "/organizations/{org_id}/scans/{scan_id}",
    response_model=ScanResponse
)
async def get_scan_details(
    org_id: str,
    scan_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    """Get scan status and details."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = ScanService(db)
    scan = await service.get_scan(org_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    return scan


@router.get(
    "/organizations/{org_id}/scans/{scan_id}/observations",
    response_model=List[ObservationResponse]
)
async def get_scan_observations(
    org_id: str,
    scan_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    """Get all raw observations produced by a scan."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = ScanService(db)
    scan = await service.get_scan(org_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    observations = await service.get_observations_for_scan(org_id, scan_id)
    return observations


@router.post(
    "/scans/results",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK
)
async def ingest_worker_scan_results(
    payload: ScanResultPayload,
    req: Request,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Authenticated Worker Ingestion Endpoint.
    Verifies worker payload HMAC signature and persists observations.
    """
    service = IngestionService(db)
    client_ip = req.client.host if req.client else "unknown"

    scan = await service.ingest_scan_result(payload, client_ip)
    return scan
