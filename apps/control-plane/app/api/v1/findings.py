from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_viewer, require_member
from app.application.finding_service import FindingService
from app.application.verification_service import VerificationService
from shared_contracts.schemas import (
    FindingResponse,
    FindingListResponse,
    FindingStatusUpdateRequest,
    VerificationResultResponse,
    APIErrorDetail,
)

router = APIRouter(tags=["Findings & Remediation Verification"])


@router.get(
    "/organizations/{org_id}/findings",
    response_model=FindingListResponse,
    responses={403: {"model": APIErrorDetail}},
)
async def list_findings(
    org_id: str,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (open, acknowledged, in_progress, resolved, reopened)"),
    asset_id: Optional[str] = Query(None, description="Filter by asset_id"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List tenant security findings (Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = FindingService(db)
    items, total = await service.list_findings(
        org_id=org_id,
        status=status_filter,
        asset_id=asset_id,
        limit=limit,
        offset=offset
    )

    finding_responses = [
        FindingResponse(
            id=f.id,
            org_id=f.org_id,
            change_id=f.change_id,
            asset_id=f.asset_id,
            risk_assessment_id=f.risk_assessment_id,
            status=f.status,
            title=f.title,
            description=f.description,
            acknowledged_by=f.acknowledged_by,
            acknowledged_at=f.acknowledged_at,
            resolved_at=f.resolved_at,
            reopened_at=f.reopened_at,
            created_at=f.created_at,
            updated_at=f.updated_at
        ) for f in items
    ]

    return FindingListResponse(items=finding_responses, total=total)


@router.get(
    "/organizations/{org_id}/findings/{finding_id}",
    response_model=FindingResponse,
    responses={403: {"model": APIErrorDetail}, 404: {"model": APIErrorDetail}},
)
async def get_finding(
    org_id: str,
    finding_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get security finding by ID (Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = FindingService(db)
    finding = await service.get_finding(org_id, finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    return FindingResponse(
        id=finding.id,
        org_id=finding.org_id,
        change_id=finding.change_id,
        asset_id=finding.asset_id,
        risk_assessment_id=finding.risk_assessment_id,
        status=finding.status,
        title=finding.title,
        description=finding.description,
        acknowledged_by=finding.acknowledged_by,
        acknowledged_at=finding.acknowledged_at,
        resolved_at=finding.resolved_at,
        reopened_at=finding.reopened_at,
        created_at=finding.created_at,
        updated_at=finding.updated_at
    )


@router.post(
    "/organizations/{org_id}/findings/{finding_id}/acknowledge",
    response_model=FindingResponse,
    responses={400: {"model": APIErrorDetail}, 403: {"model": APIErrorDetail}, 404: {"model": APIErrorDetail}},
)
async def acknowledge_finding(
    org_id: str,
    finding_id: str,
    req_body: FindingStatusUpdateRequest,
    req: Request,
    auth_ctx: dict = Depends(require_member),
    db: AsyncSession = Depends(get_db_session),
):
    """Acknowledge a security finding (Member+). Does NOT equal technical resolution."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = FindingService(db)
    client_ip = req.client.host if req.client else "unknown"

    try:
        finding = await service.acknowledge_finding(
            org_id=org_id,
            finding_id=finding_id,
            actor_id=auth_ctx["user"].id,
            reason=req_body.reason,
            ip_address=client_ip
        )
        await db.commit()
    except ValueError as ve:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    return FindingResponse(
        id=finding.id,
        org_id=finding.org_id,
        change_id=finding.change_id,
        asset_id=finding.asset_id,
        risk_assessment_id=finding.risk_assessment_id,
        status=finding.status,
        title=finding.title,
        description=finding.description,
        acknowledged_by=finding.acknowledged_by,
        acknowledged_at=finding.acknowledged_at,
        resolved_at=finding.resolved_at,
        reopened_at=finding.reopened_at,
        created_at=finding.created_at,
        updated_at=finding.updated_at
    )


@router.post(
    "/organizations/{org_id}/findings/{finding_id}/verify",
    response_model=VerificationResultResponse,
    responses={400: {"model": APIErrorDetail}, 403: {"model": APIErrorDetail}, 404: {"model": APIErrorDetail}},
)
async def verify_finding_remediation(
    org_id: str,
    finding_id: str,
    req: Request,
    scan_id: Optional[str] = Query(None, description="Optional target scan ID for verification"),
    auth_ctx: dict = Depends(require_member),
    db: AsyncSession = Depends(get_db_session),
):
    """Trigger evidence-backed remediation verification for a finding (Member+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = VerificationService(db)
    client_ip = req.client.host if req.client else "unknown"

    try:
        res = await service.verify_finding(
            org_id=org_id,
            finding_id=finding_id,
            target_scan_id=scan_id,
            actor_id=auth_ctx["user"].id,
            ip_address=client_ip
        )
        await db.commit()
    except ValueError as ve:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    return VerificationResultResponse(
        id=res.id,
        org_id=res.org_id,
        finding_id=res.finding_id,
        comparison_run_id=res.comparison_run_id,
        current_scan_id=res.current_scan_id,
        status=res.status,
        method=res.method,
        previous_observed_state=res.previous_observed_state,
        current_observed_state=res.current_observed_state,
        evidence=res.evidence,
        verified_at=res.verified_at
    )
