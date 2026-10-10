"""FastAPI endpoints for Phase 3 Exposure Intelligence & Attack Surface Correlation."""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_admin, require_member, require_viewer
from app.application.exposure_correlation_service import ExposureCorrelationService
from app.application.exposure_graph_service import ExposureGraphService
from app.infrastructure.db.models import ExposureCondition, ExposurePath

router = APIRouter(tags=["Exposure Intelligence"])


def verify_tenant_access(org_id: str, auth_ctx: dict):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )


# Response DTOs
class ExposureConditionResponse(BaseModel):
    id: str
    org_id: str
    condition_type: str
    status: str
    priority_band: str
    title: str
    description: str
    explanation: str
    primary_asset_id: str
    risk_assessment_id: Optional[str] = None
    finding_id: Optional[str] = None
    change_id: Optional[str] = None
    rule_version: str
    first_seen_at: str
    last_seen_at: str
    resolved_at: Optional[str] = None
    reopened_at: Optional[str] = None
    provenance: Dict[str, Any]

    class Config:
        from_attributes = True


class ExposureEvidenceResponse(BaseModel):
    id: str
    org_id: str
    condition_id: str
    evidence_type: str
    evidence_ref_id: str
    details: Optional[Dict[str, Any]] = None
    observed_at: str

    class Config:
        from_attributes = True


class ExposurePathResponse(BaseModel):
    id: str
    org_id: str
    condition_id: str
    start_asset_id: str
    end_asset_id: str
    path_length: int
    nodes_snapshot: List[Dict[str, Any]]
    edges_snapshot: List[Dict[str, Any]]
    explanation: str
    created_at: str

    class Config:
        from_attributes = True


class ExposureCorrelationRunResponse(BaseModel):
    id: str
    org_id: str
    rule_version: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    conditions_detected: int
    paths_detected: int
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


@router.get(
    "/organizations/{org_id}/exposures",
    response_model=List[ExposureConditionResponse],
)
async def list_exposures(
    org_id: str,
    status: Optional[str] = Query(None),
    condition_type: Optional[str] = Query(None),
    priority_band: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List tenant-scoped exposure conditions (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = ExposureCorrelationService(db)
    exposures = await svc.list_exposures(
        org_id=org_id,
        status=status,
        condition_type=condition_type,
        priority_band=priority_band,
        limit=limit,
        offset=offset,
    )
    return [
        ExposureConditionResponse(
            id=e.id,
            org_id=e.org_id,
            condition_type=e.condition_type,
            status=e.status,
            priority_band=e.priority_band,
            title=e.title,
            description=e.description,
            explanation=e.explanation,
            primary_asset_id=e.primary_asset_id,
            risk_assessment_id=e.risk_assessment_id,
            finding_id=e.finding_id,
            change_id=e.change_id,
            rule_version=e.rule_version,
            first_seen_at=e.first_seen_at.isoformat() if e.first_seen_at else "",
            last_seen_at=e.last_seen_at.isoformat() if e.last_seen_at else "",
            resolved_at=e.resolved_at.isoformat() if e.resolved_at else None,
            reopened_at=e.reopened_at.isoformat() if e.reopened_at else None,
            provenance=e.provenance or {},
        )
        for e in exposures
    ]


@router.get(
    "/organizations/{org_id}/exposures/{id}",
    response_model=ExposureConditionResponse,
)
async def get_exposure(
    org_id: str,
    id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get single tenant-scoped exposure condition detail (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = ExposureCorrelationService(db)
    e = await svc.get_exposure(org_id, id)
    if not e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exposure condition not found",
        )
    return ExposureConditionResponse(
        id=e.id,
        org_id=e.org_id,
        condition_type=e.condition_type,
        status=e.status,
        priority_band=e.priority_band,
        title=e.title,
        description=e.description,
        explanation=e.explanation,
        primary_asset_id=e.primary_asset_id,
        risk_assessment_id=e.risk_assessment_id,
        finding_id=e.finding_id,
        change_id=e.change_id,
        rule_version=e.rule_version,
        first_seen_at=e.first_seen_at.isoformat() if e.first_seen_at else "",
        last_seen_at=e.last_seen_at.isoformat() if e.last_seen_at else "",
        resolved_at=e.resolved_at.isoformat() if e.resolved_at else None,
        reopened_at=e.reopened_at.isoformat() if e.reopened_at else None,
        provenance=e.provenance or {},
    )


@router.get(
    "/organizations/{org_id}/exposures/{id}/evidence",
    response_model=List[ExposureEvidenceResponse],
)
async def get_exposure_evidence(
    org_id: str,
    id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get evidence links for an exposure condition (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = ExposureCorrelationService(db)
    e = await svc.get_exposure(org_id, id)
    if not e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exposure condition not found",
        )
    ev_items = await svc.get_exposure_evidence(org_id, id)
    return [
        ExposureEvidenceResponse(
            id=ev.id,
            org_id=ev.org_id,
            condition_id=ev.condition_id,
            evidence_type=ev.evidence_type,
            evidence_ref_id=ev.evidence_ref_id,
            details=ev.details,
            observed_at=ev.observed_at.isoformat() if ev.observed_at else "",
        )
        for ev in ev_items
    ]


@router.get(
    "/organizations/{org_id}/exposures/{id}/path",
    response_model=List[ExposurePathResponse],
)
async def get_exposure_paths(
    org_id: str,
    id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get derived exposure path graphs for an exposure condition (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = ExposureCorrelationService(db)
    e = await svc.get_exposure(org_id, id)
    if not e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exposure condition not found",
        )
    
    stmt = select(ExposurePath).where(
        ExposurePath.condition_id == id,
        ExposurePath.org_id == org_id
    )
    res = await db.execute(stmt)
    paths = res.scalars().all()

    return [
        ExposurePathResponse(
            id=p.id,
            org_id=p.org_id,
            condition_id=p.condition_id,
            start_asset_id=p.start_asset_id,
            end_asset_id=p.end_asset_id,
            path_length=p.path_length,
            nodes_snapshot=p.nodes_snapshot,
            edges_snapshot=p.edges_snapshot,
            explanation=p.explanation,
            created_at=p.created_at.isoformat() if p.created_at else "",
        )
        for p in paths
    ]


@router.post(
    "/organizations/{org_id}/exposures/correlate",
    response_model=ExposureCorrelationRunResponse,
    status_code=status.HTTP_201_CREATED,
)
async def trigger_correlation_run(
    org_id: str,
    auth_ctx: dict = Depends(require_member),
    db: AsyncSession = Depends(get_db_session),
):
    """Trigger exposure correlation run for organization (RBAC: Member+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = ExposureCorrelationService(db)
    run = await svc.run_exposure_correlation(org_id)
    return ExposureCorrelationRunResponse(
        id=run.id,
        org_id=run.org_id,
        rule_version=run.rule_version,
        status=run.status,
        started_at=run.started_at.isoformat() if run.started_at else None,
        completed_at=run.completed_at.isoformat() if run.completed_at else None,
        conditions_detected=run.conditions_detected,
        paths_detected=run.paths_detected,
        error_message=run.error_message,
    )
