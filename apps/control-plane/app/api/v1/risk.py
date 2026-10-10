"""Phase 1F: Contextual Risk Engine API.

Endpoints for viewing risk assessments, inspecting factor breakdowns,
and triggering deterministic risk recalculations.

SECURITY INVARIANTS:
1. Multi-Tenant Isolated: org_id in path verified against auth_ctx["org"].id.
2. RBAC Enforced: GET (Viewer+), Recalculate (Member+).
3. No Score Manipulation: Users cannot submit raw risk scores. Scores are computed by RiskEngineService.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_viewer, require_member
from app.api.dependencies.rate_limit import (
    check_recalculate_rate_limits,
    acquire_recalculate_concurrency_slot,
)
from app.application.risk_engine_service import RiskEngineService
from app.application.audit_service import AuditService
from shared_contracts.schemas import (
    RiskAssessmentResponse,
    RiskAssessmentListResponse,
    RiskRecalculateRequest,
    APIErrorDetail,
)

router = APIRouter(tags=["Contextual Risk Engine"])


@router.get(
    "/organizations/{org_id}/risk/assessments",
    response_model=RiskAssessmentListResponse,
    responses={403: {"model": APIErrorDetail}},
)
async def list_risk_assessments(
    org_id: str,
    risk_band: Optional[str] = Query(None, description="Filter by risk_band (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    asset_id: Optional[str] = Query(None, description="Filter by asset_id"),
    change_id: Optional[str] = Query(None, description="Filter by change_id"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List tenant contextual risk assessments (Paginated, Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    service = RiskEngineService(db)
    assessments, total = await service.list_assessments(
        org_id=org_id,
        risk_band=risk_band,
        asset_id=asset_id,
        change_id=change_id,
        limit=limit,
        offset=offset,
    )

    return RiskAssessmentListResponse(
        items=[RiskAssessmentResponse.model_validate(a, from_attributes=True) for a in assessments],
        total=total,
    )


@router.get(
    "/organizations/{org_id}/risk/assessments/{assessment_id}",
    response_model=RiskAssessmentResponse,
    responses={403: {"model": APIErrorDetail}, 404: {"model": APIErrorDetail}},
)
async def get_risk_assessment_detail(
    org_id: str,
    assessment_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get detailed risk assessment with factor breakdown and provenance trace (Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    service = RiskEngineService(db)
    assessment = await service.get_assessment(org_id=org_id, assessment_id=assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk assessment {assessment_id} not found",
        )

    return RiskAssessmentResponse.model_validate(assessment, from_attributes=True)


@router.post(
    "/organizations/{org_id}/risk/recalculate",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": APIErrorDetail},
        403: {"model": APIErrorDetail},
        404: {"model": APIErrorDetail},
        429: {"model": APIErrorDetail},
    },
)
async def recalculate_risk(
    org_id: str,
    body: RiskRecalculateRequest,
    auth_ctx: dict = Depends(require_member),
    db: AsyncSession = Depends(get_db_session),
):
    """Trigger deterministic risk assessment recalculation for a change (Member+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    if not body.change_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="change_id is required for risk recalculation",
        )

    actor_id = auth_ctx["user"].id
    model_version = body.risk_model_version or "v1"

    # 1. Audit log event for recalculation attempt
    AuditService.log_event(
        db_session=db,
        event_type="risk_assessment.recalculate_attempted",
        resource_type="change",
        ip_address="127.0.0.1",
        resource_id=body.change_id,
        org_id=org_id,
        actor_id=actor_id,
        details={"change_id": body.change_id, "model_version": model_version},
    )

    # 2. Rate Limit Enforcement (per-user 10/min, per-organization 30/min)
    try:
        await check_recalculate_rate_limits(user_id=actor_id, org_id=org_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            AuditService.log_event(
                db_session=db,
                event_type="risk_assessment.recalculate_rate_limited",
                resource_type="organization",
                ip_address="127.0.0.1",
                resource_id=org_id,
                org_id=org_id,
                actor_id=actor_id,
                details={"reason": str(exc.detail)},
            )
            await db.commit()
        raise exc

    # 3. Concurrency Slot Limit Enforcement & Model Execution
    service = RiskEngineService(db)
    try:
        async with acquire_recalculate_concurrency_slot(org_id=org_id, max_concurrent=2):
            assessment = await service.assess_change_risk(
                org_id=org_id,
                change_id=body.change_id,
                risk_model_version=model_version,
            )
            await db.commit()
            return RiskAssessmentResponse.model_validate(assessment, from_attributes=True)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS and "Concurrent" in str(exc.detail):
            AuditService.log_event(
                db_session=db,
                event_type="risk_assessment.recalculate_concurrency_exceeded",
                resource_type="organization",
                ip_address="127.0.0.1",
                resource_id=org_id,
                org_id=org_id,
                actor_id=actor_id,
                details={"reason": str(exc.detail)},
            )
            await db.commit()
        raise exc
    except ValueError as e:
        err_msg = str(e)
        if "Unsupported or invalid risk_model_version" in err_msg or "required" in err_msg:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=err_msg)

