"""Phase 1E: Organizational Context & Controlled Memory API.

All endpoints are:
- Authenticated via session/RBAC
- Tenant-isolated (org_id checked against auth_ctx)
- Audited
- Rate-limited and validated
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_viewer, require_member, require_admin
from app.application.context_service import OrganizationalContextService
from app.application.decision_service import DecisionService
from app.application.controlled_learning_service import ControlledLearningService
from app.application.context_resolver import ContextResolver
from shared_contracts.schemas import (
    AssetContextUpdateRequest,
    AssetContextResponse,
    DecisionCreateRequest,
    DecisionRevokeRequest,
    DecisionResponse,
    DecisionListResponse,
    MemoryResponse,
    MemoryListResponse,
    ContextResolveRequest,
    ContextResolutionResponse,
    APIErrorDetail,
)

router = APIRouter(tags=["Organizational Context & Memory"])


@router.patch(
    "/organizations/{org_id}/assets/{asset_id}/context",
    response_model=AssetContextResponse,
    responses={403: {"model": APIErrorDetail}, 404: {"model": APIErrorDetail}},
)
async def update_asset_context(
    org_id: str,
    asset_id: str,
    body: AssetContextUpdateRequest,
    auth_ctx: dict = Depends(require_member),
    db: AsyncSession = Depends(get_db_session),
):
    """Update organizational metadata on an asset (Owner, Team, Environment, Criticality)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    service = OrganizationalContextService(db)
    try:
        context = await service.update_asset_context(
            org_id=org_id,
            asset_id=asset_id,
            actor_id=auth_ctx["user"].id,
            owner_id=body.owner_id,
            owner_team=body.owner_team,
            environment=body.environment,
            criticality=body.criticality,
            business_purpose=body.business_purpose,
            expected_exposure=body.expected_exposure,
        )
        await db.commit()
        return AssetContextResponse.model_validate(context, from_attributes=True)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/organizations/{org_id}/assets/{asset_id}/context",
    response_model=AssetContextResponse,
    responses={403: {"model": APIErrorDetail}, 404: {"model": APIErrorDetail}},
)
async def get_asset_context(
    org_id: str,
    asset_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieve organizational metadata for an asset."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    service = OrganizationalContextService(db)
    context = await service.get_asset_context(org_id=org_id, asset_id=asset_id)
    if not context:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset context not found")
    return AssetContextResponse.model_validate(context, from_attributes=True)


@router.post(
    "/organizations/{org_id}/decisions",
    response_model=DecisionResponse,
    status_code=status.HTTP_201_CREATED,
    responses={403: {"model": APIErrorDetail}},
)
async def create_decision(
    org_id: str,
    body: DecisionCreateRequest,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session),
):
    """Create an auditable human security decision (Requires Admin+ role)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    service = DecisionService(db)
    try:
        decision = await service.create_decision(
            org_id=org_id,
            actor_id=auth_ctx["user"].id,
            decision_type=body.decision_type.value,
            scope_level=body.scope_level.value,
            subject_identifier=body.subject_identifier,
            subject_type=body.subject_type or "asset",
            new_state=body.new_state,
            reason=body.reason,
            evidence=body.evidence,
            valid_until=body.valid_until,
            review_at=body.review_at,
        )
        await db.commit()
        return DecisionResponse.model_validate(decision, from_attributes=True)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/organizations/{org_id}/decisions",
    response_model=DecisionListResponse,
    responses={403: {"model": APIErrorDetail}},
)
async def list_decisions(
    org_id: str,
    decision_type: Optional[str] = Query(None, description="Filter by decision_type"),
    decision_status: Optional[str] = Query(None, alias="status", description="Filter by status"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List organizational security decisions (Paginated, Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    service = DecisionService(db)
    decisions, total = await service.list_decisions(
        org_id=org_id,
        decision_type=decision_type,
        status=decision_status,
        limit=limit,
        offset=offset,
    )
    return DecisionListResponse(
        items=[DecisionResponse.model_validate(d, from_attributes=True) for d in decisions],
        total=total,
    )


@router.post(
    "/organizations/{org_id}/decisions/{decision_id}/revoke",
    response_model=DecisionResponse,
    responses={403: {"model": APIErrorDetail}, 404: {"model": APIErrorDetail}},
)
async def revoke_decision(
    org_id: str,
    decision_id: str,
    body: DecisionRevokeRequest,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session),
):
    """Revoke an active security decision with immutable transition history (Requires Admin+ role)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    service = DecisionService(db)
    try:
        decision = await service.revoke_decision(
            org_id=org_id,
            decision_id=decision_id,
            actor_id=auth_ctx["user"].id,
            reason=body.reason,
        )
        await db.commit()
        return DecisionResponse.model_validate(decision, from_attributes=True)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/organizations/{org_id}/memories",
    response_model=MemoryListResponse,
    responses={403: {"model": APIErrorDetail}},
)
async def list_memories(
    org_id: str,
    category: Optional[str] = Query(None, description="Filter by category"),
    scope_level: Optional[str] = Query(None, description="Filter by scope_level"),
    memory_status: Optional[str] = Query("active", alias="status", description="Filter by status"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List active or historical organizational memories (Paginated, Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    learning_service = ControlledLearningService(db)
    memories, total = await learning_service.list_memories(
        org_id=org_id,
        category=category,
        scope_level=scope_level,
        status=memory_status,
        limit=limit,
        offset=offset,
    )
    return MemoryListResponse(
        items=[MemoryResponse.model_validate(m, from_attributes=True) for m in memories],
        total=total,
    )


@router.post(
    "/organizations/{org_id}/context/resolve",
    response_model=ContextResolutionResponse,
    responses={403: {"model": APIErrorDetail}},
)
async def resolve_context(
    org_id: str,
    body: ContextResolveRequest,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Resolve expected state and organizational context for a target with explainability trace (Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    resolver = ContextResolver(db)
    response = await resolver.resolve_context(
        org_id=org_id,
        target_type=body.target_type,
        target_identifier=body.target_identifier,
        domain_name=body.domain_name,
    )
    return response
