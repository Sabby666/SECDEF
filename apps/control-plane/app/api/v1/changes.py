"""Phase 1D: Read-only change retrieval API.

All endpoints are:
- Authenticated (require_viewer — viewer+ access)
- Tenant-isolated (org_id enforced before any query)
- Deterministically ordered (detected_at DESC)
- Paginated
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_viewer
from app.infrastructure.db.models import Change, ComparisonRun
from shared_contracts.schemas import (
    ChangeResponse,
    ChangeListResponse,
    ComparisonRunResponse,
    ComparisonRunListResponse,
    APIErrorDetail,
)

router = APIRouter(tags=["Changes"])


@router.get(
    "/organizations/{org_id}/changes",
    response_model=ChangeListResponse,
    responses={403: {"model": APIErrorDetail}},
)
async def list_changes(
    org_id: str,
    change_type: Optional[str] = Query(None, description="Filter by change_type"),
    entity_type: Optional[str] = Query(None, description="Filter by entity_type (asset, relationship)"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List detected changes for the organization with optional filtering."""
    # TENANT ISOLATION: Verify caller belongs to the requested org
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    query = (
        select(Change)
        .where(Change.org_id == org_id)
        .order_by(Change.detected_at.desc())
    )

    if change_type:
        query = query.where(Change.change_type == change_type)
    if entity_type:
        query = query.where(Change.entity_type == entity_type)

    # Count total (without pagination)
    from sqlalchemy import func

    count_query = (
        select(func.count())
        .select_from(Change)
        .where(Change.org_id == org_id)
    )
    if change_type:
        count_query = count_query.where(Change.change_type == change_type)
    if entity_type:
        count_query = count_query.where(Change.entity_type == entity_type)

    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Apply pagination
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    changes = result.scalars().all()

    return ChangeListResponse(
        items=[
            ChangeResponse.model_validate(c, from_attributes=True)
            for c in changes
        ],
        total=total,
    )


@router.get(
    "/organizations/{org_id}/changes/{change_id}",
    response_model=ChangeResponse,
    responses={
        403: {"model": APIErrorDetail},
        404: {"model": APIErrorDetail},
    },
)
async def get_change(
    org_id: str,
    change_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get a single change detail by ID."""
    # TENANT ISOLATION
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    result = await db.execute(
        select(Change).where(Change.id == change_id, Change.org_id == org_id)
    )
    change = result.scalars().first()

    if not change:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Change not found",
        )

    return ChangeResponse.model_validate(change, from_attributes=True)


@router.get(
    "/organizations/{org_id}/comparisons",
    response_model=ComparisonRunListResponse,
    responses={403: {"model": APIErrorDetail}},
)
async def list_comparisons(
    org_id: str,
    comparison_status: Optional[str] = Query(None, alias="status", description="Filter by comparison status"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List comparison runs for the organization."""
    # TENANT ISOLATION
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

    query = (
        select(ComparisonRun)
        .where(ComparisonRun.org_id == org_id)
        .order_by(ComparisonRun.created_at.desc())
    )

    if comparison_status:
        query = query.where(ComparisonRun.status == comparison_status)

    from sqlalchemy import func

    count_query = (
        select(func.count())
        .select_from(ComparisonRun)
        .where(ComparisonRun.org_id == org_id)
    )
    if comparison_status:
        count_query = count_query.where(ComparisonRun.status == comparison_status)

    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    comparisons = result.scalars().all()

    return ComparisonRunListResponse(
        items=[
            ComparisonRunResponse.model_validate(c, from_attributes=True)
            for c in comparisons
        ],
        total=total,
    )
