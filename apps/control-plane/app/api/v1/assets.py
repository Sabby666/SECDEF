from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_viewer
from app.infrastructure.db.models import Asset, AssetRelationship
from shared_contracts.schemas import (
    AssetResponse,
    AssetRelationshipResponse,
    AssetListResponse,
    AssetRelationshipListResponse,
    APIErrorDetail
)

router = APIRouter(tags=["Assets"])


@router.get(
    "/organizations/{org_id}/assets",
    response_model=AssetListResponse,
    responses={403: {"model": APIErrorDetail}}
)
async def list_assets(
    org_id: str,
    asset_type: Optional[str] = Query(None, description="Filter by asset_type (subdomain, ip_address, service, certificate)"),
    environment: Optional[str] = Query(None, description="Filter by environment"),
    status_val: Optional[str] = Query(None, alias="status", description="Filter by asset status"),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    """List tenant assets with optional filtering."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    query = select(Asset).where(Asset.org_id == org_id)

    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if environment:
        query = query.where(Asset.environment == environment)
    if status_val:
        query = query.where(Asset.status == status_val)

    result = await db.execute(query)
    assets = result.scalars().all()

    return AssetListResponse(
        items=[AssetResponse.model_validate(a, from_attributes=True) for a in assets],
        total=len(assets)
    )


@router.get(
    "/organizations/{org_id}/assets/{asset_id}",
    response_model=AssetResponse,
    responses={403: {"model": APIErrorDetail}, 404: {"model": APIErrorDetail}}
)
async def get_asset(
    org_id: str,
    asset_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    """Get single asset details by ID."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
    )
    asset = result.scalars().first()

    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return AssetResponse.model_validate(asset, from_attributes=True)


@router.get(
    "/organizations/{org_id}/assets/{asset_id}/relationships",
    response_model=AssetRelationshipListResponse,
    responses={403: {"model": APIErrorDetail}, 404: {"model": APIErrorDetail}}
)
async def get_asset_relationships(
    org_id: str,
    asset_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    """List directed graph relationships involving the specified asset."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    # Ensure asset exists in tenant
    asset_res = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
    )
    if not asset_res.scalars().first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    result = await db.execute(
        select(AssetRelationship).where(
            AssetRelationship.org_id == org_id,
            or_(
                AssetRelationship.source_asset_id == asset_id,
                AssetRelationship.target_asset_id == asset_id
            )
        )
    )
    rels = result.scalars().all()

    return AssetRelationshipListResponse(
        items=[AssetRelationshipResponse.model_validate(r, from_attributes=True) for r in rels],
        total=len(rels)
    )


@router.get(
    "/organizations/{org_id}/relationships",
    response_model=AssetRelationshipListResponse,
    responses={403: {"model": APIErrorDetail}}
)
async def list_relationships(
    org_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    """List all asset relationships for the organization."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    result = await db.execute(
        select(AssetRelationship).where(AssetRelationship.org_id == org_id)
    )
    rels = result.scalars().all()

    return AssetRelationshipListResponse(
        items=[AssetRelationshipResponse.model_validate(r, from_attributes=True) for r in rels],
        total=len(rels)
    )
