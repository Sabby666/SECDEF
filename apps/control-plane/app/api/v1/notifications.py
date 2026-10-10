from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_viewer, require_admin
from app.api.dependencies.rate_limit import check_rate_limit
from app.application.notification_service import NotificationService
from app.infrastructure.notifications.webhook_delivery import WebhookDeliveryService
from shared_contracts.schemas import (
    NotificationResponse,
    NotificationListResponse,
    NotificationDestinationCreateRequest,
    NotificationDestinationResponse,
    NotificationPolicyCreateRequest,
    NotificationPolicyResponse,
    WebhookTestRequest,
    APIErrorDetail,
)

router = APIRouter(tags=["Notifications & Webhooks"])


@router.get(
    "/organizations/{org_id}/notifications",
    response_model=NotificationListResponse,
    responses={403: {"model": APIErrorDetail}},
)
async def list_notifications(
    org_id: str,
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List tenant notification history (Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = NotificationService(db)
    items, total = await service.list_notifications(org_id=org_id, limit=limit, offset=offset)

    responses = [
        NotificationResponse(
            id=n.id,
            org_id=n.org_id,
            finding_id=n.finding_id,
            risk_assessment_id=n.risk_assessment_id,
            change_id=n.change_id,
            verification_result_id=n.verification_result_id,
            trigger_type=n.trigger_type,
            title=n.title,
            summary=n.summary,
            content_payload=n.content_payload,
            event_identity=n.event_identity,
            created_at=n.created_at
        ) for n in items
    ]

    return NotificationListResponse(items=responses, total=total)


@router.get(
    "/organizations/{org_id}/notifications/destinations",
    response_model=List[NotificationDestinationResponse],
    responses={403: {"model": APIErrorDetail}},
)
async def list_destinations(
    org_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List configured notification destinations (Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = NotificationService(db)
    destinations = await service.list_destinations(org_id=org_id)

    return [
        NotificationDestinationResponse(
            id=d.id,
            org_id=d.org_id,
            channel=d.channel,
            name=d.name,
            config=d.config,
            is_active=d.is_active,
            created_at=d.created_at,
            updated_at=d.updated_at
        ) for d in destinations
    ]


@router.post(
    "/organizations/{org_id}/notifications/destinations",
    response_model=NotificationDestinationResponse,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": APIErrorDetail}, 403: {"model": APIErrorDetail}},
)
async def create_destination(
    org_id: str,
    req_body: NotificationDestinationCreateRequest,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session),
):
    """Create a new notification destination (Admin only)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = NotificationService(db)
    client_ip = req.client.host if req.client else "unknown"

    try:
        dest = await service.create_destination(
            org_id=org_id,
            channel=req_body.channel,
            name=req_body.name,
            config=req_body.config,
            actor_id=auth_ctx["user"].id,
            ip_address=client_ip
        )
        await db.commit()
    except ValueError as ve:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    return NotificationDestinationResponse(
        id=dest.id,
        org_id=dest.org_id,
        channel=dest.channel,
        name=dest.name,
        config=dest.config,
        is_active=dest.is_active,
        created_at=dest.created_at,
        updated_at=dest.updated_at
    )


@router.post(
    "/organizations/{org_id}/notifications/destinations/test",
    responses={400: {"model": APIErrorDetail}, 403: {"model": APIErrorDetail}, 429: {"model": APIErrorDetail}},
)
async def test_webhook_destination(
    org_id: str,
    req_body: WebhookTestRequest,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
):
    """Test webhook delivery with egress safety guard (Rate Limited, Admin only)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    # Rate limiting: Max 5 webhook test requests per minute per org
    await check_rate_limit(key=f"webhook_test_org:{org_id}", limit=5, window=60)

    success, code, msg = WebhookDeliveryService.deliver_webhook(
        url=req_body.url,
        payload={
            "test": True,
            "message": "ASM Webhook Delivery Test",
            "org_id": org_id
        },
        signing_secret=req_body.signing_secret
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook test failed (HTTP {code}): {msg}"
        )

    return {"status": "success", "response_code": code, "message": msg}


@router.get(
    "/organizations/{org_id}/notifications/policies",
    response_model=List[NotificationPolicyResponse],
    responses={403: {"model": APIErrorDetail}},
)
async def list_policies(
    org_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List notification policies (Viewer+)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = NotificationService(db)
    policies = await service.list_policies(org_id=org_id)

    return [
        NotificationPolicyResponse(
            id=p.id,
            org_id=p.org_id,
            policy_version=p.policy_version,
            name=p.name,
            min_risk_band=p.min_risk_band,
            trigger_types=p.trigger_types,
            destination_ids=p.destination_ids,
            cooldown_minutes=p.cooldown_minutes,
            is_active=p.is_active,
            created_at=p.created_at,
            updated_at=p.updated_at
        ) for p in policies
    ]


@router.post(
    "/organizations/{org_id}/notifications/policies",
    response_model=NotificationPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": APIErrorDetail}, 403: {"model": APIErrorDetail}},
)
async def create_policy(
    org_id: str,
    req_body: NotificationPolicyCreateRequest,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session),
):
    """Create notification policy (Admin only)."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    service = NotificationService(db)
    client_ip = req.client.host if req.client else "unknown"

    try:
        policy = await service.create_policy(
            org_id=org_id,
            name=req_body.name,
            min_risk_band=req_body.min_risk_band,
            trigger_types=req_body.trigger_types,
            destination_ids=req_body.destination_ids,
            cooldown_minutes=req_body.cooldown_minutes,
            actor_id=auth_ctx["user"].id,
            ip_address=client_ip
        )
        await db.commit()
    except ValueError as ve:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    return NotificationPolicyResponse(
        id=policy.id,
        org_id=policy.org_id,
        policy_version=policy.policy_version,
        name=policy.name,
        min_risk_band=policy.min_risk_band,
        trigger_types=policy.trigger_types,
        destination_ids=policy.destination_ids,
        cooldown_minutes=policy.cooldown_minutes,
        is_active=policy.is_active,
        created_at=policy.created_at,
        updated_at=policy.updated_at
    )
