"""Phase 5 AI Assistance FastAPI Router.

Provides tenant-scoped endpoints for security investigation queries, conversation management,
and thread retrieval with server-side RBAC enforcement.
"""
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_viewer
from app.application.ai_service import AIService
from shared_contracts.enums import UserRole, AIResponseClassification

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations/{org_id}/assistant", tags=["AI Assistance"])


def verify_tenant_access(org_id: str, auth_ctx: dict):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )


class AIQueryRequest(BaseModel):
    query: str
    conversation_id: Optional[str] = None
    target_asset_id: Optional[str] = None
    target_exposure_id: Optional[str] = None
    target_finding_id: Optional[str] = None
    target_correlation_id: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "query": "Why is asset api.example.com high risk?",
                "target_asset_id": "ast-123"
            }
        }


class CreateConversationRequest(BaseModel):
    title: Optional[str] = "Security Investigation"


from app.api.dependencies.rate_limit import check_ai_rate_limits, acquire_ai_concurrency_slot


@router.post("/query", status_code=status.HTTP_200_OK)
async def process_ai_query(
    org_id: str,
    body: AIQueryRequest,
    req: Request,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_viewer)
):
    """Process natural language security investigation query with secure context assembly."""
    verify_tenant_access(org_id, auth_ctx)
    await check_ai_rate_limits(user_id=auth_ctx["user"].id, org_id=org_id)
    async with acquire_ai_concurrency_slot(org_id=org_id):
        client_ip = req.client.host if req.client else "127.0.0.1"
        ai_svc = AIService(db)

        try:
            res = await ai_svc.process_query(
                org_id=org_id,
                user_id=auth_ctx["user"].id,
                query=body.query,
                conversation_id=body.conversation_id,
                target_asset_id=body.target_asset_id,
                target_exposure_id=body.target_exposure_id,
                target_finding_id=body.target_finding_id,
                target_correlation_id=body.target_correlation_id,
                actor_ip=client_ip
            )
            return res
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("AI assistance query failed for org %s", org_id)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post("/conversations", status_code=status.HTTP_201_CREATED)
async def create_conversation(
    org_id: str,
    body: CreateConversationRequest,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_viewer)
):
    """Create a new tenant-isolated AI conversation session."""
    verify_tenant_access(org_id, auth_ctx)
    ai_svc = AIService(db)
    conv = await ai_svc.create_conversation(org_id, auth_ctx["user"].id, title=body.title)
    return {
        "id": conv.id,
        "org_id": conv.org_id,
        "user_id": conv.user_id,
        "title": conv.title,
        "created_at": conv.created_at.isoformat(),
        "updated_at": conv.updated_at.isoformat()
    }


@router.get("/conversations", status_code=status.HTTP_200_OK)
async def list_conversations(
    org_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_viewer)
):
    """Fetch tenant-scoped AI conversation sessions."""
    verify_tenant_access(org_id, auth_ctx)
    ai_svc = AIService(db)
    convs = await ai_svc.list_conversations(org_id, user_id=auth_ctx["user"].id, limit=limit, offset=offset)
    return {
        "items": [
            {
                "id": c.id,
                "org_id": c.org_id,
                "user_id": c.user_id,
                "title": c.title,
                "created_at": c.created_at.isoformat(),
                "updated_at": c.updated_at.isoformat()
            } for c in convs
        ],
        "limit": limit,
        "offset": offset
    }


@router.get("/conversations/{conversation_id}", status_code=status.HTTP_200_OK)
async def get_conversation_thread(
    org_id: str,
    conversation_id: str,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_viewer)
):
    """Fetch messages within a tenant-scoped conversation thread."""
    verify_tenant_access(org_id, auth_ctx)
    ai_svc = AIService(db)
    conv = await ai_svc.get_conversation(org_id, conversation_id)
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")

    messages = await ai_svc.get_conversation_messages(org_id, conversation_id)
    return {
        "conversation": {
            "id": conv.id,
            "org_id": conv.org_id,
            "title": conv.title,
            "created_at": conv.created_at.isoformat()
        },
        "messages": [
            {
                "id": m.id,
                "sender_type": m.sender_type,
                "content": m.content,
                "structured_data": m.structured_data,
                "created_at": m.created_at.isoformat()
            } for m in messages
        ]
    }
