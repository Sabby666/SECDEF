"""Phase 6 Action Execution & Approval Router.

Provides tenant-isolated REST endpoints to propose, approve, execute, verify,
rollback, and audit security action executions with RBAC enforcement.
"""
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.session import get_db_session
from app.infrastructure.db.models import ActionExecution, ActionApproval, ActionVerification, ActionRollback
from app.api.dependencies.auth import require_viewer, require_member, require_admin
from app.application.action_service import ActionService
from shared_contracts.enums import UserRole

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations/{org_id}/actions", tags=["Action Orchestration"])


def verify_tenant_access(org_id: str, auth_ctx: dict):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")


class ProposeActionRequest(BaseModel):
    action_type: str
    target_type: str
    target_identifier: str
    action_parameters: Dict[str, Any]
    correlation_id: Optional[str] = None
    automation_depth: int = 0
    parent_execution_id: Optional[str] = None


class ApproveActionRequest(BaseModel):
    decision: str  # APPROVED / REJECTED
    reason: Optional[str] = None


@router.post("/propose", status_code=status.HTTP_201_CREATED)
async def propose_action(
    org_id: str,
    body: ProposeActionRequest,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_member)
):
    verify_tenant_access(org_id, auth_ctx)
    import json
    if len(json.dumps(body.action_parameters)) > 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Action parameters payload exceeds 1MB limit"
        )
    action_svc = ActionService(db)
    role_enum = UserRole(auth_ctx["role"])

    try:
        execution = await action_svc.propose_action(
            org_id=org_id,
            actor_id=auth_ctx["user"].id,
            actor_role=role_enum,
            action_type=body.action_type,
            target_type=body.target_type,
            target_identifier=body.target_identifier,
            action_parameters=body.action_parameters,
            correlation_id=body.correlation_id,
            automation_depth=body.automation_depth,
            parent_execution_id=body.parent_execution_id
        )
        return {
            "id": execution.id,
            "org_id": execution.org_id,
            "action_type": execution.action_type,
            "target_type": execution.target_type,
            "target_identifier": execution.target_identifier,
            "risk_class": execution.risk_class,
            "execution_state": execution.execution_state,
            "authorization_state": execution.authorization_state,
            "approval_requirement": execution.approval_requirement,
            "idempotency_key": execution.idempotency_key,
            "correlation_id": execution.correlation_id,
            "created_at": execution.created_at.isoformat()
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/{action_id}/approve", status_code=status.HTTP_200_OK)
async def approve_action(
    org_id: str,
    action_id: str,
    body: ApproveActionRequest,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_member)
):
    """Approve or reject a pending action execution (Requires Member/Admin role)."""
    verify_tenant_access(org_id, auth_ctx)
    action_svc = ActionService(db)
    role_enum = UserRole(auth_ctx["role"])

    try:
        execution = await action_svc.approve_action(
            org_id=org_id,
            approver_user_id=auth_ctx["user"].id,
            approver_role=role_enum,
            action_execution_id=action_id,
            decision=body.decision,
            reason=body.reason
        )
        return {
            "id": execution.id,
            "org_id": execution.org_id,
            "action_type": execution.action_type,
            "execution_state": execution.execution_state,
            "authorization_state": execution.authorization_state,
            "updated_at": execution.updated_at.isoformat()
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/{action_id}/execute", status_code=status.HTTP_200_OK)
async def execute_action(
    org_id: str,
    action_id: str,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_member)
):
    """Execute an approved security action."""
    verify_tenant_access(org_id, auth_ctx)
    action_svc = ActionService(db)

    try:
        execution = await action_svc.execute_action(
            org_id=org_id,
            actor_id=auth_ctx["user"].id,
            action_execution_id=action_id
        )
        return {
            "id": execution.id,
            "org_id": execution.org_id,
            "action_type": execution.action_type,
            "execution_state": execution.execution_state,
            "result_data": execution.result_data,
            "failure_reason": execution.failure_reason,
            "updated_at": execution.updated_at.isoformat()
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/{action_id}/verify", status_code=status.HTTP_200_OK)
async def verify_action(
    org_id: str,
    action_id: str,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_member)
):
    """Independently verify whether an executed action achieved security remediation."""
    verify_tenant_access(org_id, auth_ctx)
    action_svc = ActionService(db)

    try:
        verif = await action_svc.verify_action_execution(
            org_id=org_id,
            action_execution_id=action_id
        )
        return {
            "id": verif.id,
            "org_id": verif.org_id,
            "action_execution_id": verif.action_execution_id,
            "verification_method": verif.verification_method,
            "verification_state": verif.verification_state,
            "evidence_ref_id": verif.evidence_ref_id,
            "verified_at": verif.verified_at.isoformat()
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/{action_id}/rollback", status_code=status.HTTP_200_OK)
async def rollback_action(
    org_id: str,
    action_id: str,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_admin)
):
    """Roll back a reversible executed action (Admin only)."""
    verify_tenant_access(org_id, auth_ctx)
    action_svc = ActionService(db)

    try:
        rollback = await action_svc.rollback_action_execution(
            org_id=org_id,
            user_id=auth_ctx["user"].id,
            action_execution_id=action_id
        )
        return {
            "id": rollback.id,
            "org_id": rollback.org_id,
            "action_execution_id": rollback.action_execution_id,
            "rollback_action_type": rollback.rollback_action_type,
            "rollback_state": rollback.rollback_state,
            "rolled_back_by": rollback.rolled_back_by,
            "started_at": rollback.started_at.isoformat()
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("", status_code=status.HTTP_200_OK)
async def list_action_executions(
    org_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_viewer)
):
    """List tenant-scoped action execution history."""
    verify_tenant_access(org_id, auth_ctx)
    res = await db.execute(
        select(ActionExecution)
        .where(ActionExecution.org_id == org_id)
        .order_by(ActionExecution.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    executions = res.scalars().all()
    return {
        "items": [
            {
                "id": e.id,
                "org_id": e.org_id,
                "action_type": e.action_type,
                "target_type": e.target_type,
                "target_identifier": e.target_identifier,
                "risk_class": e.risk_class,
                "execution_state": e.execution_state,
                "authorization_state": e.authorization_state,
                "approval_requirement": e.approval_requirement,
                "requested_by": e.requested_by,
                "verification_state": e.verification_state,
                "rollback_state": e.rollback_state,
                "idempotency_key": e.idempotency_key,
                "created_at": e.created_at.isoformat()
            } for e in executions
        ],
        "limit": limit,
        "offset": offset
    }


@router.get("/{action_id}", status_code=status.HTTP_200_OK)
async def get_action_execution_details(
    org_id: str,
    action_id: str,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_viewer)
):
    """Fetch complete details, approvals, verifications, and rollbacks for a specific action execution."""
    verify_tenant_access(org_id, auth_ctx)
    res = await db.execute(select(ActionExecution).where(ActionExecution.id == action_id, ActionExecution.org_id == org_id))
    execution = res.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action execution not found")

    appr_res = await db.execute(select(ActionApproval).where(ActionApproval.action_execution_id == action_id))
    approvals = appr_res.scalars().all()

    verif_res = await db.execute(select(ActionVerification).where(ActionVerification.action_execution_id == action_id))
    verifications = verif_res.scalars().all()

    roll_res = await db.execute(select(ActionRollback).where(ActionRollback.action_execution_id == action_id))
    rollbacks = roll_res.scalars().all()

    return {
        "execution": {
            "id": execution.id,
            "org_id": execution.org_id,
            "action_type": execution.action_type,
            "target_type": execution.target_type,
            "target_identifier": execution.target_identifier,
            "risk_class": execution.risk_class,
            "execution_state": execution.execution_state,
            "authorization_state": execution.authorization_state,
            "approval_requirement": execution.approval_requirement,
            "requested_by": execution.requested_by,
            "requested_at": execution.requested_at.isoformat(),
            "action_parameters": execution.action_parameters,
            "result_data": execution.result_data,
            "failure_reason": execution.failure_reason,
            "verification_state": execution.verification_state,
            "rollback_state": execution.rollback_state,
            "provenance": execution.provenance,
            "idempotency_key": execution.idempotency_key,
            "correlation_id": execution.correlation_id,
            "automation_depth": execution.automation_depth,
            "created_at": execution.created_at.isoformat()
        },
        "approvals": [
            {
                "id": a.id,
                "approver_user_id": a.approver_user_id,
                "decision": a.decision,
                "reason": a.reason,
                "approved_at": a.approved_at.isoformat()
            } for a in approvals
        ],
        "verifications": [
            {
                "id": v.id,
                "verification_method": v.verification_method,
                "verification_state": v.verification_state,
                "evidence_ref_id": v.evidence_ref_id,
                "verified_at": v.verified_at.isoformat()
            } for v in verifications
        ],
        "rollbacks": [
            {
                "id": r.id,
                "rollback_action_type": r.rollback_action_type,
                "rollback_state": r.rollback_state,
                "rolled_back_by": r.rolled_back_by,
                "started_at": r.started_at.isoformat()
            } for r in rollbacks
        ]
    }
