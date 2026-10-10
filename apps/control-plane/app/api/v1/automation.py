"""Phase 6 Automation Policies & Rules Router.

Provides tenant-isolated REST endpoints to configure automation policies and rules
with server-side RBAC enforcement (ADMIN required for policy configuration).
"""
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.session import get_db_session
from app.infrastructure.db.models import AutomationPolicy, AutomationRule
from app.api.dependencies.auth import require_admin, require_viewer
from app.application.audit_service import AuditService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations/{org_id}/automation", tags=["Automation Policy"])


def verify_tenant_access(org_id: str, auth_ctx: dict):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")


class CreatePolicyRequest(BaseModel):
    name: str
    description: Optional[str] = None
    is_enabled: bool = True
    allow_auto_approval: bool = False
    max_risk_class: str = "CLASS_B_LOW_RISK_REVERSIBLE"
    allowed_action_types: List[str]
    target_environment_constraints: Optional[Dict[str, Any]] = None


class CreateRuleRequest(BaseModel):
    policy_id: str
    name: str
    trigger_event: str
    trigger_conditions: Dict[str, Any]
    action_type: str
    action_parameters_template: Dict[str, Any]
    is_enabled: bool = True


@router.post("/policies", status_code=status.HTTP_201_CREATED)
async def create_automation_policy(
    org_id: str,
    body: CreatePolicyRequest,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_admin)
):
    """Create a new organization automation policy (Admin only)."""
    verify_tenant_access(org_id, auth_ctx)
    policy = AutomationPolicy(
        org_id=org_id,
        name=body.name,
        description=body.description,
        is_enabled=body.is_enabled,
        allow_auto_approval=body.allow_auto_approval,
        max_risk_class=body.max_risk_class,
        allowed_action_types=body.allowed_action_types,
        target_environment_constraints=body.target_environment_constraints
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    AuditService.log_event(
        db_session=db,
        org_id=org_id,
        event_type="automation_policy_created",
        resource_type="automation_policy",
        resource_id=policy.id,
        ip_address="127.0.0.1",
        actor_id=auth_ctx["user"].id,
        details={"policy_id": policy.id, "name": policy.name}
    )
    await db.commit()

    return {
        "id": policy.id,
        "org_id": policy.org_id,
        "name": policy.name,
        "is_enabled": policy.is_enabled,
        "allow_auto_approval": policy.allow_auto_approval,
        "max_risk_class": policy.max_risk_class,
        "allowed_action_types": policy.allowed_action_types,
        "created_at": policy.created_at.isoformat()
    }


@router.get("/policies", status_code=status.HTTP_200_OK)
async def list_automation_policies(
    org_id: str,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_viewer)
):
    """Fetch organization automation policies."""
    verify_tenant_access(org_id, auth_ctx)
    res = await db.execute(select(AutomationPolicy).where(AutomationPolicy.org_id == org_id))
    policies = res.scalars().all()
    return {
        "items": [
            {
                "id": p.id,
                "org_id": p.org_id,
                "name": p.name,
                "description": p.description,
                "is_enabled": p.is_enabled,
                "allow_auto_approval": p.allow_auto_approval,
                "max_risk_class": p.max_risk_class,
                "allowed_action_types": p.allowed_action_types,
                "created_at": p.created_at.isoformat()
            } for p in policies
        ]
    }


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_automation_rule(
    org_id: str,
    body: CreateRuleRequest,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_admin)
):
    """Create a new trigger-action rule inside an automation policy (Admin only)."""
    verify_tenant_access(org_id, auth_ctx)
    policy_res = await db.execute(select(AutomationPolicy).where(AutomationPolicy.id == body.policy_id, AutomationPolicy.org_id == org_id))
    if not policy_res.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Automation policy not found")

    rule = AutomationRule(
        org_id=org_id,
        policy_id=body.policy_id,
        name=body.name,
        trigger_event=body.trigger_event,
        trigger_conditions=body.trigger_conditions,
        action_type=body.action_type,
        action_parameters_template=body.action_parameters_template,
        is_enabled=body.is_enabled
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    AuditService.log_event(
        db_session=db,
        org_id=org_id,
        event_type="automation_rule_created",
        resource_type="automation_rule",
        resource_id=rule.id,
        ip_address="127.0.0.1",
        actor_id=auth_ctx["user"].id,
        details={"rule_id": rule.id, "trigger_event": rule.trigger_event, "action_type": rule.action_type}
    )
    await db.commit()

    return {
        "id": rule.id,
        "org_id": rule.org_id,
        "policy_id": rule.policy_id,
        "name": rule.name,
        "trigger_event": rule.trigger_event,
        "action_type": rule.action_type,
        "is_enabled": rule.is_enabled,
        "created_at": rule.created_at.isoformat()
    }


@router.get("/rules", status_code=status.HTTP_200_OK)
async def list_automation_rules(
    org_id: str,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_viewer)
):
    """Fetch organization automation rules."""
    verify_tenant_access(org_id, auth_ctx)
    res = await db.execute(select(AutomationRule).where(AutomationRule.org_id == org_id))
    rules = res.scalars().all()
    return {
        "items": [
            {
                "id": r.id,
                "org_id": r.org_id,
                "policy_id": r.policy_id,
                "name": r.name,
                "trigger_event": r.trigger_event,
                "action_type": r.action_type,
                "trigger_conditions": r.trigger_conditions,
                "is_enabled": r.is_enabled,
                "created_at": r.created_at.isoformat()
            } for r in rules
        ]
    }


@router.patch("/policies/{policy_id}/toggle", status_code=status.HTTP_200_OK)
async def toggle_automation_policy(
    org_id: str,
    policy_id: str,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_admin)
):
    """Toggle automation policy enabled state (Admin only)."""
    verify_tenant_access(org_id, auth_ctx)
    res = await db.execute(select(AutomationPolicy).where(AutomationPolicy.id == policy_id, AutomationPolicy.org_id == org_id))
    policy = res.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Automation policy not found")

    policy.is_enabled = not policy.is_enabled
    AuditService.log_event(
        db_session=db,
        org_id=org_id,
        event_type="automation_policy_toggled",
        resource_type="automation_policy",
        resource_id=policy.id,
        ip_address="127.0.0.1",
        actor_id=auth_ctx["user"].id,
        details={"policy_id": policy.id, "is_enabled": policy.is_enabled}
    )
    await db.commit()
    await db.refresh(policy)
    return {
        "id": policy.id,
        "is_enabled": policy.is_enabled
    }


@router.delete("/policies/{policy_id}", status_code=status.HTTP_200_OK)
async def delete_automation_policy(
    org_id: str,
    policy_id: str,
    db: AsyncSession = Depends(get_db_session),
    auth_ctx=Depends(require_admin)
):
    """Delete an automation policy (Admin only)."""
    verify_tenant_access(org_id, auth_ctx)
    res = await db.execute(select(AutomationPolicy).where(AutomationPolicy.id == policy_id, AutomationPolicy.org_id == org_id))
    policy = res.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Automation policy not found")

    AuditService.log_event(
        db_session=db,
        org_id=org_id,
        event_type="automation_policy_deleted",
        resource_type="automation_policy",
        resource_id=policy.id,
        ip_address="127.0.0.1",
        actor_id=auth_ctx["user"].id,
        details={"policy_id": policy.id, "name": policy.name}
    )
    await db.delete(policy)
    await db.commit()
    return {"status": "deleted", "policy_id": policy_id}
