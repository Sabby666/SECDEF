from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from typing import List

from app.api.dependencies.auth import get_current_user_and_org
from shared_contracts.enums import UserRole

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])


class SessionResponse(BaseModel):
    user_id: str
    email: str
    full_name: str
    org_id: str
    org_name: str
    role: str
    is_admin: bool
    is_owner: bool
    permissions: List[str]


ROLE_PERMISSIONS = {
    UserRole.OWNER: [
        "read",
        "domain:create",
        "domain:verify",
        "scan:trigger",
        "candidate:promote",
        "candidate:reject",
        "finding:acknowledge",
        "finding:verify",
        "action:propose",
        "action:approve",
        "action:reject",
        "action:execute",
        "action:rollback",
        "automation:write",
        "notifications:write",
        "settings:write",
        "apikey:write",
        "export:read",
        "assistant:query",
        "verification:write"
    ],
    UserRole.ADMIN: [
        "read",
        "domain:create",
        "domain:verify",
        "scan:trigger",
        "candidate:promote",
        "candidate:reject",
        "finding:acknowledge",
        "finding:verify",
        "action:propose",
        "action:approve",
        "action:execute",
        "automation:write",
        "notifications:write",
        "settings:write",
        "apikey:write",
        "export:read",
        "assistant:query",
        "verification:write"
    ],
    UserRole.MEMBER: [
        "read",
        "scan:trigger",
        "candidate:promote",
        "finding:acknowledge",
        "action:propose",
        "export:read",
        "assistant:query"
    ],
    UserRole.VIEWER: [
        "read",
        "export:read"
    ]
}


@router.get("/session", response_model=SessionResponse, status_code=status.HTTP_200_OK)
@router.get("/me", response_model=SessionResponse, status_code=status.HTTP_200_OK)
async def get_session_info(auth_ctx: dict = Depends(get_current_user_and_org)):
    """
    Returns the server-authoritative authentication and RBAC context
    for the current request. Role and permissions are derived strictly
    from the database membership record and cannot be client-spoofed.
    """
    user = auth_ctx["user"]
    org = auth_ctx["org"]
    role = auth_ctx["role"]
    
    # Normalize role enum / string
    role_enum = role if isinstance(role, UserRole) else UserRole(str(role).lower())
    role_str = role_enum.value.upper()
    
    permissions = ROLE_PERMISSIONS.get(role_enum, ["read"])
    is_admin = role_enum in (UserRole.OWNER, UserRole.ADMIN)
    is_owner = role_enum == UserRole.OWNER
    
    return SessionResponse(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name or user.email,
        org_id=org.id,
        org_name=org.name or "Primary Organization",
        role=role_str,
        is_admin=is_admin,
        is_owner=is_owner,
        permissions=permissions
    )


# =========================================================================
# Organization Settings & API Keys REST Endpoints
# =========================================================================

from fastapi import Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.infrastructure.db.session import get_db_session
from app.infrastructure.db.models import Organization, Membership, User
from app.api.dependencies.auth import require_admin, require_viewer
from app.application.audit_service import AuditService
import secrets
import hashlib
from datetime import datetime, timezone


class OrgSettingsUpdateRequest(BaseModel):
    name: str
    status: str = "active"


class ApiKeyCreateRequest(BaseModel):
    key_name: str
    scope: str = "read:assets write:scans"


# In-memory storage for active API keys associated with organizations
_ORG_API_KEYS: dict[str, list[dict]] = {
    "org-001": [
        {
            "id": "key-001",
            "org_id": "org-001",
            "key_name": "CI/CD Scanner Integration",
            "key_prefix": "asm_live_9f82...",
            "scope": "read:assets write:scans",
            "created_at": "2026-09-01T00:00:00Z",
            "status": "ACTIVE"
        }
    ]
}


@router.get("/organizations/{org_id}/settings")
async def get_org_settings(
    org_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")
    
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalars().first()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
        
    return {
        "org_id": org.id,
        "name": org.name,
        "slug": org.slug,
        "status": org.status,
        "created_at": org.created_at.isoformat() if org.created_at else None,
        "updated_at": org.updated_at.isoformat() if org.updated_at else None
    }


@router.put("/organizations/{org_id}/settings")
async def update_org_settings(
    org_id: str,
    body: OrgSettingsUpdateRequest,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session)
):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalars().first()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    old_name = org.name
    org.name = body.name
    org.status = body.status
    org.updated_at = datetime.now(timezone.utc)
    
    client_ip = req.client.host if req.client else "127.0.0.1"
    AuditService.log_event(
        db_session=db,
        event_type="ORG_SETTINGS_UPDATED",
        resource_type="organization",
        resource_id=org_id,
        ip_address=client_ip,
        org_id=org_id,
        actor_id=auth_ctx["user"].id,
        details={"old_name": old_name, "new_name": body.name, "status": body.status}
    )
    await db.commit()

    return {
        "org_id": org.id,
        "name": org.name,
        "slug": org.slug,
        "status": org.status,
        "updated_at": org.updated_at.isoformat()
    }


@router.get("/organizations/{org_id}/members")
async def list_org_members(
    org_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    result = await db.execute(
        select(Membership, User)
        .join(User, Membership.user_id == User.id)
        .where(Membership.org_id == org_id)
    )
    rows = result.all()
    
    return [
        {
            "user_id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": membership.role.upper(),
            "status": user.status,
            "created_at": membership.created_at.isoformat() if membership.created_at else None
        }
        for membership, user in rows
    ]


@router.get("/organizations/{org_id}/apikeys")
async def list_org_api_keys(
    org_id: str,
    auth_ctx: dict = Depends(require_viewer)
):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")
    return _ORG_API_KEYS.get(org_id, [])


@router.post("/organizations/{org_id}/apikeys", status_code=status.HTTP_201_CREATED)
async def generate_org_api_key(
    org_id: str,
    body: ApiKeyCreateRequest,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session)
):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    raw_token = f"asm_live_{secrets.token_hex(16)}"
    key_prefix = f"{raw_token[:13]}..."
    key_id = f"key-{secrets.token_hex(4)}"

    new_key = {
        "id": key_id,
        "org_id": org_id,
        "key_name": body.key_name,
        "key_prefix": key_prefix,
        "scope": body.scope,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "ACTIVE"
    }

    if org_id not in _ORG_API_KEYS:
        _ORG_API_KEYS[org_id] = []
    _ORG_API_KEYS[org_id].append(new_key)

    client_ip = req.client.host if req.client else "127.0.0.1"
    AuditService.log_event(
        db_session=db,
        event_type="API_KEY_GENERATED",
        resource_type="api_key",
        resource_id=key_id,
        ip_address=client_ip,
        org_id=org_id,
        actor_id=auth_ctx["user"].id,
        details={"key_name": body.key_name, "key_prefix": key_prefix, "scope": body.scope}
    )
    await db.commit()

    return {**new_key, "token": raw_token}


@router.delete("/organizations/{org_id}/apikeys/{key_id}", status_code=status.HTTP_200_OK)
async def revoke_org_api_key(
    org_id: str,
    key_id: str,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session)
):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")

    keys = _ORG_API_KEYS.get(org_id, [])
    for k in keys:
        if k["id"] == key_id:
            k["status"] = "REVOKED"
            client_ip = req.client.host if req.client else "127.0.0.1"
            AuditService.log_event(
                db_session=db,
                event_type="API_KEY_REVOKED",
                resource_type="api_key",
                resource_id=key_id,
                ip_address=client_ip,
                org_id=org_id,
                actor_id=auth_ctx["user"].id,
                details={"key_name": k["key_name"]}
            )
            await db.commit()
            return {"status": "revoked", "key_id": key_id}

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

