from fastapi import Header, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.infrastructure.db.session import get_db_session
from app.infrastructure.db.models import User, Organization, Membership
from shared_contracts.enums import UserRole
from app.core.config import settings

# NOTE: For Phase 1A testing without full session tokens implemented, 
# we use explicit headers to simulate an authenticated context.
# In production, this will extract a session token from an HttpOnly cookie,
# query the `sessions` table, and return the User and Org context.

async def get_current_user_and_org(
    x_user_id: str = Header(..., description="Simulated user ID for Phase 1A"),
    x_org_id: str = Header(..., description="Simulated org ID for Phase 1A"),
    db: AsyncSession = Depends(get_db_session)
) -> dict:
    
    if settings.APP_ENV not in ("development", "test"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Development AuthAdapter cannot be used in production."
        )
        
    # 1. Verify User exists
    result = await db.execute(select(User).where(User.id == x_user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user")

    # 2. Verify Organization exists
    result = await db.execute(select(Organization).where(Organization.id == x_org_id))
    org = result.scalars().first()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    # 3. Verify Membership and Role
    result = await db.execute(
        select(Membership)
        .where(Membership.user_id == user.id, Membership.org_id == org.id)
    )
    membership = result.scalars().first()
    
    if not membership:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not a member of this organization")
        
    return {
        "user": user,
        "org": org,
        "role": membership.role
    }


def require_role(allowed_roles: list[str]):
    def role_checker(context: dict = Depends(get_current_user_and_org)):
        if context["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail=f"Required role in {allowed_roles}"
            )
        return context
    return role_checker

# Pre-configured dependencies
require_admin = require_role([UserRole.OWNER, UserRole.ADMIN])
require_member = require_role([UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER])
require_viewer = require_role([UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER])
