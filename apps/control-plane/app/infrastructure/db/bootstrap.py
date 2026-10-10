from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.config import settings
from app.core.logging import logger
from app.infrastructure.db.models import Organization, User, Membership
from shared_contracts.enums import UserRole


DEV_ORG_ID = "org-001"

DEV_USERS = [
    {
        "id": "user-owner-01",
        "email": "owner@dev.local",
        "password_hash": "$2b$12$dev_hashed_password_owner",
        "full_name": "Dev Owner",
        "role": UserRole.OWNER.value,
        "mem_id": "mem-owner-01"
    },
    {
        "id": "user-admin-01",
        "email": "admin@dev.local",
        "password_hash": "$2b$12$dev_hashed_password_admin",
        "full_name": "Dev Admin",
        "role": UserRole.ADMIN.value,
        "mem_id": "mem-admin-01"
    },
    {
        "id": "user-member-01",
        "email": "member@dev.local",
        "password_hash": "$2b$12$dev_hashed_password_member",
        "full_name": "Dev Member",
        "role": UserRole.MEMBER.value,
        "mem_id": "mem-member-01"
    },
    {
        "id": "user-viewer-01",
        "email": "viewer@dev.local",
        "password_hash": "$2b$12$dev_hashed_password_viewer",
        "full_name": "Dev Viewer",
        "role": UserRole.VIEWER.value,
        "mem_id": "mem-viewer-01"
    },
]


async def bootstrap_development_data(db: AsyncSession) -> bool:
    """
    Idempotent development data bootstrapper.
    Ensures canonical development organization (org-001) and development role users
    (user-owner-01, user-admin-01, user-member-01, user-viewer-01) exist.
    ONLY executes when APP_ENV == 'development'.
    """
    if settings.APP_ENV != "development":
        logger.info("bootstrap_skipped_non_dev_env", environment=settings.APP_ENV)
        return False

    # 1. Ensure Development Organization exists
    res = await db.execute(select(Organization).where(Organization.id == DEV_ORG_ID))
    org = res.scalars().first()
    if not org:
        org = Organization(
            id=DEV_ORG_ID,
            name="Local Development Org",
            slug="org-001",
            status="active"
        )
        db.add(org)
        await db.commit()
        logger.info("bootstrap_created_dev_org", org_id=DEV_ORG_ID)

    # 2. Ensure Development Users and Memberships exist
    for udef in DEV_USERS:
        u_res = await db.execute(select(User).where((User.id == udef["id"]) | (User.email == udef["email"])))
        user = u_res.scalars().first()
        if not user:
            user = User(
                id=udef["id"],
                email=udef["email"],
                password_hash=udef["password_hash"],
                full_name=udef["full_name"],
                status="active"
            )
            db.add(user)
            await db.commit()
            logger.info("bootstrap_created_dev_user", user_id=udef["id"], role=udef["role"])
        elif user.id != udef["id"]:
            # Reassign ID to canonical dev user ID if needed
            user.id = udef["id"]
            await db.commit()

        m_res = await db.execute(
            select(Membership).where(
                Membership.user_id == udef["id"],
                Membership.org_id == DEV_ORG_ID
            )
        )
        mem = m_res.scalars().first()
        if not mem:
            mem = Membership(
                id=udef["mem_id"],
                org_id=DEV_ORG_ID,
                user_id=udef["id"],
                role=udef["role"]
            )
            db.add(mem)
            await db.commit()
            logger.info("bootstrap_created_dev_membership", user_id=udef["id"], org_id=DEV_ORG_ID, role=udef["role"])
        elif mem.role != udef["role"]:
            mem.role = udef["role"]
            await db.commit()
            logger.info("bootstrap_updated_dev_membership_role", user_id=udef["id"], role=udef["role"])

    return True
