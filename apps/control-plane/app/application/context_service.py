"""Phase 1E: Organizational Context Service.

Manages tenant-isolated asset metadata overrides (ownership, team, environment,
criticality, business purpose, expected exposure) with audit logging.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.infrastructure.db.models import Asset, AssetContext, User
from app.application.audit_service import AuditService
from shared_contracts.enums import Environment, Criticality

logger = logging.getLogger(__name__)


class OrganizationalContextService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_asset_context(self, org_id: str, asset_id: str) -> Optional[AssetContext]:
        """Fetch asset context with strict tenant isolation."""
        result = await self.db.execute(
            select(AssetContext).where(
                and_(AssetContext.org_id == org_id, AssetContext.asset_id == asset_id)
            )
        )
        return result.scalars().first()

    async def update_asset_context(
        self,
        org_id: str,
        asset_id: str,
        actor_id: str,
        owner_id: Optional[str] = None,
        owner_team: Optional[str] = None,
        environment: Optional[str] = None,
        criticality: Optional[str] = None,
        business_purpose: Optional[str] = None,
        expected_exposure: Optional[str] = None,
        ip_address: Optional[str] = "127.0.0.1",
    ) -> AssetContext:
        """Update or create organizational context for an asset.

        Enforces tenant isolation and updates the canonical Asset record in sync.
        Logs an audit event for accountability.
        """
        now = datetime.now(timezone.utc)

        # 1. Tenant Isolation: Verify asset exists and belongs to org_id
        asset_result = await self.db.execute(
            select(Asset).where(and_(Asset.id == asset_id, Asset.org_id == org_id))
        )
        asset = asset_result.scalars().first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found or does not belong to org {org_id}")

        # 2. Validate owner_id if provided
        if owner_id:
            user_result = await self.db.execute(
                select(User).where(User.id == owner_id)
            )
            if not user_result.scalars().first():
                raise ValueError(f"Owner user {owner_id} not found")

        # 3. Get or create AssetContext
        context = await self.get_asset_context(org_id, asset_id)
        is_new = False

        if not context:
            is_new = True
            import uuid
            context = AssetContext(
                id=str(uuid.uuid4()),
                org_id=org_id,
                asset_id=asset_id,
                owner_id=owner_id,
                owner_team=owner_team,
                environment=environment or asset.environment or Environment.UNKNOWN,
                criticality=criticality or asset.criticality or Criticality.MEDIUM,
                business_purpose=business_purpose,
                expected_exposure=expected_exposure,
                created_at=now,
                updated_at=now,
            )
            self.db.add(context)
        else:
            if owner_id is not None:
                context.owner_id = owner_id
            if owner_team is not None:
                context.owner_team = owner_team
            if environment is not None:
                context.environment = environment
            if criticality is not None:
                context.criticality = criticality
            if business_purpose is not None:
                context.business_purpose = business_purpose
            if expected_exposure is not None:
                context.expected_exposure = expected_exposure
            context.updated_at = now

        # 4. Sync Asset model metadata fields
        if owner_id is not None:
            asset.owner_id = owner_id
        if owner_team is not None:
            asset.owner_team = owner_team
        if environment is not None:
            asset.environment = environment
        if criticality is not None:
            asset.criticality = criticality

        await self.db.flush()

        # 5. Audit Logging
        AuditService.log_event(
            db_session=self.db,
            event_type="asset.context_created" if is_new else "asset.context_updated",
            resource_type="asset",
            resource_id=asset_id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address or "127.0.0.1",
            details={
                "owner_id": context.owner_id,
                "owner_team": context.owner_team,
                "environment": context.environment,
                "criticality": context.criticality,
                "business_purpose": context.business_purpose,
                "expected_exposure": context.expected_exposure,
            },
        )

        logger.info(
            "asset_context_updated",
            extra={
                "org_id": org_id,
                "asset_id": asset_id,
                "actor_id": actor_id,
                "environment": context.environment,
                "criticality": context.criticality,
            },
        )

        return context
