import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from app.infrastructure.db.models import (
    Notification, NotificationDestination, NotificationPolicy, NotificationDelivery,
    Finding, RiskAssessment, Change, VerificationResult, Asset
)
from app.application.audit_service import AuditService
from app.infrastructure.notifications.webhook_delivery import WebhookDeliveryService
from shared_contracts.enums import RiskBand, NotificationChannel, NotificationDeliveryStatus, NotificationTriggerType


class NotificationService:
    """Phase 1G: Change-Aware Notification Engine with deterministic identity, policy filtering, deduplication, rate limiting, and bounded retries."""

    MAX_DELIVERY_RETRIES = 3

    RISK_BAND_RANK = {
        RiskBand.CRITICAL.value: 5,
        RiskBand.HIGH.value: 4,
        RiskBand.MEDIUM.value: 3,
        RiskBand.LOW.value: 2,
        RiskBand.INFO.value: 1
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_destination(
        self,
        org_id: str,
        channel: str,
        name: str,
        config: Dict[str, Any],
        actor_id: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> NotificationDestination:
        """Create a tenant-scoped notification destination."""
        if channel == NotificationChannel.WEBHOOK.value:
            url = config.get("url")
            if not url:
                raise ValueError("Webhook configuration must include 'url'")
            # Validate URL and SSRF safety immediately
            WebhookDeliveryService.validate_url_and_resolve(url)

        destination = NotificationDestination(
            id=str(uuid.uuid4()),
            org_id=org_id,
            channel=channel,
            name=name,
            config=config,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        self.db.add(destination)

        AuditService.log_event(
            db_session=self.db,
            event_type="destination.created",
            resource_type="notification_destination",
            resource_id=destination.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"channel": channel, "name": name}
        )

        await self.db.flush()
        return destination

    async def list_destinations(self, org_id: str) -> List[NotificationDestination]:
        """List tenant destinations."""
        stmt = select(NotificationDestination).where(NotificationDestination.org_id == org_id)
        res = await self.db.execute(stmt)
        return list(res.scalars().all())

    async def revoke_destination(
        self,
        org_id: str,
        destination_id: str,
        actor_id: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> NotificationDestination:
        """Revoke / deactivate a notification destination."""
        stmt = select(NotificationDestination).where(
            NotificationDestination.org_id == org_id,
            NotificationDestination.id == destination_id
        )
        res = await self.db.execute(stmt)
        dest = res.scalars().first()
        if not dest:
            raise ValueError(f"Destination {destination_id} not found for organization {org_id}")

        dest.is_active = False
        dest.updated_at = datetime.now(timezone.utc)

        AuditService.log_event(
            db_session=self.db,
            event_type="destination.revoked",
            resource_type="notification_destination",
            resource_id=dest.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"name": dest.name}
        )

        await self.db.flush()
        return dest

    async def create_policy(
        self,
        org_id: str,
        name: str,
        min_risk_band: str = "HIGH",
        trigger_types: Optional[List[str]] = None,
        destination_ids: Optional[List[str]] = None,
        cooldown_minutes: int = 60,
        actor_id: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> NotificationPolicy:
        """Create a tenant-scoped notification policy."""
        policy = NotificationPolicy(
            id=str(uuid.uuid4()),
            org_id=org_id,
            policy_version="v1",
            name=name,
            min_risk_band=min_risk_band,
            trigger_types=trigger_types or [],
            destination_ids=destination_ids or [],
            cooldown_minutes=cooldown_minutes,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        self.db.add(policy)

        AuditService.log_event(
            db_session=self.db,
            event_type="policy.created",
            resource_type="notification_policy",
            resource_id=policy.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"name": name, "min_risk_band": min_risk_band}
        )

        await self.db.flush()
        return policy

    async def list_policies(self, org_id: str) -> List[NotificationPolicy]:
        """List tenant notification policies."""
        stmt = select(NotificationPolicy).where(NotificationPolicy.org_id == org_id)
        res = await self.db.execute(stmt)
        return list(res.scalars().all())

    async def evaluate_and_notify(
        self,
        org_id: str,
        trigger_type: str,
        source_id: str,
        finding_id: Optional[str] = None,
        risk_assessment_id: Optional[str] = None,
        change_id: Optional[str] = None,
        verification_result_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> List[Notification]:
        """
        Evaluate security event against active organization policies.
        Enforces deterministic event identity deduplication, cooldown limits, and bounded retries.
        Dispatches notification side-effects without mutating DB security transactions.
        """
        # 1. Fetch active policies for organization
        policy_stmt = select(NotificationPolicy).where(
            NotificationPolicy.org_id == org_id,
            NotificationPolicy.is_active == True
        )
        res_pol = await self.db.execute(policy_stmt)
        policies = res_pol.scalars().all()
        if not policies:
            return []

        # 2. Load context objects ensuring tenant scoping
        finding = None
        if finding_id:
            res_find = await self.db.execute(select(Finding).where(Finding.org_id == org_id, Finding.id == finding_id))
            finding = res_find.scalars().first()

        risk_assessment = None
        if risk_assessment_id:
            res_risk = await self.db.execute(select(RiskAssessment).where(RiskAssessment.org_id == org_id, RiskAssessment.id == risk_assessment_id))
            risk_assessment = res_risk.scalars().first()

        change = None
        if change_id:
            res_chg = await self.db.execute(select(Change).where(Change.org_id == org_id, Change.id == change_id))
            change = res_chg.scalars().first()
        elif finding and finding.change_id:
            res_chg = await self.db.execute(select(Change).where(Change.org_id == org_id, Change.id == finding.change_id))
            change = res_chg.scalars().first()

        verification_result = None
        if verification_result_id:
            res_ver = await self.db.execute(select(VerificationResult).where(VerificationResult.org_id == org_id, VerificationResult.id == verification_result_id))
            verification_result = res_ver.scalars().first()

        asset = None
        if finding and finding.asset_id:
            res_ast = await self.db.execute(select(Asset).where(Asset.org_id == org_id, Asset.id == finding.asset_id))
            asset = res_ast.scalars().first()
        elif change and change.asset_id:
            res_ast = await self.db.execute(select(Asset).where(Asset.org_id == org_id, Asset.id == change.asset_id))
            asset = res_ast.scalars().first()

        # 3. Determine Risk Band for threshold checking
        event_risk_band = RiskBand.INFO.value
        if risk_assessment:
            event_risk_band = risk_assessment.risk_band

        generated_notifications = []

        for policy in policies:
            # Check trigger type filter
            if policy.trigger_types and trigger_type not in policy.trigger_types:
                continue

            # Check min risk band threshold
            policy_band_rank = self.RISK_BAND_RANK.get(policy.min_risk_band, 1)
            event_band_rank = self.RISK_BAND_RANK.get(event_risk_band, 1)
            if event_band_rank < policy_band_rank:
                continue

            # 4. Deterministic Event Identity: (org_id, trigger_type, source_id, policy_version)
            raw_id = f"{org_id}:{trigger_type}:{source_id}:{policy.policy_version}"
            event_identity = hashlib.sha256(raw_id.encode('utf-8')).hexdigest()

            # Deduplication Check: Check if Notification with same event_identity exists
            dup_stmt = select(Notification).where(
                Notification.org_id == org_id,
                Notification.event_identity == event_identity
            )
            res_dup = await self.db.execute(dup_stmt)
            existing_notif = res_dup.scalars().first()
            if existing_notif:
                # Deduplicated! Skip generating duplicate notification
                continue

            # Cooldown Check: Check if notification volume exceeds limit within policy cooldown window
            if policy.cooldown_minutes > 0:
                cutoff = datetime.now(timezone.utc) - timedelta(minutes=policy.cooldown_minutes)
                cd_stmt = select(Notification).where(
                    Notification.org_id == org_id,
                    Notification.trigger_type == trigger_type,
                    Notification.created_at >= cutoff
                )
                res_cd = await self.db.execute(cd_stmt)
                recent_notifs = res_cd.scalars().all()
                if len(recent_notifs) >= 10: # Cooldown threshold
                    AuditService.log_event(
                        db_session=self.db,
                        event_type="notification.suppressed_cooldown",
                        resource_type="notification",
                        org_id=org_id,
                        ip_address=ip_address,
                        details={"trigger_type": trigger_type, "policy_id": policy.id}
                    )
                    continue

            # Construct structured evidence payload
            title = f"[{event_risk_band}] Security Event: {trigger_type.replace('_', ' ').title()}"
            summary = (
                f"SECDEF detected {trigger_type} for entity '{change.entity_identifier if change else source_id}'. "
                f"Risk Band: {event_risk_band}."
            )

            content_payload = {
                "what": title,
                "asset": {
                    "id": asset.id if asset else None,
                    "identifier": change.entity_identifier if change else (asset.identifier if asset else source_id),
                    "type": asset.asset_type if asset else "unknown"
                },
                "why": {
                    "risk_band": event_risk_band,
                    "risk_score": risk_assessment.risk_score if risk_assessment else 0.0,
                    "explanation": risk_assessment.explanation if risk_assessment else "Event matching notification policy."
                },
                "change": {
                    "change_id": change.id if change else None,
                    "change_type": change.change_type if change else None,
                    "previous_state": change.previous_state if change else None,
                    "current_state": change.current_state if change else None
                },
                "risk": {
                    "risk_assessment_id": risk_assessment.id if risk_assessment else None,
                    "model_version": risk_assessment.risk_model_version if risk_assessment else "v1"
                },
                "evidence": risk_assessment.factor_breakdown if risk_assessment else {},
                "verification": {
                    "verification_result_id": verification_result.id if verification_result else None,
                    "status": verification_result.status if verification_result else "unverified"
                }
            }

            notification = Notification(
                id=str(uuid.uuid4()),
                org_id=org_id,
                finding_id=finding.id if finding else None,
                risk_assessment_id=risk_assessment.id if risk_assessment else None,
                change_id=change.id if change else None,
                verification_result_id=verification_result.id if verification_result else None,
                trigger_type=trigger_type,
                title=title,
                summary=summary,
                content_payload=content_payload,
                event_identity=event_identity,
                created_at=datetime.now(timezone.utc)
            )
            try:
                async with self.db.begin_nested():
                    self.db.add(notification)
                    await self.db.flush()
            except IntegrityError:
                # Concurrent evaluation already inserted this notification event identity
                continue

            AuditService.log_event(
                db_session=self.db,
                event_type="notification.created",
                resource_type="notification",
                resource_id=notification.id,
                org_id=org_id,
                actor_id=actor_id,
                ip_address=ip_address,
                details={"trigger_type": trigger_type, "event_identity": event_identity}
            )

            # 5. Dispatch delivery with bounded retries (Max 3 attempts)
            if policy.destination_ids:
                dest_ids = list(policy.destination_ids) if isinstance(policy.destination_ids, (list, tuple)) else []
                if dest_ids:
                    dest_stmt = select(NotificationDestination).where(
                        NotificationDestination.org_id == org_id,
                        NotificationDestination.id.in_(dest_ids),
                        NotificationDestination.is_active == True # Revoked/inactive destinations skipped!
                    )
                    res_dest = await self.db.execute(dest_stmt)
                    destinations = res_dest.scalars().all()
                    # Filter in python to guarantee inactive destinations are skipped regardless of DB dialect boolean representation
                    destinations = [d for d in destinations if bool(d.is_active)]


                    for dest in destinations:
                        if dest.channel == NotificationChannel.WEBHOOK.value:
                            url = dest.config.get("url")
                            signing_secret = dest.config.get("signing_secret")
                            if url:
                                delivered = False
                                for attempt in range(1, self.MAX_DELIVERY_RETRIES + 1):
                                    success, code, msg = WebhookDeliveryService.deliver_webhook(
                                        url=url,
                                        payload=content_payload,
                                        signing_secret=signing_secret
                                    )

                                    delivery = NotificationDelivery(
                                        id=str(uuid.uuid4()),
                                        org_id=org_id,
                                        notification_id=notification.id,
                                        destination_id=dest.id,
                                        channel=dest.channel,
                                        attempt_number=attempt,
                                        status=NotificationDeliveryStatus.SENT.value if success else NotificationDeliveryStatus.FAILED.value,
                                        response_code=code,
                                        error_message=msg if not success else None,
                                        delivered_at=datetime.now(timezone.utc) if success else None,
                                        created_at=datetime.now(timezone.utc)
                                    )
                                    self.db.add(delivery)

                                    AuditService.log_event(
                                        db_session=self.db,
                                        event_type="notification.sent" if success else "notification.failed",
                                        resource_type="notification_delivery",
                                        resource_id=delivery.id,
                                        org_id=org_id,
                                        ip_address=ip_address,
                                        details={"destination_id": dest.id, "attempt": attempt, "success": success, "code": code}
                                    )

                                    if success:
                                        delivered = True
                                        break

                                # If attempt fails and more retries remain, loop continues (bounded retries)

            generated_notifications.append(notification)

        await self.db.flush()
        return generated_notifications

    async def list_notifications(
        self,
        org_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[Notification], int]:
        """List tenant notifications."""
        stmt = select(Notification).where(Notification.org_id == org_id)
        count_stmt = select(func.count(Notification.id)).where(Notification.org_id == org_id)

        res_count = await self.db.execute(count_stmt)
        total = res_count.scalar() or 0

        res = await self.db.execute(stmt.order_by(Notification.created_at.desc()).limit(limit).offset(offset))
        notifications = res.scalars().all()
        return list(notifications), total
