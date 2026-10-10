from datetime import datetime, timezone
import structlog
from typing import Optional
from app.infrastructure.db.models import AuditEvent

logger = structlog.get_logger("asm.audit")

class AuditService:
    @staticmethod
    def log_event(
        db_session,
        event_type: str,
        resource_type: str,
        ip_address: str,
        org_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[dict] = None
    ) -> None:
        """
        Record a security-relevant event to the audit log.
        Does NOT commit the session. Expects caller to commit.
        """
        
        # Ensure no sensitive fields leak in details
        safe_details = {}
        if details:
            safe_details = details.copy()
            # Explicitly scrub known sensitive keys just in case
            for key in ["password", "token", "secret", "verification_token"]:
                if key in safe_details:
                    safe_details[key] = "[REDACTED]"
                    
        # Sanitize actor_id for DB FK constraint (users.id)
        db_actor_id = actor_id
        if actor_id and (actor_id.startswith("system") or actor_id.startswith("worker-")):
            db_actor_id = None
            if safe_details is None:
                safe_details = {}
            safe_details["system_actor"] = actor_id

        event = AuditEvent(
            org_id=org_id,
            actor_id=db_actor_id,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=safe_details,
            created_at=datetime.now(timezone.utc)
        )
        db_session.add(event)
        
        # Also emit to application log (structured)
        logger.info(
            "audit_event",
            event_type=event_type,
            org_id=org_id,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id
        )
