import secrets
import string
import re
import idna
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError

from app.infrastructure.db.models import Domain, Organization
from shared_contracts.enums import DomainStatus
from app.application.audit_service import AuditService

def normalize_domain(domain: str) -> str:
    """
    Safely normalizes a domain name.
    - Trims whitespace
    - Lowercases
    - Removes trailing dot
    """
    if not domain:
        raise ValueError("Domain cannot be empty")
        
    normalized = domain.strip().lower()
    if normalized.endswith('.'):
        normalized = normalized[:-1]
        
    try:
        normalized = idna.encode(normalized).decode('ascii')
    except idna.IDNAError:
        raise ValueError("Invalid domain syntax")
        
    # Basic structural check: max 253 chars, valid chars
    if len(normalized) > 253:
        raise ValueError("Domain length exceeds 253 characters")
        
    # Only allow basic alphanumeric and hyphens (IDNs should be punycoded before this step).
    if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', normalized):
        raise ValueError("Invalid domain syntax")
        
    return normalized

def generate_verification_token() -> str:
    """Generate a cryptographically secure 256-bit (32 bytes) URL-safe token."""
    return secrets.token_urlsafe(32)

class DomainService:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def add_domain(self, org_id: str, domain_name: str, actor_id: str, ip_address: str) -> Domain:
        normalized_name = normalize_domain(domain_name)
        
        token = generate_verification_token()
        
        domain = Domain(
            org_id=org_id,
            domain_name=normalized_name,
            status=DomainStatus.PENDING_VERIFICATION,
            verification_token=token
        )
        
        self.db.add(domain)
        
        try:
            await self.db.flush()
        except IntegrityError:
            await self.db.rollback()
            raise ValueError(f"Domain {normalized_name} is already registered to this organization")
            
        AuditService.log_event(
            db_session=self.db,
            event_type="domain.created",
            resource_type="domain",
            resource_id=domain.id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"domain_name": normalized_name}
        )
        
        await self.db.commit()
        await self.db.refresh(domain)
        return domain

    async def get_domains_for_org(self, org_id: str) -> List[Domain]:
        result = await self.db.execute(
            select(Domain).where(Domain.org_id == org_id).order_by(Domain.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_domain(self, org_id: str, domain_id: str) -> Optional[Domain]:
        result = await self.db.execute(
            select(Domain).where(Domain.org_id == org_id, Domain.id == domain_id)
        )
        return result.scalars().first()

    async def get_domain_for_verification(self, org_id: str, domain_id: str, actor_id: str, ip_address: str) -> Optional[Domain]:
        stmt = select(Domain).where(Domain.org_id == org_id, Domain.id == domain_id).with_for_update()
        result = await self.db.execute(stmt)
        domain = result.scalars().first()
        
        if not domain:
            return None
            
        # Check expiry (72 hours)
        if domain.status == DomainStatus.PENDING_VERIFICATION:
            if datetime.now(timezone.utc) > domain.created_at.replace(tzinfo=timezone.utc) + timedelta(hours=72):
                domain.status = DomainStatus.EXPIRED
                AuditService.log_event(
                    db_session=self.db,
                    event_type="domain.verification_expired",
                    resource_type="domain",
                    resource_id=domain.id,
                    org_id=domain.org_id,
                    actor_id=actor_id,
                    ip_address=ip_address,
                    details={"domain_name": domain.domain_name}
                )
                await self.db.commit()
                await self.db.refresh(domain)
                
        return domain

    async def mark_domain_verified(self, domain: Domain, actor_id: str, ip_address: str) -> Domain:
        domain.status = DomainStatus.VERIFIED
        domain.verified_at = datetime.now(timezone.utc)
        domain.last_verified_at = domain.verified_at
        
        AuditService.log_event(
            db_session=self.db,
            event_type="domain.verification_succeeded",
            resource_type="domain",
            resource_id=domain.id,
            org_id=domain.org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"domain_name": domain.domain_name}
        )
        
        await self.db.commit()
        await self.db.refresh(domain)
        return domain

    async def mark_domain_verification_failed(self, domain: Domain, actor_id: str, ip_address: str) -> Domain:
        domain.status = DomainStatus.FAILED
        AuditService.log_event(
            db_session=self.db,
            event_type="domain.verification_failed",
            resource_type="domain",
            resource_id=domain.id,
            org_id=domain.org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"domain_name": domain.domain_name}
        )
        await self.db.commit()
        await self.db.refresh(domain)
        return domain

    async def delete_domain(self, domain: Domain, actor_id: str, ip_address: str) -> None:
        domain_id = domain.id
        org_id = domain.org_id
        domain_name = domain.domain_name
        
        await self.db.delete(domain)
        AuditService.log_event(
            db_session=self.db,
            event_type="domain.deleted",
            resource_type="domain",
            resource_id=domain_id,
            org_id=org_id,
            actor_id=actor_id,
            ip_address=ip_address,
            details={"domain_name": domain_name}
        )
        await self.db.commit()
