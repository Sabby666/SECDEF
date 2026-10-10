from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_admin, require_viewer
from app.api.dependencies.rate_limit import check_rate_limit
from app.application.domain_service import DomainService
from app.infrastructure.dns.dns_verifier import DNSVerifier
from shared_contracts.schemas import DomainCreateRequest, DomainResponse, APIErrorDetail

router = APIRouter(tags=["Domains"])


@router.post(
    "/organizations/{org_id}/domains",
    response_model=DomainResponse,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": APIErrorDetail}, 403: {"model": APIErrorDetail}}
)
async def create_domain(
    org_id: str,
    request: DomainCreateRequest,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session)
):
    """Register a new seed domain for the organization."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")
        
    await check_rate_limit(key=f"create_domain_org:{org_id}", limit=10, window=900)

    service = DomainService(db)
    client_ip = req.client.host if req.client else "unknown"
    
    try:
        domain = await service.add_domain(
            org_id=org_id,
            domain_name=request.domain_name,
            actor_id=auth_ctx["user"].id,
            ip_address=client_ip
        )
        return domain
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/organizations/{org_id}/domains",
    response_model=List[DomainResponse]
)
async def list_domains(
    org_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    """List all registered domains for the organization."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")
        
    service = DomainService(db)
    domains = await service.get_domains_for_org(org_id)
    return domains


@router.get(
    "/organizations/{org_id}/domains/{domain_id}",
    response_model=DomainResponse
)
async def get_domain(
    org_id: str,
    domain_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session)
):
    """Get domain details and verification status."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")
        
    service = DomainService(db)
    domain = await service.get_domain(org_id, domain_id)
    if not domain:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
        
    return domain


@router.post(
    "/organizations/{org_id}/domains/{domain_id}/verify",
    response_model=DomainResponse
)
async def verify_domain(
    org_id: str,
    domain_id: str,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session)
):
    """Trigger DNS TXT verification for the domain."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")
        
    await check_rate_limit(key=f"verify_domain:{domain_id}", limit=5, window=60)
        
    service = DomainService(db)
    client_ip = req.client.host if req.client else "unknown"
    
    domain = await service.get_domain_for_verification(org_id, domain_id, auth_ctx["user"].id, client_ip)
    
    if not domain:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
        
    if domain.status == "expired":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification token has expired")
        
    verifier = DNSVerifier()
    is_verified = await verifier.verify_txt_record(domain.domain_name, domain.verification_token)
    
    if is_verified:
        domain = await service.mark_domain_verified(domain, auth_ctx["user"].id, client_ip)
    else:
        domain = await service.mark_domain_verification_failed(domain, auth_ctx["user"].id, client_ip)
        
    return domain

@router.delete(
    "/organizations/{org_id}/domains/{domain_id}",
    status_code=status.HTTP_204_NO_CONTENT
)
async def delete_domain(
    org_id: str,
    domain_id: str,
    req: Request,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete a domain from the organization."""
    if org_id != auth_ctx["org"].id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")
        
    service = DomainService(db)
    domain = await service.get_domain(org_id, domain_id)
    if not domain:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
        
    client_ip = req.client.host if req.client else "unknown"
    await service.delete_domain(domain, auth_ctx["user"].id, client_ip)
    return None
