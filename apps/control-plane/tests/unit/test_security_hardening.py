import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from app.application.domain_service import DomainService, normalize_domain
from app.infrastructure.db.models import Domain, AuditEvent
from shared_contracts.enums import DomainStatus
import dns.resolver

@pytest.mark.asyncio
async def test_domain_expiry_check():
    """Test that a domain older than 72 hours transitions to EXPIRED."""
    db_mock = AsyncMock()
    service = DomainService(db_mock)
    
    domain_mock = MagicMock(spec=Domain)
    domain_mock.id = "domain-123"
    domain_mock.org_id = "org-123"
    domain_mock.domain_name = "example.com"
    domain_mock.status = DomainStatus.PENDING_VERIFICATION
    # Mock created_at to 73 hours ago
    domain_mock.created_at = datetime.now(timezone.utc) - timedelta(hours=73)
    
    # Mock the scalars().first() chain
    result_mock = MagicMock()
    result_mock.scalars().first.return_value = domain_mock
    db_mock.execute.return_value = result_mock
    
    with patch("app.application.audit_service.AuditService.log_event") as mock_audit:
        res = await service.get_domain_for_verification("org-123", "domain-123", "actor-123", "127.0.0.1")
        
        assert res is not None
        assert res.status == DomainStatus.EXPIRED
        db_mock.commit.assert_called_once()
        mock_audit.assert_called_once()


def test_idn_normalization():
    """Test that Unicode domains are properly encoded into punycode."""
    unicode_domain = "münchen.de"
    expected = "xn--mnchen-3ya.de"
    assert normalize_domain(unicode_domain) == expected

def test_idn_normalization_invalid():
    """Test that invalid domains raise ValueError."""
    with pytest.raises(ValueError, match="Invalid domain syntax"):
        normalize_domain("invalid_.com")

@pytest.mark.asyncio
async def test_dns_verifier_no_nameservers():
    """Test that dns_verifier handles NoNameservers properly."""
    from app.infrastructure.dns.dns_verifier import DNSVerifier
    verifier = DNSVerifier()
    
    with patch("dns.asyncresolver.resolve", side_effect=dns.resolver.NoNameservers):
        res = await verifier.verify_txt_record("example.com", "some-token")
        assert res is False
