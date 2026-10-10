import pytest
from unittest.mock import patch, MagicMock
import dns.resolver
from app.infrastructure.dns.dns_verifier import DNSVerifier


@pytest.mark.asyncio
async def test_dns_verifier_match():
    verifier = DNSVerifier()
    
    # Mock dns.asyncresolver.resolve
    with patch("dns.asyncresolver.resolve") as mock_resolve:
        mock_rdata = MagicMock()
        mock_rdata.strings = [b"wrong_token", b"correct_token_123"]
        mock_resolve.return_value = [mock_rdata]
        
        result = await verifier.verify_txt_record("example.com", "correct_token_123")
        assert result is True
        mock_resolve.assert_called_once_with("_asm.example.com", "TXT", lifetime=verifier.resolver.lifetime)

@pytest.mark.asyncio
async def test_dns_verifier_no_match():
    verifier = DNSVerifier()
    
    with patch("dns.asyncresolver.resolve") as mock_resolve:
        mock_rdata = MagicMock()
        mock_rdata.strings = [b"wrong_token"]
        mock_resolve.return_value = [mock_rdata]
        
        result = await verifier.verify_txt_record("example.com", "correct_token_123")
        assert result is False

@pytest.mark.asyncio
async def test_dns_verifier_nxdomain():
    verifier = DNSVerifier()
    
    with patch("dns.asyncresolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        
        result = await verifier.verify_txt_record("example.com", "correct_token_123")
        assert result is False

@pytest.mark.asyncio
async def test_dns_verifier_timeout():
    verifier = DNSVerifier()
    
    with patch("dns.asyncresolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.exception.Timeout
        
        result = await verifier.verify_txt_record("example.com", "correct_token_123")
        assert result is False
