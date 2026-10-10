import pytest
from app.application.domain_service import normalize_domain, generate_verification_token


def test_normalize_domain_trims_whitespace():
    assert normalize_domain("  example.com  ") == "example.com"
    assert normalize_domain("\texample.com\n") == "example.com"

def test_normalize_domain_lowercases():
    assert normalize_domain("EXAMPLE.COM") == "example.com"
    assert normalize_domain("ExAmPlE.cOm") == "example.com"

def test_normalize_domain_removes_trailing_dot():
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("sub.example.com.") == "sub.example.com"

def test_normalize_domain_invalid_length():
    with pytest.raises(ValueError, match="Invalid domain syntax"):
        long_domain = "a" * 250 + ".com"
        normalize_domain(long_domain)

def test_normalize_domain_invalid_syntax():
    with pytest.raises(ValueError, match="Invalid domain syntax"):
        normalize_domain("-example.com")
    with pytest.raises(ValueError, match="Invalid domain syntax"):
        normalize_domain("example-.com")
    with pytest.raises(ValueError, match="Invalid domain syntax"):
        normalize_domain("ex ample.com")

def test_generate_verification_token_length_and_randomness():
    token1 = generate_verification_token()
    token2 = generate_verification_token()
    assert token1 != token2
    assert len(token1) >= 43 # 32 bytes base64url encoded is 43 chars
