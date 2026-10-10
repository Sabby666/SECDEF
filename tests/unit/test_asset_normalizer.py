import pytest
from app.application.asset_normalizer import (
    normalize_hostname,
    normalize_ip,
    normalize_port,
    normalize_service_endpoint,
    normalize_url,
)


def test_hostname_normalization():
    # Lowercase & whitespace trim
    assert normalize_hostname("  EXAMPLE.COM  ") == "example.com"
    # Trailing dot removal
    assert normalize_hostname("sub.example.com.") == "sub.example.com"
    # Mixed case with trailing dot
    assert normalize_hostname("API.Staging.Example.Com.") == "api.staging.example.com"
    # IDN Punycode conversion
    assert normalize_hostname("bücher.example.com") == "xn--bcher-kva.example.com"
    assert normalize_hostname("XN--BCHER-KVA.EXAMPLE.COM.") == "xn--bcher-kva.example.com"


def test_hostname_validation_failures():
    with pytest.raises(ValueError):
        normalize_hostname("")
    with pytest.raises(ValueError):
        normalize_hostname("   ")
    with pytest.raises(ValueError):
        normalize_hostname("invalid hostname with spaces.com")
    with pytest.raises(ValueError):
        normalize_hostname("example.com:8080")
    with pytest.raises(ValueError):
        normalize_hostname("http://example.com")


def test_ip_normalization():
    # Canonical IPv4
    assert normalize_ip("192.0.2.1") == "192.0.2.1"
    assert normalize_ip("  192.0.2.1  ") == "192.0.2.1"

    # Canonical IPv6
    assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert normalize_ip("2001:db8::1") == "2001:db8::1"

    # IPv4-mapped IPv6 unwrapping
    assert normalize_ip("::ffff:192.0.2.1") == "192.0.2.1"
    assert normalize_ip("0:0:0:0:0:ffff:192.0.2.1") == "192.0.2.1"


def test_ip_validation_failures():
    with pytest.raises(ValueError):
        normalize_ip("")
    with pytest.raises(ValueError):
        normalize_ip("256.256.256.256")
    with pytest.raises(ValueError):
        normalize_ip("192.0.2.1.5")
    with pytest.raises(ValueError):
        normalize_ip("not-an-ip")


def test_port_normalization():
    assert normalize_port(80) == 80
    assert normalize_port("443") == 443
    assert normalize_port(65535) == 65535

    with pytest.raises(ValueError):
        normalize_port(0)
    with pytest.raises(ValueError):
        normalize_port(65536)
    with pytest.raises(ValueError):
        normalize_port("invalid")


def test_service_endpoint_normalization():
    assert normalize_service_endpoint("192.0.2.1", 8080) == "192.0.2.1:8080"
    assert normalize_service_endpoint("::ffff:192.0.2.1", "443") == "192.0.2.1:443"
    assert normalize_service_endpoint("API.EXAMPLE.COM.", 8443) == "api.example.com:8443"


def test_url_normalization():
    res = normalize_url("HTTPS://User:Pass@API.Example.Com:8443/v1/resource?query=1")
    assert res["scheme"] == "https"
    assert res["hostname"] == "api.example.com"
    assert res["port"] == 8443
    assert res["canonical_url"] == "https://api.example.com:8443/v1/resource"
    # Credentials stripped
    assert "User" not in res["canonical_url"]
    assert "Pass" not in res["canonical_url"]


def test_url_validation_failures():
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")
    with pytest.raises(ValueError):
        normalize_url("not a url")
