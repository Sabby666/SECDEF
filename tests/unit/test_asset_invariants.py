import pytest
from app.application.asset_normalizer import (
    normalize_hostname,
    normalize_ip,
    normalize_port,
    normalize_service_endpoint,
)


@pytest.mark.parametrize("hostname", [
    "EXAMPLE.COM.",
    "  sub.domain.org  ",
    "API.STAGING.EXAMPLE.COM.",
    "xn--bcher-kva.example.com."
])
def test_hostname_normalization_idempotency(hostname):
    """Invariant: normalize(normalize(x)) == normalize(x)"""
    first_pass = normalize_hostname(hostname)
    second_pass = normalize_hostname(first_pass)
    assert first_pass == second_pass


@pytest.mark.parametrize("ip", [
    "192.0.2.1",
    "  198.51.100.45  ",
    "::ffff:192.0.2.1",
    "2001:0db8:0000:0000:0000:0000:0000:0001"
])
def test_ip_normalization_idempotency(ip):
    """Invariant: normalize_ip(normalize_ip(x)) == normalize_ip(x)"""
    first_pass = normalize_ip(ip)
    second_pass = normalize_ip(first_pass)
    assert first_pass == second_pass


@pytest.mark.parametrize("target,port", [
    ("192.0.2.1", 443),
    ("::ffff:192.0.2.1", "8080"),
    ("SUB.EXAMPLE.COM.", 8443)
])
def test_service_endpoint_normalization_idempotency(target, port):
    """Invariant: normalize_service(normalize_service(x)) == normalize_service(x)"""
    first_pass = normalize_service_endpoint(target, port)
    ip_host, p = first_pass.rsplit(":", 1)
    second_pass = normalize_service_endpoint(ip_host, int(p))
    assert first_pass == second_pass
