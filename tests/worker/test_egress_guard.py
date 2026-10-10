import pytest
from worker.safety.egress_guard import is_ip_safe_for_egress


def test_public_ips_are_safe():
    assert is_ip_safe_for_egress("8.8.8.8") is True
    assert is_ip_safe_for_egress("1.1.1.1") is True
    assert is_ip_safe_for_egress("93.184.216.34") is True
    assert is_ip_safe_for_egress("2606:4700:4700::1111") is True


def test_private_ipv4_are_blocked():
    assert is_ip_safe_for_egress("10.0.0.1") is False
    assert is_ip_safe_for_egress("10.255.255.254") is False
    assert is_ip_safe_for_egress("172.16.0.1") is False
    assert is_ip_safe_for_egress("172.31.255.255") is False
    assert is_ip_safe_for_egress("192.168.1.1") is False
    assert is_ip_safe_for_egress("100.64.0.1") is False  # CGNAT


def test_loopback_and_metadata_are_blocked():
    assert is_ip_safe_for_egress("127.0.0.1") is False
    assert is_ip_safe_for_egress("127.0.0.53") is False
    assert is_ip_safe_for_egress("169.254.169.254") is False
    assert is_ip_safe_for_egress("0.0.0.0") is False
    assert is_ip_safe_for_egress("::1") is False
    assert is_ip_safe_for_egress("fe80::1") is False


def test_ipv4_mapped_ipv6_are_blocked():
    assert is_ip_safe_for_egress("::ffff:127.0.0.1") is False
    assert is_ip_safe_for_egress("::ffff:10.0.0.1") is False
    assert is_ip_safe_for_egress("::ffff:169.254.169.254") is False
    assert is_ip_safe_for_egress("::ffff:192.168.1.1") is False


def test_malformed_inputs_fail_closed():
    assert is_ip_safe_for_egress("") is False
    assert is_ip_safe_for_egress(None) is False
    assert is_ip_safe_for_egress("invalid_ip") is False
    assert is_ip_safe_for_egress("example.com") is False
    assert is_ip_safe_for_egress("256.256.256.256") is False
    assert is_ip_safe_for_egress("127.0.0.1.1") is False
    assert is_ip_safe_for_egress("http://10.0.0.1") is False
