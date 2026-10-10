import ipaddress
from typing import Optional


BLOCKED_NETWORKS = [
    # IPv4 Private & Special
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),    # Loopback
    ipaddress.ip_network("169.254.0.0/16"), # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),  # Private RFC 1918
    ipaddress.ip_network("192.168.0.0/16"), # Private RFC 1918
    
    # IPv6 Loopback & Link-local & Private
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def is_ip_safe_for_egress(ip_str: Optional[str]) -> bool:
    """Validate that target IP string is NOT private, loopback, link-local, or cloud metadata.
    
    Fails closed (returns False) for invalid inputs, hostnames, or unparseable strings.
    Handles IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1).
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    ip_str = ip_str.strip()

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Fail-closed for non-IP strings / hostnames / malformed input
        return False

    # Unmap IPv4-mapped IPv6 addresses (e.g. ::ffff:10.0.0.1 -> 10.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    # Check built-in properties
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return False

    # Check explicit denylist networks
    for network in BLOCKED_NETWORKS:
        if ip in network:
            return False

    return True
