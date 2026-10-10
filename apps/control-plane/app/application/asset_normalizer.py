import ipaddress
import re
import urllib.parse
from typing import Dict, Any, Tuple, Optional
import idna


def normalize_hostname(hostname: str) -> str:
    """
    Canonical hostname normalization:
    - Trim whitespace
    - Lowercase
    - Strip trailing dot
    - Convert IDN/Unicode to canonical punycode
    - Reject malformed hostnames
    """
    if not hostname or not isinstance(hostname, str):
        raise ValueError("Hostname must be a non-empty string")

    cleaned = hostname.strip().lower()

    # Remove trailing dot if present (e.g., "example.com." -> "example.com")
    if cleaned.endswith(".") and len(cleaned) > 1:
        cleaned = cleaned[:-1]

    if not cleaned or len(cleaned) > 253:
        raise ValueError(f"Invalid hostname length: '{hostname}'")

    # Check for invalid characters or spaces
    if any(char in cleaned for char in (" ", "\t", "\r", "\n", "/", "\\", ":", "@", "#", "?")):
        raise ValueError(f"Hostname contains invalid characters: '{hostname}'")

    # IDN / Punycode normalization
    try:
        # Encode to punycode and back to ensure standard ascii format
        ascii_encoded = idna.encode(cleaned).decode("ascii")
        return ascii_encoded
    except Exception as e:
        raise ValueError(f"Failed IDN normalization for hostname '{hostname}': {e}")


def normalize_ip(ip_str: str) -> str:
    """
    Canonical IP address normalization:
    - Validates IPv4 and IPv6
    - Unwraps IPv4-mapped IPv6 addresses (e.g., '::ffff:1.2.3.4' -> '1.2.3.4')
    - Returns canonical compressed string format
    """
    if not ip_str or not isinstance(ip_str, str):
        raise ValueError("IP address must be a non-empty string")

    cleaned = ip_str.strip()

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        raise ValueError(f"Invalid IP address format: '{ip_str}'")

    # Unwrap IPv4-mapped IPv6 address (e.g. ::ffff:192.0.2.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        return str(ip_obj.ipv4_mapped)

    return str(ip_obj)


def normalize_port(port: Any) -> int:
    """
    Normalizes port to integer in range 1..65535.
    """
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid port value: '{port}'")

    if port_int < 1 or port_int > 65535:
        raise ValueError(f"Port out of valid range (1..65535): {port_int}")

    return port_int


def normalize_service_endpoint(ip_or_host: str, port: Any) -> str:
    """
    Normalizes a service target string (e.g., '1.2.3.4:443' or 'sub.example.com:8080').
    Handles both IP and Hostname targets safely.
    """
    p_int = normalize_port(port)

    # Try IP normalization first
    try:
        norm_target = normalize_ip(ip_or_host)
    except ValueError:
        norm_target = normalize_hostname(ip_or_host)

    return f"{norm_target}:{p_int}"


def normalize_url(url_str: str) -> Dict[str, Any]:
    """
    Normalizes a URL string into canonical parts:
    - Strips credentials (username:password)
    - Lowercases scheme & hostname
    - Normalizes host & port
    - Returns sanitized component dictionary
    """
    if not url_str or not isinstance(url_str, str):
        raise ValueError("URL must be a non-empty string")

    cleaned = url_str.strip()
    parsed = urllib.parse.urlparse(cleaned)

    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Malformed URL missing scheme or host: '{url_str}'")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{scheme}'")

    # Hostname normalization (without credentials)
    norm_host = normalize_hostname(parsed.hostname)

    # Port normalization
    default_port = 80 if scheme == "http" else 443
    port = parsed.port if parsed.port is not None else default_port
    norm_p = normalize_port(port)

    # Rebuild canonical URL (excluding credentials and parameters if unnecessary)
    path = parsed.path or "/"
    canonical_url = f"{scheme}://{norm_host}:{norm_p}{path}"

    return {
        "scheme": scheme,
        "hostname": norm_host,
        "port": norm_p,
        "path": path,
        "canonical_url": canonical_url,
    }
