import logging
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from worker.safety.dns_resolver_guard import resolve_and_validate_target

logger = logging.getLogger(__name__)


async def validate_redirect_url(
    target_url: str,
    current_hop: int = 0,
    max_hops: int = 5
) -> Tuple[bool, Optional[str], List[str]]:
    """
    Redirect Safety Guard:
    1. Validates current hop count <= max_hops (max 5).
    2. Parses URL syntax safely using urlparse.
    3. Enforces scheme MUST be http or https.
    4. Rejects credentials in URL (e.g. http://user:pass@host).
    5. Resolves target hostname and validates EVERY IP address via egress safety guard.
    6. Returns (is_safe, parsed_url_string, validated_ips).
    """
    if current_hop >= max_hops:
        logger.warning(f"Redirect limit exceeded (max {max_hops} hops): {target_url}")
        return False, None, []

    if not target_url or not isinstance(target_url, str):
        return False, None, []

    target_url = target_url.strip()

    try:
        parsed = urlparse(target_url)
    except Exception as e:
        logger.warning(f"Malformed redirect URL '{target_url}': {e}")
        return False, None, []

    # Scheme validation (HTTP/HTTPS only)
    if parsed.scheme.lower() not in ("http", "https"):
        logger.warning(f"Prohibited redirect scheme '{parsed.scheme}' in URL '{target_url}'")
        return False, None, []

    # Reject credentials in URL
    if parsed.username or parsed.password:
        logger.warning(f"Credentials detected in redirect URL '{target_url}' - Target Rejected.")
        return False, None, []

    hostname = parsed.hostname
    if not hostname:
        logger.warning(f"Missing hostname in redirect URL '{target_url}'")
        return False, None, []

    # Resolve and validate destination IPs (TOCTOU & Rebinding Guard)
    validated_ips = await resolve_and_validate_target(hostname)
    if not validated_ips:
        logger.warning(f"Redirect hop destination '{hostname}' failed network safety check.")
        return False, None, []

    return True, target_url, validated_ips
