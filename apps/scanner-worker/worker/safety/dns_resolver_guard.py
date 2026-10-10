import logging
from typing import List
import dns.asyncresolver
import dns.resolver
from worker.safety.egress_guard import is_ip_safe_for_egress

logger = logging.getLogger(__name__)


async def resolve_and_validate_target(domain_name: str, lifetime: float = 5.0) -> List[str]:
    """
    DNS TOCTOU / Rebinding Guard:
    1. Resolves hostname to all A and AAAA IP addresses.
    2. Validates EVERY single resolved IP against egress safety rules.
    3. Rejects IMMEDIATELY (returns empty list) if ANY resolved IP is unsafe (private/loopback/link-local/metadata)
       or if resolution fails/times out.
    4. Returns list of validated IP strings to be used directly in socket connections.
    """
    if not domain_name or not isinstance(domain_name, str):
        return []

    domain_name = domain_name.strip().rstrip(".")
    if not domain_name:
        return []

    resolved_ips: List[str] = []

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = lifetime

    # Resolve A records
    try:
        answers_a = await resolver.resolve(domain_name, "A")
        for rdata in answers_a:
            resolved_ips.append(rdata.address)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception as e:
        logger.warning(f"Unexpected error resolving A records for {domain_name}: {e}")

    # Resolve AAAA records
    try:
        answers_aaaa = await resolver.resolve(domain_name, "AAAA")
        for rdata in answers_aaaa:
            resolved_ips.append(rdata.address)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception as e:
        logger.warning(f"Unexpected error resolving AAAA records for {domain_name}: {e}")

    if not resolved_ips:
        logger.info(f"No IP addresses resolved for domain: {domain_name}")
        return []

    validated_ips: List[str] = []
    for ip_str in resolved_ips:
        if not is_ip_safe_for_egress(ip_str):
            logger.warning(
                f"DNS Safety Violation (TOCTOU/Rebinding Guard): "
                f"Domain '{domain_name}' resolved to prohibited IP '{ip_str}'. Target Rejected."
            )
            # Fail closed: reject the entire target if ANY resolved destination is unsafe
            return []
        validated_ips.append(ip_str)

    return validated_ips
