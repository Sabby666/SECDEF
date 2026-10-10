"""Active DNS expansion discovery provider implementation with egress safety guards."""
import logging
import socket
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from app.application.discovery_providers.base import BaseDiscoveryProvider, RawCandidateEvidence
from shared_contracts.enums import DiscoverySourceType, DiscoveryConfidence, ExposureState

logger = logging.getLogger(__name__)


BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def is_ip_safe_for_egress(ip_str: Optional[str]) -> bool:
    """Validate that target IP string is NOT private, loopback, link-local, or cloud metadata.
    Fails closed (returns False) for invalid inputs or unparseable strings.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    ip_str = ip_str.strip()
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return False

    for network in BLOCKED_NETWORKS:
        if ip in network:
            return False

    return True


def safe_dial_host(ip_str: str, port: int = 80, timeout: float = 3.0) -> socket.socket:

    """Safely open socket connection pinned to a pre-validated IP address.
    Re-evaluates is_ip_safe_for_egress immediately prior to connection, defeating DNS rebinding.
    """
    if not is_ip_safe_for_egress(ip_str):
        raise ValueError(f"Egress safety guard blocked connection to unsafe IP: {ip_str}")
    
    # Dial exact IP to avoid TOCTOU DNS rebinding re-resolution
    return socket.create_connection((ip_str, port), timeout=timeout)


class ActiveDNSDiscoveryProvider(BaseDiscoveryProvider):

    """Performs controlled, authorization-bounded active DNS enumeration and record expansion."""

    @property
    def source_type(self) -> str:
        return DiscoverySourceType.ACTIVE_DNS.value

    async def execute_discovery(
        self, org_id: str, domain_name: str, config: Optional[Dict[str, Any]] = None
    ) -> List[RawCandidateEvidence]:
        config = config or {}
        results: List[RawCandidateEvidence] = []
        seen = set()

        clean_dom = domain_name.strip().lower()

        # Wordlist prefixes for controlled active enumeration
        wordlist = config.get("wordlist")
        if not wordlist:
            wordlist = [
                "api",
                "app",
                "dev",
                "staging",
                "mail",
                "vpn",
                "admin",
                "portal",
                "auth",
                "gateway",
                "test",
                "prod",
            ]

        # Injected test resolves or real DNS resolution simulation
        mock_resolutions = config.get("mock_resolutions")

        now = datetime.now(timezone.utc)

        for prefix in wordlist:
            hostname = f"{prefix}.{clean_dom}"
            sanit_name = self.sanitize_identifier(hostname)

            if not self.is_subdomain_of(sanit_name, domain_name):
                continue

            if sanit_name in seen:
                continue
            seen.add(sanit_name)

            resolved_ips = []
            if mock_resolutions and sanit_name in mock_resolutions:
                raw_ips = mock_resolutions[sanit_name]
                for raw_ip in raw_ips:
                    if is_ip_safe_for_egress(raw_ip):
                        resolved_ips.append(raw_ip)
                    else:
                        logger.warning(
                            f"Active DNS discovery blocked unsafe IP {raw_ip} for candidate {sanit_name}"
                        )
            else:
                # Local DNS socket lookup with safety filter
                try:
                    _, _, ip_list = socket.gethostbyname_ex(sanit_name)
                    for ip_candidate in ip_list:
                        if is_ip_safe_for_egress(ip_candidate):
                            resolved_ips.append(ip_candidate)
                except (socket.gaierror, socket.herror, TimeoutError):
                    # Unresolvable hostname in real network -> skip
                    continue
                except Exception as e:
                    logger.debug(f"DNS resolution exception for {sanit_name}: {e}")
                    continue

            # If resolved or mock resolution provided valid evidence
            if mock_resolutions or resolved_ips:
                evidence = RawCandidateEvidence(
                    canonical_identifier=sanit_name,
                    candidate_type="subdomain",
                    source_type=self.source_type,
                    confidence=DiscoveryConfidence.HIGH.value if resolved_ips else DiscoveryConfidence.MEDIUM.value,
                    exposure_state=ExposureState.CURRENT.value,
                    raw_data={
                        "hostname": sanit_name,
                        "resolved_ips": resolved_ips,
                        "wordlist_prefix": prefix,
                    },
                    provenance={
                        "provider": "active_dns",
                        "domain_name": domain_name,
                        "resolved_ip_count": len(resolved_ips),
                        "observed_at": now.isoformat(),
                    },
                    observed_at=now,
                )
                results.append(evidence)

                if len(results) >= self.MAX_CANDIDATES_PER_RUN:
                    logger.warning(
                        f"Active DNS discovery for {domain_name} hit MAX_CANDIDATES_PER_RUN limit"
                    )
                    return results

        return results
