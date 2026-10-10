"""Base discovery provider framework with resource bounds, safety guards, and evidentiary data structures."""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class RawCandidateEvidence:
    """Represents raw candidate evidence produced by a discovery source."""
    canonical_identifier: str
    candidate_type: str  # subdomain, ip_address, service, certificate
    source_type: str  # certificate_transparency, passive_dns, active_dns, scanner
    confidence: str = "UNVERIFIED"  # HIGH, MEDIUM, LOW, UNVERIFIED
    exposure_state: str = "UNKNOWN"  # CURRENT, HISTORICAL, UNKNOWN
    raw_data: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseDiscoveryProvider:
    """Base interface and resource guard for all external discovery providers."""
    
    # Enforced operational limits per provider execution run
    MAX_CANDIDATES_PER_RUN: int = 1000
    MAX_SANS_PER_CERT: int = 50
    MAX_EXECUTION_TIME_SECONDS: float = 10.0
    MAX_RESPONSE_BYTES: int = 1_048_576  # 1 MB maximum payload limit
    MAX_RETRIES: int = 3  # Maximum 3 retries for transient 429/5xx/timeout errors

    async def execute_with_retry(self, func, *args, **kwargs):
        """Bounded retry wrapper executing func up to MAX_RETRIES times with exponential backoff."""
        attempt = 0
        backoff = 0.1
        while attempt < self.MAX_RETRIES:
            try:
                return await func(*args, **kwargs)
            except Exception as exc:
                attempt += 1
                if attempt >= self.MAX_RETRIES:
                    logger.error(f"Provider reached MAX_RETRIES ({self.MAX_RETRIES}). Terminal failure: {exc}")
                    raise exc
                logger.warning(f"Provider attempt {attempt} failed ({exc}). Retrying in {backoff}s...")
                import asyncio
                await asyncio.sleep(backoff)
                backoff *= 2.0


    @property
    def source_type(self) -> str:
        raise NotImplementedError("Subclasses must specify source_type")

    async def execute_discovery(
        self, org_id: str, domain_name: str, config: Optional[Dict[str, Any]] = None
    ) -> List[RawCandidateEvidence]:
        """Execute discovery for a target domain under organization scope."""
        raise NotImplementedError("Subclasses must implement execute_discovery")

    @staticmethod
    def is_subdomain_of(hostname: str, parent_domain: str) -> bool:
        """Check if hostname is identical to or a valid subdomain of parent_domain."""
        clean_host = hostname.strip().lower().rstrip(".")
        clean_parent = parent_domain.strip().lower().rstrip(".")

        # Reject empty, wildcards, or malformed entries
        if not clean_host or not clean_parent or "*" in clean_host:
            return False

        if clean_host == clean_parent:
            return True

        return clean_host.endswith(f".{clean_parent}")

    @staticmethod
    def sanitize_identifier(identifier: str) -> str:
        """Normalize and sanitize raw discovery identifiers."""
        return identifier.strip().lower().rstrip(".")
