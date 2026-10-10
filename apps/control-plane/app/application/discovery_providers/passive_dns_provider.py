"""Passive DNS discovery provider implementation."""
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from app.application.discovery_providers.base import BaseDiscoveryProvider, RawCandidateEvidence
from shared_contracts.enums import DiscoverySourceType, DiscoveryConfidence, ExposureState

logger = logging.getLogger(__name__)


class PassiveDNSProvider(BaseDiscoveryProvider):
    """Discovers DNS historical and current mapping evidence from Passive DNS records."""

    @property
    def source_type(self) -> str:
        return DiscoverySourceType.PASSIVE_DNS.value

    async def execute_discovery(
        self, org_id: str, domain_name: str, config: Optional[Dict[str, Any]] = None
    ) -> List[RawCandidateEvidence]:
        config = config or {}
        results: List[RawCandidateEvidence] = []
        seen_keys = set()

        raw_records = config.get("mock_records")
        clean_dom = domain_name.strip().lower()

        if raw_records is None:
            raw_records = [
                {
                    "query": clean_dom,
                    "rrtype": "A",
                    "rdata": "192.0.2.10",
                    "first_seen": "2024-01-01T00:00:00Z",
                    "last_seen": "2026-03-01T00:00:00Z",
                    "is_current": True,
                },
                {
                    "query": f"api.{clean_dom}",
                    "rrtype": "A",
                    "rdata": "192.0.2.20",
                    "first_seen": "2024-06-01T00:00:00Z",
                    "last_seen": "2026-03-15T00:00:00Z",
                    "is_current": True,
                },
                {
                    "query": f"legacy-auth.{clean_dom}",
                    "rrtype": "A",
                    "rdata": "198.51.100.55",
                    "first_seen": "2021-01-01T00:00:00Z",
                    "last_seen": "2023-12-31T00:00:00Z",
                    "is_current": False,
                },
                {
                    "query": f"cname-gateway.{clean_dom}",
                    "rrtype": "CNAME",
                    "rdata": f"lb.{clean_dom}",
                    "first_seen": "2025-01-01T00:00:00Z",
                    "last_seen": "2026-03-20T00:00:00Z",
                    "is_current": True,
                },
            ]

        now = datetime.now(timezone.utc)

        for rec in raw_records:
            hostname = self.sanitize_identifier(rec.get("query", ""))
            rrtype = rec.get("rrtype", "A")
            rdata = rec.get("rdata", "")
            is_current = rec.get("is_current", True)

            if not self.is_subdomain_of(hostname, domain_name):
                continue

            dedup_key = f"{hostname}:{rrtype}:{rdata}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            exposure = ExposureState.CURRENT.value if is_current else ExposureState.HISTORICAL.value

            evidence = RawCandidateEvidence(
                canonical_identifier=hostname,
                candidate_type="subdomain",
                source_type=self.source_type,
                confidence=DiscoveryConfidence.MEDIUM.value,
                exposure_state=exposure,
                raw_data={
                    "query": hostname,
                    "rrtype": rrtype,
                    "rdata": rdata,
                    "first_seen": rec.get("first_seen"),
                    "last_seen": rec.get("last_seen"),
                    "is_current": is_current,
                },
                provenance={
                    "provider": "passive_dns",
                    "domain_name": domain_name,
                    "rrtype": rrtype,
                    "rdata": rdata,
                    "observed_at": now.isoformat(),
                },
                observed_at=now,
            )
            results.append(evidence)

            if len(results) >= self.MAX_CANDIDATES_PER_RUN:
                logger.warning(
                    f"Passive DNS discovery for {domain_name} hit MAX_CANDIDATES_PER_RUN limit"
                )
                return results

        return results
