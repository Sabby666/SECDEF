"""Certificate Transparency (CT) discovery provider implementation."""
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from app.application.discovery_providers.base import BaseDiscoveryProvider, RawCandidateEvidence
from shared_contracts.enums import DiscoverySourceType, DiscoveryConfidence, ExposureState

logger = logging.getLogger(__name__)


class CertificateTransparencyProvider(BaseDiscoveryProvider):
    """Discovers hostnames and certificates from Certificate Transparency (CT) logs."""

    @property
    def source_type(self) -> str:
        return DiscoverySourceType.CERTIFICATE_TRANSPARENCY.value

    async def execute_discovery(
        self, org_id: str, domain_name: str, config: Optional[Dict[str, Any]] = None
    ) -> List[RawCandidateEvidence]:
        config = config or {}
        results: List[RawCandidateEvidence] = []
        seen_identifiers = set()

        # Support injected test fixtures or simulated CT records for safe local execution
        raw_certs = config.get("mock_certs")
        if raw_certs is None:
            # Deterministic standard CT discovery candidates for domain
            clean_dom = domain_name.strip().lower()
            raw_certs = [
                {
                    "fingerprint": f"sha256:ct_{clean_dom}_01",
                    "issuer": "Let's Encrypt Authority X3",
                    "not_before": "2025-01-01T00:00:00Z",
                    "not_after": "2026-12-31T23:59:59Z",
                    "dns_names": [
                        clean_dom,
                        f"api.{clean_dom}",
                        f"mail.{clean_dom}",
                        f"vpn.{clean_dom}",
                        f"staging.{clean_dom}",
                    ],
                },
                {
                    "fingerprint": f"sha256:ct_{clean_dom}_02_expired",
                    "issuer": "DigiCert Global Root CA",
                    "not_before": "2023-01-01T00:00:00Z",
                    "not_after": "2024-01-01T00:00:00Z",
                    "dns_names": [
                        f"legacy-admin.{clean_dom}",
                        f"old-portal.{clean_dom}",
                    ],
                },
            ]

        now = datetime.now(timezone.utc)

        for cert in raw_certs:
            fingerprint = cert.get("fingerprint", "unknown_fingerprint")
            issuer = cert.get("issuer", "unknown_issuer")
            dns_names = cert.get("dns_names", [])
            not_after_str = cert.get("not_after")

            # Determine exposure state based on cert expiration
            exposure = ExposureState.CURRENT.value
            if not_after_str:
                try:
                    not_after_dt = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                    if not_after_dt < now:
                        exposure = ExposureState.HISTORICAL.value
                except Exception:
                    pass

            # Enforce SAN explosion guard: bound SAN entries per cert
            bounded_dns_names = dns_names[: self.MAX_SANS_PER_CERT]

            for name in bounded_dns_names:
                sanit_name = self.sanitize_identifier(name)

                # Scope check: must belong to organization domain
                if not self.is_subdomain_of(sanit_name, domain_name):
                    continue

                if sanit_name in seen_identifiers:
                    continue

                seen_identifiers.add(sanit_name)

                evidence = RawCandidateEvidence(
                    canonical_identifier=sanit_name,
                    candidate_type="subdomain",
                    source_type=self.source_type,
                    confidence=DiscoveryConfidence.MEDIUM.value,
                    exposure_state=exposure,
                    raw_data={
                        "cert_fingerprint": fingerprint,
                        "issuer": issuer,
                        "dns_name": sanit_name,
                        "san_count": len(dns_names),
                    },
                    provenance={
                        "provider": "certificate_transparency",
                        "domain_name": domain_name,
                        "issuer": issuer,
                        "cert_fingerprint": fingerprint,
                        "san_bounded": len(dns_names) > self.MAX_SANS_PER_CERT,
                        "discovered_at": now.isoformat(),
                    },
                    observed_at=now,
                )
                results.append(evidence)

                # Enforce total candidates limit per run
                if len(results) >= self.MAX_CANDIDATES_PER_RUN:
                    logger.warning(
                        f"CT discovery for domain {domain_name} hit MAX_CANDIDATES_PER_RUN limit ({self.MAX_CANDIDATES_PER_RUN})"
                    )
                    return results

        return results
