"""FIRST EPSS (Exploit Prediction Scoring System) Intelligence Provider Adapter."""
import logging
from typing import Dict, Any, List, Optional

from app.application.intelligence_providers.base_provider import (
    BaseIntelligenceProvider, ProviderValidationError, sanitize_text, utc_now
)
from shared_contracts.enums import IntelligenceSourceType, Severity

logger = logging.getLogger(__name__)


class FirstEpssIntelligenceProvider(BaseIntelligenceProvider):
    """Adapter for ingesting FIRST EPSS probability score feed."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(
            source_name="first_epss_scores",
            source_type=IntelligenceSourceType.FIRST_EPSS.value,
            config=config
        )

    def extract_records(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract EPSS score items from FIRST API payload."""
        data_items = payload.get("data") or payload.get("epss") or []
        if not isinstance(data_items, list):
            raise ProviderValidationError("Expected list under 'data' or 'epss' in EPSS payload")

        normalized_records: List[Dict[str, Any]] = []

        for item in data_items[:self.MAX_RECORDS_PER_RUN]:
            try:
                cve_id = item.get("cve")
                if not cve_id or not str(cve_id).startswith("CVE-"):
                    continue

                external_id = sanitize_text(cve_id, 50)
                epss_score = float(item.get("epss", 0.0))
                epss_percentile = float(item.get("percentile", 0.0))

                severity = Severity.HIGH.value if epss_score >= 0.5 else Severity.MEDIUM.value

                record = {
                    "external_id": external_id,
                    "title": f"EPSS Score {external_id}",
                    "description": f"Exploit Prediction Score for {external_id}: probability={epss_score:.4f}, percentile={epss_percentile:.4f}",
                    "severity": severity,
                    "cvss_v3_score": None,
                    "cvss_vector": None,
                    "cwe_ids": [],
                    "affected_vendor": "unknown",
                    "affected_product": "unknown",
                    "affected_cpe": None,
                    "affected_version_range": "*",
                    "epss_score": epss_score,
                    "epss_percentile": epss_percentile,
                    "is_cisa_kev": False,
                    "exploit_availability": "PROBABILITY_ESTIMATED" if epss_score > 0.1 else "none",
                    "published_at": utc_now(),
                    "updated_at": utc_now(),
                    "raw_data": item,
                    "provenance": {
                        "provider": self.source_name,
                        "source_type": self.source_type,
                        "epss_score": epss_score,
                        "epss_percentile": epss_percentile,
                        "extracted_at": utc_now().isoformat()
                    }
                }
                normalized_records.append(record)
            except Exception as e:
                logger.warning("Failed to extract EPSS record item: %s", str(e))
                continue

        return normalized_records
