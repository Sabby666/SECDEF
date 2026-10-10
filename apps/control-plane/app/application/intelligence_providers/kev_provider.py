"""CISA KEV (Known Exploited Vulnerabilities) Intelligence Provider Adapter."""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.application.intelligence_providers.base_provider import (
    BaseIntelligenceProvider, ProviderValidationError, sanitize_text, utc_now
)
from shared_contracts.enums import IntelligenceSourceType, Severity

logger = logging.getLogger(__name__)


class CisaKevIntelligenceProvider(BaseIntelligenceProvider):
    """Adapter for ingesting CISA Known Exploited Vulnerabilities (KEV) catalog feed."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(
            source_name="cisa_kev_catalog",
            source_type=IntelligenceSourceType.CISA_KEV.value,
            config=config
        )

    def extract_records(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerability items from CISA KEV JSON catalog payload."""
        vulnerabilities = payload.get("vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ProviderValidationError("Expected list under 'vulnerabilities' in CISA KEV payload")

        normalized_records: List[Dict[str, Any]] = []

        for item in vulnerabilities[:self.MAX_RECORDS_PER_RUN]:
            try:
                cve_id = item.get("cveID")
                if not cve_id or not str(cve_id).startswith("CVE-"):
                    continue

                external_id = sanitize_text(cve_id, 50)
                vendor_proj = sanitize_text(item.get("vendorProject", "unknown"), 100)
                product_name = sanitize_text(item.get("product", "unknown"), 100)
                vuln_name = sanitize_text(item.get("vulnerabilityName", f"KEV {external_id}"), 255)
                short_desc = sanitize_text(item.get("shortDescription", f"CISA KEV catalog entry for {external_id}"), 4000)

                date_added_str = item.get("dateAdded")
                published_at = None
                if date_added_str:
                    try:
                        published_at = datetime.fromisoformat(date_added_str + "T00:00:00+00:00")
                    except Exception:
                        published_at = utc_now()

                record = {
                    "external_id": external_id,
                    "title": vuln_name,
                    "description": short_desc,
                    "severity": Severity.HIGH.value,
                    "cvss_v3_score": 8.5,
                    "cvss_vector": None,
                    "cwe_ids": [],
                    "affected_vendor": vendor_proj.lower(),
                    "affected_product": product_name.lower(),
                    "affected_cpe": None,
                    "affected_version_range": "*",
                    "is_cisa_kev": True,
                    "exploit_availability": "ACTIVE_EXPLOITATION",
                    "published_at": published_at or utc_now(),
                    "updated_at": utc_now(),
                    "raw_data": item,
                    "provenance": {
                        "provider": self.source_name,
                        "source_type": self.source_type,
                        "cisa_required_action": item.get("requiredAction"),
                        "cisa_due_date": item.get("dueDate"),
                        "known_ransomware_use": item.get("knownRansomwareCampaignUse"),
                        "extracted_at": utc_now().isoformat()
                    }
                }
                normalized_records.append(record)
            except Exception as e:
                logger.warning("Failed to extract CISA KEV record item: %s", str(e))
                continue

        return normalized_records
