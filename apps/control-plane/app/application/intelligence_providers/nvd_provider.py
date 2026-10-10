"""NVD (National Vulnerability Database) Intelligence Provider Adapter."""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.application.intelligence_providers.base_provider import (
    BaseIntelligenceProvider, ProviderValidationError, sanitize_text, utc_now
)
from shared_contracts.enums import IntelligenceSourceType, Severity

logger = logging.getLogger(__name__)


class NvdIntelligenceProvider(BaseIntelligenceProvider):
    """Adapter for ingesting CVE records from National Vulnerability Database (NVD) schema."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(
            source_name="nvd_cve_feed",
            source_type=IntelligenceSourceType.NVD.value,
            config=config
        )

    def extract_records(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract CVE records from NVD API or JSON feed payload."""
        vulnerabilities = payload.get("vulnerabilities") or payload.get("CVE_Items") or []
        if not isinstance(vulnerabilities, list):
            raise ProviderValidationError("Expected list under 'vulnerabilities' or 'CVE_Items'")

        normalized_records: List[Dict[str, Any]] = []

        for item in vulnerabilities[:self.MAX_RECORDS_PER_RUN]:
            try:
                cve_data = item.get("cve", item)
                id_val = cve_data.get("id") or cve_data.get("CVE_data_meta", {}).get("ID")
                if not id_val or not str(id_val).startswith("CVE-"):
                    continue

                external_id = sanitize_text(id_val, 50)
                descriptions = cve_data.get("descriptions") or []
                desc_text = ""
                if isinstance(descriptions, list):
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc_text = d.get("value", "")
                            break
                if not desc_text and isinstance(cve_data.get("description"), dict):
                    desc_text = cve_data["description"].get("description_data", [{}])[0].get("value", "")

                desc_text = sanitize_text(desc_text, 4000) or f"NVD record for {external_id}"
                title = sanitize_text(f"Vulnerability {external_id}", 255)

                # Metrics / CVSS
                metrics = cve_data.get("metrics", {})
                cvss_v3_score = None
                cvss_vector = None
                severity_str = Severity.MEDIUM.value

                if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                    v3 = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_v3_score = float(v3.get("baseScore", 0.0))
                    cvss_vector = sanitize_text(v3.get("vectorString", ""), 100)
                    severity_str = sanitize_text(v3.get("baseSeverity", "").lower(), 20) or Severity.MEDIUM.value
                elif "cvssMetricV30" in metrics and len(metrics["cvssMetricV30"]) > 0:
                    v3 = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cvss_v3_score = float(v3.get("baseScore", 0.0))
                    cvss_vector = sanitize_text(v3.get("vectorString", ""), 100)
                    severity_str = sanitize_text(v3.get("baseSeverity", "").lower(), 20) or Severity.MEDIUM.value

                if severity_str not in [s.value for s in Severity]:
                    severity_str = Severity.MEDIUM.value

                # Weaknesses / CWE
                cwe_ids = []
                weaknesses = cve_data.get("weaknesses", [])
                for w in weaknesses:
                    desc_list = w.get("description", [])
                    for d in desc_list:
                        val = d.get("value", "")
                        if val.startswith("CWE-"):
                            cwe_ids.append(sanitize_text(val, 20))

                # Affected configurations / CPE
                affected_vendor = "unknown"
                affected_product = "unknown"
                affected_cpe = None
                affected_version_range = None

                configurations = cve_data.get("configurations", [])
                for cfg in configurations:
                    nodes = cfg.get("nodes", [])
                    for node in nodes:
                        cpe_matches = node.get("cpeMatch", [])
                        for cpe_item in cpe_matches:
                            cpe_str = cpe_item.get("criteria") or cpe_item.get("cpe23Uri")
                            if cpe_str and cpe_str.startswith("cpe:2.3:"):
                                parts = cpe_str.split(":")
                                if len(parts) >= 6:
                                    affected_vendor = sanitize_text(parts[3], 100)
                                    affected_product = sanitize_text(parts[4], 100)
                                    affected_cpe = sanitize_text(cpe_str, 255)
                                    ver_start = cpe_item.get("versionStartIncluding") or cpe_item.get("versionStartExcluding")
                                    ver_end = cpe_item.get("versionEndIncluding") or cpe_item.get("versionEndExcluding")
                                    if ver_start or ver_end:
                                        affected_version_range = f">={ver_start or '0.0.0'}, <= {ver_end or '*'}"
                                    elif len(parts) > 5 and parts[5] != "*":
                                        affected_version_range = sanitize_text(parts[5], 100)
                                break

                # Timestamps
                pub_str = cve_data.get("published")
                published_at = None
                if pub_str:
                    try:
                        published_at = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                    except Exception:
                        published_at = utc_now()

                record = {
                    "external_id": external_id,
                    "title": title,
                    "description": desc_text,
                    "severity": severity_str,
                    "cvss_v3_score": cvss_v3_score,
                    "cvss_vector": cvss_vector,
                    "cwe_ids": cwe_ids,
                    "affected_vendor": affected_vendor.lower(),
                    "affected_product": affected_product.lower(),
                    "affected_cpe": affected_cpe,
                    "affected_version_range": affected_version_range,
                    "is_cisa_kev": False,
                    "exploit_availability": "none",
                    "published_at": published_at or utc_now(),
                    "updated_at": utc_now(),
                    "raw_data": item,
                    "provenance": {
                        "provider": self.source_name,
                        "source_type": self.source_type,
                        "extracted_at": utc_now().isoformat()
                    }
                }
                normalized_records.append(record)
            except Exception as e:
                logger.warning("Failed to extract NVD record item: %s", str(e))
                continue

        return normalized_records
