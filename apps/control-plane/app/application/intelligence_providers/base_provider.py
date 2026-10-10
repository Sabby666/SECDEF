"""Phase 4 Intelligence Provider Abstract Base Class.

Defines standard interface and security bounds for ingesting untrusted external intelligence feeds
(NVD, CISA KEV, FIRST EPSS, Vendor Advisories).
"""
import logging
import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sanitize_text(value: Optional[str], max_len: int = 5000) -> str:
    """Sanitize untrusted external string inputs against null bytes, control sequences, and buffer overruns."""
    if not value:
        return ""
    # Remove null bytes and non-printable control characters (except space, tab, newline)
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(value))
    return cleaned[:max_len].strip()


class ProviderValidationError(Exception):
    """Raised when external feed payload violates validation bounds."""
    pass


class BaseIntelligenceProvider:
    """Abstract Base Class for Phase 4 External Intelligence Feed Adapters."""

    MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024  # 10 MB payload cap
    MAX_NESTED_DEPTH: int = 10  # Maximum JSON nesting depth
    MAX_RECORDS_PER_RUN: int = 5000  # Cap records per run

    def __init__(self, source_name: str, source_type: str, config: Optional[Dict[str, Any]] = None):
        self.source_name = source_name
        self.source_type = source_type
        self.config = config or {}

    def validate_payload_size(self, raw_bytes: bytes) -> None:
        """Enforce maximum payload size bounds."""
        if len(raw_bytes) > self.MAX_RESPONSE_BYTES:
            raise ProviderValidationError(
                f"Payload size {len(raw_bytes)} bytes exceeds limit of {self.MAX_RESPONSE_BYTES} bytes"
            )

    def validate_structure_depth(self, data: Any, current_depth: int = 0) -> None:
        """Enforce maximum JSON structure depth to prevent recursion exhaustion attacks."""
        if current_depth > self.MAX_NESTED_DEPTH:
            raise ProviderValidationError(f"Payload structure depth exceeds max limit of {self.MAX_NESTED_DEPTH}")

        if isinstance(data, dict):
            for v in data.values():
                self.validate_structure_depth(v, current_depth + 1)
        elif isinstance(data, list):
            for item in data[:100]:  # Sample first 100 array items
                self.validate_structure_depth(item, current_depth + 1)

    def parse_raw_payload(self, raw_content: str) -> Dict[str, Any]:
        """Safely parse JSON payload with size and depth validation."""
        self.validate_payload_size(raw_content.encode('utf-8'))
        try:
            data = json.loads(raw_content)
        except Exception as err:
            raise ProviderValidationError(f"Malformed JSON payload: {str(err)}")

        self.validate_structure_depth(data)
        return data

    def extract_records(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and normalize raw feed records into standardized dictionaries."""
        raise NotImplementedError("Subclasses must implement extract_records")
