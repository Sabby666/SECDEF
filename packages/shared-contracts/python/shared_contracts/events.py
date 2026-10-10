from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class BaseQueueEvent(BaseModel):
    schema_version: str = Field(default="1.0", description="Contract schema version")
    event_id: str = Field(..., description="Unique event execution ID")
    org_id: str = Field(..., description="Tenant organization ID")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanExecuteJobPayload(BaseQueueEvent):
    scan_id: str
    domain_id: str
    domain_name: str
    job_nonce: str
    target_ports: Optional[List[int]] = None


class ScanResultPayload(BaseQueueEvent):
    scan_id: str
    worker_id: str
    target_domain: str
    job_nonce: str
    status: str = Field(..., description="completed or failed")
    observations: List[Dict[str, Any]] = Field(default_factory=list)
    error_message: Optional[str] = None
    raw_results_s3_key: Optional[str] = None
    signature: str = Field(..., description="HMAC-SHA256 payload signature")
