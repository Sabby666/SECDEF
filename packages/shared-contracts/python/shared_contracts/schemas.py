from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from shared_contracts.enums import (
    DecisionType, ScopeLevel, DecisionStatus, MemoryCategory, ClaimType,
    RiskBand, RiskModelVersion
)


class HealthResponse(BaseModel):
    status: str = Field(..., json_schema_extra={"example": "healthy"})
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = Field(..., json_schema_extra={"example": "1.0.0"})
    checks: Dict[str, Any] = Field(default_factory=dict)


class SystemStatusResponse(BaseModel):
    app_name: str = "SECDEF"
    environment: str = "development"
    database_connected: bool = False
    redis_connected: bool = False


class APIErrorDetail(BaseModel):
    error: str
    code: str
    details: Optional[Dict[str, Any]] = None


class DomainCreateRequest(BaseModel):
    domain_name: str = Field(..., json_schema_extra={"example": "example.com"})


class DomainResponse(BaseModel):
    id: str
    org_id: str
    domain_name: str
    status: str
    verification_token: str
    verified_at: Optional[datetime] = None
    last_verified_at: Optional[datetime] = None
    created_at: datetime


class ScanResponse(BaseModel):
    id: str
    org_id: str
    domain_id: str
    status: str
    job_nonce: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    scan_metadata: Optional[Dict[str, Any]] = None
    created_at: datetime


class ObservationResponse(BaseModel):
    id: str
    org_id: str
    scan_id: str
    asset_id: Optional[str] = None
    observation_type: str
    target: str
    raw_data: Dict[str, Any]
    observed_at: datetime


class AssetResponse(BaseModel):
    id: str
    org_id: str
    domain_id: Optional[str] = None
    asset_type: str
    identifier: str
    environment: str = "unknown"
    criticality: str = "medium"
    owner_id: Optional[str] = None
    owner_team: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    status: str = "active"


class AssetRelationshipResponse(BaseModel):
    id: str
    org_id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    confidence: str = "HIGH"
    evidence: Optional[Dict[str, Any]] = None
    first_seen_at: datetime
    last_seen_at: datetime
    status: str = "active"


class AssetListResponse(BaseModel):
    items: List[AssetResponse]
    total: int


class AssetRelationshipListResponse(BaseModel):
    items: List[AssetRelationshipResponse]
    total: int


# --- Phase 1D: Change Detection Response DTOs ---

class ComparisonRunResponse(BaseModel):
    """Represents a single scan-over-scan comparison execution."""
    id: str
    org_id: str
    domain_id: str
    current_scan_id: str
    previous_scan_id: Optional[str] = None
    status: str
    current_scan_completeness: str
    completeness_details: Optional[Dict[str, Any]] = None
    changes_detected: int = 0
    comparison_metadata: Optional[Dict[str, Any]] = None
    created_at: datetime


class ComparisonRunListResponse(BaseModel):
    items: List[ComparisonRunResponse]
    total: int


class ChangeResponse(BaseModel):
    """Represents a single detected change from a comparison run."""
    id: str
    org_id: str
    comparison_run_id: str
    asset_id: Optional[str] = None
    change_type: str
    entity_type: str
    entity_identifier: str
    previous_state: Optional[Dict[str, Any]] = None
    current_state: Optional[Dict[str, Any]] = None
    previous_scan_id: Optional[str] = None
    current_scan_id: str
    evidence: Optional[Dict[str, Any]] = None
    detected_at: datetime


class ChangeListResponse(BaseModel):
    items: List[ChangeResponse]
    total: int


# --- Phase 1E: Organizational Context & Controlled Memory DTOs ---

class AssetContextUpdateRequest(BaseModel):
    """Request DTO for updating organizational metadata on an asset."""
    owner_id: Optional[str] = None
    owner_team: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    business_purpose: Optional[str] = None
    expected_exposure: Optional[str] = None


class AssetContextResponse(BaseModel):
    """Response DTO for asset organizational context."""
    id: str
    org_id: str
    asset_id: str
    owner_id: Optional[str] = None
    owner_team: Optional[str] = None
    environment: str
    criticality: str
    business_purpose: Optional[str] = None
    expected_exposure: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class DecisionCreateRequest(BaseModel):
    """Request DTO for creating an auditable human security decision."""
    decision_type: DecisionType
    scope_level: ScopeLevel
    subject_identifier: str
    subject_type: Optional[str] = "asset"
    new_state: Dict[str, Any]
    reason: str
    evidence: Optional[Dict[str, Any]] = None
    valid_until: Optional[datetime] = None
    review_at: Optional[datetime] = None


class DecisionRevokeRequest(BaseModel):
    """Request DTO for revoking an existing decision."""
    reason: str


class DecisionResponse(BaseModel):
    """Response DTO for an immutable human decision event."""
    id: str
    org_id: str
    actor_id: str
    subject_type: str
    subject_identifier: str
    decision_type: DecisionType
    scope_level: ScopeLevel
    previous_state: Optional[Dict[str, Any]] = None
    new_state: Dict[str, Any]
    reason: str
    evidence: Optional[Dict[str, Any]] = None
    valid_from: datetime
    valid_until: Optional[datetime] = None
    review_at: Optional[datetime] = None
    status: DecisionStatus
    created_at: datetime


class DecisionListResponse(BaseModel):
    items: List[DecisionResponse]
    total: int


class MemoryResponse(BaseModel):
    """Response DTO for a persistent organizational memory record."""
    id: str
    org_id: str
    decision_id: Optional[str] = None
    category: MemoryCategory
    scope_level: ScopeLevel
    scope_identifier: str
    memory_key: str
    memory_value: Dict[str, Any]
    confidence: float
    source: str
    evidence: Optional[Dict[str, Any]] = None
    valid_from: datetime
    valid_until: Optional[datetime] = None
    status: str
    created_at: datetime
    updated_at: datetime


class MemoryListResponse(BaseModel):
    items: List[MemoryResponse]
    total: int


class ContextResolveRequest(BaseModel):
    """Request DTO for resolving context and expected state for a target."""
    target_type: str
    target_identifier: str
    domain_name: Optional[str] = None


class ProvenanceExplanation(BaseModel):
    """Explainability provenance trace for resolved context."""
    claim_type: ClaimType
    source_type: str
    source_id: Optional[str] = None
    scope_level: ScopeLevel
    scope_identifier: str
    actor_id: Optional[str] = None
    reason: str
    confidence: float = 1.0


class ContextResolutionResponse(BaseModel):
    """Response DTO for resolved organizational context and expected state."""
    target_identifier: str
    target_type: str
    expected_state: str
    environment: str
    criticality: str
    owner_id: Optional[str] = None
    owner_team: Optional[str] = None
    conflict_detected: bool = False
    resolution_status: str
    matched_memories: List[MemoryResponse] = []
    provenance: List[ProvenanceExplanation] = []


class RiskFactorDetail(BaseModel):
    """Detailed breakdown of an individual risk factor contribution."""
    factor_name: str
    factor_value: Any
    contribution: float
    source_type: str
    source_id: Optional[str] = None
    evidence_ref: Optional[Dict[str, Any]] = None
    uncertainty_flag: Optional[str] = None


class RiskAssessmentResponse(BaseModel):
    """Response DTO for deterministic, traceable contextual risk assessment."""
    id: str
    org_id: str
    change_id: Optional[str] = None
    asset_id: Optional[str] = None
    risk_model_version: RiskModelVersion
    risk_score: float
    risk_band: RiskBand
    confidence: float
    factor_breakdown: List[RiskFactorDetail]
    context_snapshot: Dict[str, Any]
    uncertainty_flags: List[str]
    explanation: str
    created_at: datetime
    updated_at: datetime


class RiskAssessmentListResponse(BaseModel):
    items: List[RiskAssessmentResponse]
    total: int


class RiskRecalculateRequest(BaseModel):
    """Request DTO to trigger risk recalculation for a change or asset."""
    change_id: Optional[str] = Field(None, min_length=1, max_length=128)
    asset_id: Optional[str] = Field(None, min_length=1, max_length=128)
    risk_model_version: Optional[str] = Field("v1", description="Model version to evaluate (e.g. v1, v2)")


# Phase 1G: Remediation Verification & Notifications Schemas

class FindingResponse(BaseModel):
    id: str
    org_id: str
    change_id: str
    asset_id: Optional[str] = None
    risk_assessment_id: Optional[str] = None
    status: str
    title: str
    description: str
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    reopened_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int


class FindingStatusUpdateRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)


class VerificationResultResponse(BaseModel):
    id: str
    org_id: str
    finding_id: str
    comparison_run_id: str
    current_scan_id: str
    status: str
    method: str
    previous_observed_state: Optional[Dict[str, Any]] = None
    current_observed_state: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
    verified_at: datetime


class NotificationDestinationCreateRequest(BaseModel):
    channel: str = Field(..., description="webhook, email, in_app, slack")
    name: str = Field(..., min_length=1, max_length=255)
    config: Dict[str, Any] = Field(..., description="Destination configuration e.g. url, signing_secret, recipient_emails")


class NotificationDestinationResponse(BaseModel):
    id: str
    org_id: str
    channel: str
    name: str
    config: Dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime


class NotificationPolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    min_risk_band: str = Field("HIGH", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    trigger_types: List[str] = Field(default_factory=list)
    destination_ids: List[str] = Field(default_factory=list)
    cooldown_minutes: int = Field(60, ge=0, le=10080)


class NotificationPolicyResponse(BaseModel):
    id: str
    org_id: str
    policy_version: str
    name: str
    min_risk_band: str
    trigger_types: List[str]
    destination_ids: List[str]
    cooldown_minutes: int
    is_active: bool
    created_at: datetime
    updated_at: datetime


class NotificationResponse(BaseModel):
    id: str
    org_id: str
    finding_id: Optional[str] = None
    risk_assessment_id: Optional[str] = None
    change_id: Optional[str] = None
    verification_result_id: Optional[str] = None
    trigger_type: str
    title: str
    summary: str
    content_payload: Dict[str, Any]
    event_identity: str
    created_at: datetime


class NotificationListResponse(BaseModel):
    items: List[NotificationResponse]
    total: int


class WebhookTestRequest(BaseModel):
    url: str = Field(..., description="Webhook URL to test")
    signing_secret: Optional[str] = Field(None, description="Optional HMAC signing secret")



