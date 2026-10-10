from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    SERVICE = "service"
    CERTIFICATE = "certificate"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    UNKNOWN = "unknown"


class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNASSIGNED = "unassigned"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class ChangeType(str, Enum):
    """Phase 1D deterministic change types."""
    ASSET_ADDED = "asset_added"
    ASSET_REMOVED = "asset_removed"
    ASSET_PROPERTY_CHANGED = "asset_property_changed"
    RELATIONSHIP_ADDED = "relationship_added"
    RELATIONSHIP_REMOVED = "relationship_removed"


class ScanCompleteness(str, Enum):
    """Assessment of how complete a scan's observation coverage was."""
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ComparisonStatus(str, Enum):
    """Outcome status of a scan-over-scan comparison run."""
    COMPLETED = "completed"
    BASELINE_ESTABLISHED = "baseline_established"
    SKIPPED_INCOMPLETE = "skipped_incomplete"
    SKIPPED_OUT_OF_ORDER = "skipped_out_of_order"


class FindingStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class DecisionType(str, Enum):
    ACKNOWLEDGE = "acknowledge"
    ACCEPT_RISK = "accept_risk"
    MARK_FALSE_POSITIVE = "mark_false_positive"
    MARK_EXPECTED = "mark_expected"
    MARK_UNEXPECTED = "mark_unexpected"
    ASSIGN_OWNER = "assign_owner"
    SET_CRITICALITY = "set_criticality"
    SET_ENVIRONMENT = "set_environment"
    REVOKE_DECISION = "revoke_decision"


class ScopeLevel(str, Enum):
    """Scope hierarchy for decisions, memory, and context."""
    ORGANIZATION = "organization"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    ASSET = "asset"
    SERVICE = "service"
    RELATIONSHIP = "relationship"


class DecisionStatus(str, Enum):
    """Status lifecycle of a human security decision."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


class MemoryCategory(str, Enum):
    """10-Level Learning Taxonomy categories."""
    OBSERVATION = "observation"
    CONTEXT = "context"
    EXPECTATION = "expectation"
    DECISION = "decision"
    MEMORY = "memory"
    RULE = "rule"
    BASELINE = "baseline"
    FEEDBACK = "feedback"
    LEARNING = "learning"
    VERIFICATION = "verification"


class ClaimType(str, Enum):
    """Claim classification types for evidence integrity."""
    FACT = "fact"
    INFERENCE = "inference"
    ASSUMPTION = "assumption"
    EXPECTATION = "expectation"
    DECISION = "decision"
    RECOMMENDATION = "recommendation"
    MEMORY = "memory"
    RULE = "rule"
    BASELINE = "baseline"
    LEARNING = "learning"


class DomainStatus(str, Enum):
    PENDING_VERIFICATION = "pending_verification"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class RiskBand(str, Enum):
    """Deterministic contextual risk severity bands."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskModelVersion(str, Enum):
    """Deterministic risk engine model versions."""
    V1 = "v1"
    V2 = "v2"


class FindingLifecycleStatus(str, Enum):
    """Lifecycle status of a security finding."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    UNKNOWN = "unknown"


class VerificationStatus(str, Enum):
    """Outcome of a remediation verification run."""
    RESOLVED = "resolved"
    STILL_PRESENT = "still_present"
    INCOMPLETE = "incomplete"
    UNKNOWN = "unknown"


class VerificationMethod(str, Enum):
    """Method used to perform remediation verification."""
    SCAN_OBSERVATION_COMPARISON = "scan_observation_comparison"


class NotificationTriggerType(str, Enum):
    """Authoritative triggers for change-aware notifications."""
    HIGH_RISK_NEW_ASSET = "high_risk_new_asset"
    CRITICAL_CONTEXTUAL_RISK = "critical_contextual_risk"
    UNEXPECTED_EXPOSED_SERVICE = "unexpected_exposed_service"
    IMPORTANT_ASSET_PROPERTY_CHANGED = "important_asset_property_changed"
    RELATIONSHIP_CHANGED = "relationship_changed"
    RISKY_CONDITION_RESOLVED = "risky_condition_resolved"
    RESOLVED_CONDITION_RETURNED = "resolved_condition_returned"
    VERIFICATION_FAILED = "verification_failed"
    REPEATED_UNRESOLVED_CONDITION = "repeated_unresolved_condition"


class NotificationChannel(str, Enum):
    """Delivery channels for notifications."""
    IN_APP = "in_app"
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"


class NotificationDeliveryStatus(str, Enum):
    """Status of external notification delivery."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    SUPPRESSED = "suppressed"


class DiscoverySourceType(str, Enum):
    """Phase 2: Types of discovery sources."""
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    PASSIVE_DNS = "passive_dns"
    ACTIVE_DNS = "active_dns"
    SCANNER = "scanner"


class DiscoveryRunStatus(str, Enum):
    """Phase 2: Lifecycle states of a discovery run."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ValidationState(str, Enum):
    """Phase 2: Validation states of a discovery candidate."""
    UNVALIDATED = "unvalidated"
    DNS_CONFIRMED = "dns_confirmed"
    NETWORK_CONFIRMED = "network_confirmed"
    TLS_CONFIRMED = "tls_confirmed"
    ASSET_CONFIRMED = "asset_confirmed"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class DiscoveryConfidence(str, Enum):
    """Phase 2: Evidentiary discovery confidence levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNVERIFIED = "UNVERIFIED"


class ExposureState(str, Enum):
    """Phase 2: Temporal exposure state of discovery evidence."""
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"
    UNKNOWN = "UNKNOWN"


class ExposureConditionType(str, Enum):
    """Phase 3: Deterministic taxonomy of exposure conditions."""
    INTERNET_FACING_SERVICE = "internet_facing_service"
    UNEXPECTED_EXPOSED_SERVICE = "unexpected_exposed_service"
    NEWLY_EXPOSED_SERVICE = "newly_exposed_service"
    EXTERNALLY_REACHABLE_PRODUCTION_ASSET = "externally_reachable_production_asset"
    EXTERNALLY_REACHABLE_HIGH_CRITICALITY = "externally_reachable_high_criticality"
    EXPOSED_ADMIN_INTERFACE = "exposed_admin_interface"
    NON_STANDARD_SERVICE_EXPOSURE = "non_standard_service_exposure"
    CERTIFICATE_LINKED_EXPOSURE = "certificate_linked_exposure"
    UNEXPECTED_RELATIONSHIP_EXPOSURE = "unexpected_relationship_exposure"
    EXPOSED_ASSET_HIGH_RISK = "exposed_asset_high_risk"
    EXPOSED_ASSET_OPEN_FINDING = "exposed_asset_open_finding"
    RECURRING_EXPOSURE_CONDITION = "recurring_exposure_condition"


class ExposureConditionStatus(str, Enum):
    """Phase 3: Lifecycle status of a derived exposure condition."""
    ACTIVE = "active"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    STALE = "stale"


class ExposurePriorityBand(str, Enum):
    """Phase 3: Deterministic prioritization bands referencing Phase 1 Context & Risk."""
    CRITICAL_EXPOSURE = "CRITICAL_EXPOSURE"
    HIGH_EXPOSURE = "HIGH_EXPOSURE"
    MEDIUM_EXPOSURE = "MEDIUM_EXPOSURE"
    LOW_EXPOSURE = "LOW_EXPOSURE"


class ExposureCorrelationRunStatus(str, Enum):
    """Phase 3: Execution status of an exposure correlation run."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class IntelligenceSourceType(str, Enum):
    """Phase 4: Types of intelligence sources/feeds."""
    NVD = "nvd"
    CISA_KEV = "cisa_kev"
    FIRST_EPSS = "first_epss"
    VENDOR_ADVISORY = "vendor_advisory"
    CERT_ADVISORY = "cert_advisory"
    INTERNAL_FEED = "internal_feed"


class IntelligenceRunStatus(str, Enum):
    """Phase 4: Lifecycle states of an intelligence ingestion/correlation run."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FreshnessStatus(str, Enum):
    """Phase 4: Intelligence record freshness states."""
    CURRENT = "CURRENT"
    STALE = "STALE"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


class CorrelationState(str, Enum):
    """Phase 4: Explicit states of intelligence correlation."""
    UNMATCHED = "UNMATCHED"
    POTENTIAL_MATCH = "POTENTIAL_MATCH"
    CORRELATED = "CORRELATED"
    VERSION_CONFIRMED = "VERSION_CONFIRMED"
    STALE = "STALE"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"
    INTELLIGENCE_CONFLICT = "INTELLIGENCE_CONFLICT"


class CorrelationConfidenceBand(str, Enum):
    """Phase 4: Deterministic intelligence correlation confidence bands."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNCERTAIN = "UNCERTAIN"


class IntelligenceConflictStatus(str, Enum):
    """Phase 4: Explicit conflict status between intelligence sources."""
    NO_CONFLICT = "NO_CONFLICT"
    CONFIRMED_CONFLICT = "CONFIRMED_CONFLICT"
    RESOLVED_BY_AUTHORITY = "RESOLVED_BY_AUTHORITY"


class AIMessageSender(str, Enum):
    """Phase 5: AI conversation message sender types."""
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


class AIResponseClassification(str, Enum):
    """Phase 5: Mandatory AI response classification."""
    AI_GENERATED_ASSISTANCE = "AI_GENERATED_ASSISTANCE"


class AIIntentType(str, Enum):
    """Phase 5: Structured intent classification for investigation queries."""
    INVESTIGATE_ASSET = "INVESTIGATE_ASSET"
    EXPLAIN_EXPOSURE = "EXPLAIN_EXPOSURE"
    EXPLAIN_RISK = "EXPLAIN_RISK"
    EXPLAIN_INTELLIGENCE = "EXPLAIN_INTELLIGENCE"
    EXPLAIN_FINDING = "EXPLAIN_FINDING"
    EXPLAIN_CHANGE = "EXPLAIN_CHANGE"
    SUMMARIZE_TIMELINE = "SUMMARIZE_TIMELINE"
    GENERAL_SECURITY_QUERY = "GENERAL_SECURITY_QUERY"





