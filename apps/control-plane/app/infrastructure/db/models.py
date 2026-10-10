import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text, JSON, Float, func, Index
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from shared_contracts.enums import DomainStatus, UserRole
from app.infrastructure.db.base import Base

# Note: We use String for UUID instead of postgresql.UUID if we are testing with SQLite,
# but for production PostgreSQL compatibility, we use a generic UUID type approach or String for fallback.
# Alembic handles native UUIDs on Postgres. Here we use String(36) to be SQLite compatible for local dev.

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    memberships: Mapped[List["Membership"]] = relationship("Membership", back_populates="organization")
    domains: Mapped[List["Domain"]] = relationship("Domain", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending_verification")
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_secret_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    memberships: Mapped[List["Membership"]] = relationship("Membership", back_populates="user")


class Membership(Base):
    __tablename__ = "memberships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="memberships")
    user: Mapped["User"] = relationship("User", back_populates="memberships")

    __table_args__ = (
        Index("uix_org_user", "org_id", "user_id", unique=True),
    )


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    domain_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default=DomainStatus.PENDING_VERIFICATION)
    verification_token: Mapped[str] = mapped_column(String(128), nullable=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="domains")

    __table_args__ = (
        Index("uix_org_domain", "org_id", "domain_name", unique=True),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False) # Use String for SQLite compat instead of INET
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # SQLite does not support JSONB natively, Alembic and SQLAlchemy can abstract it or we can use JSON type.
    # For now, we will use Text or SQLAlchemy JSON. Let's use sqlalchemy JSON.
    from sqlalchemy import JSON
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        Index("idx_audit_org_created", "org_id", "created_at"),
        Index("idx_audit_actor_created", "actor_id", "created_at"),
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    domain_id: Mapped[str] = mapped_column(String(36), ForeignKey("domains.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")
    job_nonce: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scan_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    domain: Mapped["Domain"] = relationship("Domain")
    observations: Mapped[List["Observation"]] = relationship("Observation", back_populates="scan")

    __table_args__ = (
        Index("idx_scans_org_status", "org_id", "status"),
        Index("idx_scans_domain_created", "domain_id", "created_at"),
    )


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    domain_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("domains.id"), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)  # subdomain, ip_address, service, certificate
    identifier: Mapped[str] = mapped_column(Text, nullable=False)
    environment: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    criticality: Mapped[str] = mapped_column(String(50), nullable=False, default="medium")
    owner_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    owner_team: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    expected_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")

    organization: Mapped["Organization"] = relationship("Organization")
    domain: Mapped[Optional["Domain"]] = relationship("Domain")
    observations: Mapped[List["Observation"]] = relationship("Observation", back_populates="resolved_asset")

    __table_args__ = (
        Index("uix_assets_org_type_ident", "org_id", "asset_type", "identifier", unique=True),
        Index("idx_assets_org_env", "org_id", "environment"),
        Index("idx_assets_org_owner", "org_id", "owner_id"),
        Index("idx_assets_org_type", "org_id", "asset_type"),
    )


class AssetRelationship(Base):
    __tablename__ = "asset_relationships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    source_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    target_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)  # resolves_to, runs_service, presents_cert, cname_to, associated_with
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="HIGH")  # HIGH, MEDIUM, LOW
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")

    organization: Mapped["Organization"] = relationship("Organization")
    source_asset: Mapped["Asset"] = relationship("Asset", foreign_keys=[source_asset_id])
    target_asset: Mapped["Asset"] = relationship("Asset", foreign_keys=[target_asset_id])

    __table_args__ = (
        Index("uix_rel_org_src_tgt_type", "org_id", "source_asset_id", "target_asset_id", "relationship_type", unique=True),
        Index("idx_rel_source", "source_asset_id"),
        Index("idx_rel_target", "target_asset_id"),
        Index("idx_rel_org_status", "org_id", "status"),
    )


class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    observation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="observations")
    resolved_asset: Mapped[Optional["Asset"]] = relationship("Asset", back_populates="observations")

    __table_args__ = (
        Index("idx_obs_org_target_time", "org_id", "target", "observed_at"),
        Index("idx_obs_scan_type", "scan_id", "observation_type"),
        Index("idx_obs_asset_id", "asset_id"),
    )


class ComparisonRun(Base):
    """Phase 1D: Represents a single scan-over-scan comparison execution.

    Each ComparisonRun is scoped to (org_id, domain_id, current_scan_id) and is
    idempotent — processing the same scan twice returns the existing record.
    """
    __tablename__ = "comparison_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    domain_id: Mapped[str] = mapped_column(String(36), ForeignKey("domains.id"), nullable=False)
    current_scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    previous_scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # completed, baseline_established, skipped_incomplete, skipped_out_of_order
    current_scan_completeness: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    completeness_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    changes_detected: Mapped[int] = mapped_column(nullable=False, default=0)
    comparison_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    domain: Mapped["Domain"] = relationship("Domain")
    current_scan: Mapped["Scan"] = relationship("Scan", foreign_keys=[current_scan_id])
    previous_scan: Mapped[Optional["Scan"]] = relationship("Scan", foreign_keys=[previous_scan_id])

    __table_args__ = (
        Index("uix_comparison_org_domain_scan", "org_id", "domain_id", "current_scan_id", unique=True),
        Index("idx_comparison_org_created", "org_id", "created_at"),
        Index("idx_comparison_domain", "domain_id"),
    )


class Change(Base):
    """Phase 1D: An individual detected change from a comparison run.

    Each change is deterministically identified by the combination of
    (org_id, comparison_run_id, change_type, entity_type, entity_identifier),
    preventing duplicate change records for the same comparison.
    """
    __tablename__ = "changes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    comparison_run_id: Mapped[str] = mapped_column(String(36), ForeignKey("comparison_runs.id"), nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    change_type: Mapped[str] = mapped_column(String(50), nullable=False)  # asset_added, asset_removed, asset_property_changed, relationship_added, relationship_removed
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)  # asset, relationship
    entity_identifier: Mapped[str] = mapped_column(Text, nullable=False)  # Canonical identifier of the changed entity
    previous_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    current_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    previous_scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    current_scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    comparison_run: Mapped["ComparisonRun"] = relationship("ComparisonRun")
    asset: Mapped[Optional["Asset"]] = relationship("Asset")

    __table_args__ = (
        Index("uix_change_identity", "org_id", "comparison_run_id", "change_type", "entity_type", "entity_identifier", unique=True),
        Index("idx_changes_org_detected", "org_id", "detected_at"),
        Index("idx_changes_org_type", "org_id", "change_type"),
        Index("idx_changes_comparison", "comparison_run_id"),
    )


class AssetContext(Base):
    """Phase 1E: Organizational context and metadata attached to an asset."""
    __tablename__ = "asset_contexts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    owner_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    owner_team: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    environment: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    criticality: Mapped[str] = mapped_column(String(50), nullable=False, default="medium")
    business_purpose: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expected_exposure: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    asset: Mapped["Asset"] = relationship("Asset")
    owner: Mapped[Optional["User"]] = relationship("User")

    __table_args__ = (
        Index("uix_asset_context_org_asset", "org_id", "asset_id", unique=True),
        Index("idx_asset_context_org_env", "org_id", "environment"),
        Index("idx_asset_context_org_criticality", "org_id", "criticality"),
    )


class OrganizationalDecision(Base):
    """Phase 1E: An immutable human security decision event."""
    __tablename__ = "organizational_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(50), nullable=False)  # asset, service, domain, relationship
    subject_identifier: Mapped[str] = mapped_column(Text, nullable=False)
    decision_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scope_level: Mapped[str] = mapped_column(String(50), nullable=False)
    previous_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    new_state: Mapped[dict] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    review_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    actor: Mapped["User"] = relationship("User")

    __table_args__ = (
        Index("idx_decision_org_subject", "org_id", "subject_identifier"),
        Index("idx_decision_org_status", "org_id", "status"),
        Index("idx_decision_org_created", "org_id", "created_at"),
    )


class OrganizationalMemory(Base):
    """Phase 1E: Derived persistent organizational memory record."""
    __tablename__ = "organizational_memories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    decision_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("organizational_decisions.id"), nullable=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)  # expectation, context, decision, memory, rule, baseline, etc.
    scope_level: Mapped[str] = mapped_column(String(50), nullable=False)
    scope_identifier: Mapped[str] = mapped_column(Text, nullable=False)
    memory_key: Mapped[str] = mapped_column(String(100), nullable=False)
    memory_value: Mapped[dict] = mapped_column(JSON, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    decision: Mapped[Optional["OrganizationalDecision"]] = relationship("OrganizationalDecision")

    __table_args__ = (
        Index("idx_memory_org_scope", "org_id", "scope_level", "scope_identifier"),
        Index("idx_memory_org_key", "org_id", "memory_key"),
        Index("idx_memory_org_status", "org_id", "status"),
    )


class DecisionTransitionHistory(Base):
    """Phase 1E: Append-only transition log for decision lifecycle state changes."""
    __tablename__ = "decision_transition_histories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    decision_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizational_decisions.id"), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    from_status: Mapped[str] = mapped_column(String(50), nullable=False)
    to_status: Mapped[str] = mapped_column(String(50), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    decision: Mapped["OrganizationalDecision"] = relationship("OrganizationalDecision")
    actor: Mapped["User"] = relationship("User")

    __table_args__ = (
        Index("idx_transition_org_decision", "org_id", "decision_id"),
        Index("idx_transition_created", "created_at"),
    )


class RiskAssessment(Base):
    """Phase 1F: Deterministic, traceable contextual risk assessment record."""
    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    change_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("changes.id"), nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    risk_model_version: Mapped[str] = mapped_column(String(20), nullable=False, default="v1")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_band: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    factor_breakdown: Mapped[list] = mapped_column(JSON, nullable=False)
    context_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)
    uncertainty_flags: Mapped[list] = mapped_column(JSON, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    change: Mapped[Optional["Change"]] = relationship("Change")
    asset: Mapped[Optional["Asset"]] = relationship("Asset")

    __table_args__ = (
        Index("uix_risk_org_change_version", "org_id", "change_id", "risk_model_version", unique=True),
        Index("idx_risk_org_band", "org_id", "risk_band"),
        Index("idx_risk_org_asset", "org_id", "asset_id"),
        Index("idx_risk_org_created", "org_id", "created_at"),
    )


class Finding(Base):
    """Phase 1G: Security finding derived from Change + RiskAssessment."""
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    change_id: Mapped[str] = mapped_column(String(36), ForeignKey("changes.id"), nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    risk_assessment_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("risk_assessments.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open") # open, acknowledged, in_progress, resolved, reopened, unknown
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reopened_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    change: Mapped["Change"] = relationship("Change")
    asset: Mapped[Optional["Asset"]] = relationship("Asset")
    risk_assessment: Mapped[Optional["RiskAssessment"]] = relationship("RiskAssessment")
    acknowledged_user: Mapped[Optional["User"]] = relationship("User")

    __table_args__ = (
        Index("uix_finding_org_change", "org_id", "change_id", unique=True),
        Index("idx_finding_org_status", "org_id", "status"),
        Index("idx_finding_org_asset", "org_id", "asset_id"),
        Index("idx_finding_created", "created_at"),
    )


class FindingStateTransition(Base):
    """Phase 1G: Audit log for finding lifecycle state transitions."""
    __tablename__ = "finding_state_transitions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    from_status: Mapped[str] = mapped_column(String(50), nullable=False)
    to_status: Mapped[str] = mapped_column(String(50), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_snapshot: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    finding: Mapped["Finding"] = relationship("Finding")
    actor: Mapped[Optional["User"]] = relationship("User")

    __table_args__ = (
        Index("idx_finding_trans_org_finding", "org_id", "finding_id"),
        Index("idx_finding_trans_created", "created_at"),
    )


class VerificationResult(Base):
    """Phase 1G: Evidence-backed remediation verification result."""
    __tablename__ = "verification_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    comparison_run_id: Mapped[str] = mapped_column(String(36), ForeignKey("comparison_runs.id"), nullable=False)
    current_scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False) # resolved, still_present, incomplete, unknown
    method: Mapped[str] = mapped_column(String(50), nullable=False, default="scan_observation_comparison")
    previous_observed_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    current_observed_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    finding: Mapped["Finding"] = relationship("Finding")
    comparison_run: Mapped["ComparisonRun"] = relationship("ComparisonRun")
    current_scan: Mapped["Scan"] = relationship("Scan")

    __table_args__ = (
        Index("uix_verification_org_finding_comp", "org_id", "finding_id", "comparison_run_id", unique=True),
        Index("idx_verification_org_status", "org_id", "status"),
        Index("idx_verification_verified_at", "verified_at"),
    )


class NotificationDestination(Base):
    """Phase 1G: Configured destination for notifications (Webhook, Email, Slack, In-App)."""
    __tablename__ = "notification_destinations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    channel: Mapped[str] = mapped_column(String(50), nullable=False) # webhook, email, in_app, slack
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    config: Mapped[dict] = mapped_column(JSON, nullable=False) # url, signing_secret, recipient_emails
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")

    __table_args__ = (
        Index("idx_dest_org_channel", "org_id", "channel"),
        Index("idx_dest_org_active", "org_id", "is_active"),
    )


class NotificationPolicy(Base):
    """Phase 1G: Notification policy rules and thresholds."""
    __tablename__ = "notification_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(20), nullable=False, default="v1")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    min_risk_band: Mapped[str] = mapped_column(String(20), nullable=False, default="HIGH")
    trigger_types: Mapped[list] = mapped_column(JSON, nullable=False)
    destination_ids: Mapped[list] = mapped_column(JSON, nullable=False)
    cooldown_minutes: Mapped[int] = mapped_column(nullable=False, default=60)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")

    __table_args__ = (
        Index("idx_policy_org_active", "org_id", "is_active"),
        Index("idx_policy_org_version", "org_id", "policy_version"),
    )


class Notification(Base):
    """Phase 1G: Generated notification event record with deterministic identity."""
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("findings.id"), nullable=True)
    risk_assessment_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("risk_assessments.id"), nullable=True)
    change_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("changes.id"), nullable=True)
    verification_result_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("verification_results.id"), nullable=True)
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    content_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    event_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    finding: Mapped[Optional["Finding"]] = relationship("Finding")
    risk_assessment: Mapped[Optional["RiskAssessment"]] = relationship("RiskAssessment")
    change: Mapped[Optional["Change"]] = relationship("Change")
    verification_result: Mapped[Optional["VerificationResult"]] = relationship("VerificationResult")

    __table_args__ = (
        Index("uix_notification_event_identity", "org_id", "event_identity", unique=True),
        Index("idx_notification_org_created", "org_id", "created_at"),
        Index("idx_notification_trigger", "org_id", "trigger_type"),
    )


class NotificationDelivery(Base):
    """Phase 1G: Channel delivery attempt audit log."""
    __tablename__ = "notification_deliveries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    notification_id: Mapped[str] = mapped_column(String(36), ForeignKey("notifications.id"), nullable=False)
    destination_id: Mapped[str] = mapped_column(String(36), ForeignKey("notification_destinations.id"), nullable=False)
    channel: Mapped[str] = mapped_column(String(50), nullable=False)
    attempt_number: Mapped[int] = mapped_column(nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending") # pending, sent, failed, rate_limited, suppressed
    response_code: Mapped[Optional[int]] = mapped_column(nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    notification: Mapped["Notification"] = relationship("Notification")
    destination: Mapped["NotificationDestination"] = relationship("NotificationDestination")

    __table_args__ = (
        Index("idx_delivery_org_notification", "org_id", "notification_id"),
        Index("idx_delivery_org_status", "org_id", "status"),
        Index("idx_delivery_created", "created_at"),
    )


class DiscoverySource(Base):
    """Phase 2: Registered discovery source (e.g., CT, Passive DNS, Active DNS)."""
    __tablename__ = "discovery_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # certificate_transparency, passive_dns, active_dns, scanner
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    runs: Mapped[List["DiscoveryRun"]] = relationship("DiscoveryRun", back_populates="source")

    __table_args__ = (
        Index("idx_disc_source_org_type", "org_id", "source_type"),
        Index("idx_disc_source_active", "org_id", "is_active"),
    )


class DiscoveryRun(Base):
    """Phase 2: Operational record of a discovery execution."""
    __tablename__ = "discovery_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    source_id: Mapped[str] = mapped_column(String(36), ForeignKey("discovery_sources.id"), nullable=False)
    domain_id: Mapped[str] = mapped_column(String(36), ForeignKey("domains.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")  # queued, running, completed, partial, failed, cancelled
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    candidates_discovered: Mapped[int] = mapped_column(nullable=False, default=0)
    candidates_validated: Mapped[int] = mapped_column(nullable=False, default=0)
    candidates_rejected: Mapped[int] = mapped_column(nullable=False, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    run_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    source: Mapped["DiscoverySource"] = relationship("DiscoverySource", back_populates="runs")
    domain: Mapped["Domain"] = relationship("Domain")
    candidates: Mapped[List["DiscoveryCandidate"]] = relationship("DiscoveryCandidate", back_populates="discovery_run")

    __table_args__ = (
        Index("idx_disc_run_org_source", "org_id", "source_id"),
        Index("idx_disc_run_org_status", "org_id", "status"),
        Index("idx_disc_run_created", "created_at"),
    )


class DiscoveryCandidate(Base):
    """Phase 2: Unvalidated discovery candidate record prior to asset resolution."""
    __tablename__ = "discovery_candidates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    discovery_run_id: Mapped[str] = mapped_column(String(36), ForeignKey("discovery_runs.id"), nullable=False)
    canonical_identifier: Mapped[str] = mapped_column(Text, nullable=False)
    candidate_type: Mapped[str] = mapped_column(String(50), nullable=False)  # subdomain, ip_address, service, certificate
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    validation_state: Mapped[str] = mapped_column(String(50), nullable=False, default="unvalidated")
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="UNVERIFIED")
    exposure_state: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    promoted_asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    candidate_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    organization: Mapped["Organization"] = relationship("Organization")
    discovery_run: Mapped["DiscoveryRun"] = relationship("DiscoveryRun", back_populates="candidates")
    promoted_asset: Mapped[Optional["Asset"]] = relationship("Asset")
    evidence_items: Mapped[List["DiscoveryEvidence"]] = relationship("DiscoveryEvidence", back_populates="candidate")

    __table_args__ = (
        Index("uix_candidate_org_ident", "org_id", "candidate_type", "canonical_identifier", unique=True),
        Index("idx_candidate_org_state", "org_id", "validation_state"),
        Index("idx_candidate_org_type", "org_id", "candidate_type"),
    )


class DiscoveryEvidence(Base):
    """Phase 2: Individual evidentiary observation backing a candidate."""
    __tablename__ = "discovery_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    candidate_id: Mapped[str] = mapped_column(String(36), ForeignKey("discovery_candidates.id"), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    candidate: Mapped["DiscoveryCandidate"] = relationship("DiscoveryCandidate", back_populates="evidence_items")

    __table_args__ = (
        Index("idx_evidence_org_candidate", "org_id", "candidate_id"),
        Index("idx_evidence_observed", "observed_at"),
    )


class ExposureCorrelationRun(Base):
    """Phase 3: Operational record of an exposure correlation execution."""
    __tablename__ = "exposure_correlation_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(20), nullable=False, default="v1")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")  # queued, running, completed, failed
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    conditions_detected: Mapped[int] = mapped_column(nullable=False, default=0)
    paths_detected: Mapped[int] = mapped_column(nullable=False, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    run_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")

    __table_args__ = (
        Index("idx_exp_run_org_status", "org_id", "status"),
        Index("idx_exp_run_created", "created_at"),
    )


class ExposureCondition(Base):
    """Phase 3: Deterministic derived exposure condition record."""
    __tablename__ = "exposure_conditions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    condition_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")  # active, resolved, reopened, stale
    priority_band: Mapped[str] = mapped_column(String(50), nullable=False, default="MEDIUM_EXPOSURE")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    primary_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    risk_assessment_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("risk_assessments.id"), nullable=True)
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("findings.id"), nullable=True)
    change_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("changes.id"), nullable=True)
    rule_version: Mapped[str] = mapped_column(String(20), nullable=False, default="v1")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reopened_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")
    primary_asset: Mapped["Asset"] = relationship("Asset", foreign_keys=[primary_asset_id])
    risk_assessment: Mapped[Optional["RiskAssessment"]] = relationship("RiskAssessment")
    finding: Mapped[Optional["Finding"]] = relationship("Finding")
    change: Mapped[Optional["Change"]] = relationship("Change")
    evidence_links: Mapped[List["ExposureConditionEvidence"]] = relationship("ExposureConditionEvidence", back_populates="condition")
    paths: Mapped[List["ExposurePath"]] = relationship("ExposurePath", back_populates="condition")

    __table_args__ = (
        Index("uix_exp_cond_org_type_asset", "org_id", "condition_type", "primary_asset_id", unique=True),
        Index("idx_exp_cond_org_status", "org_id", "status"),
        Index("idx_exp_cond_org_priority", "org_id", "priority_band"),
        Index("idx_exp_cond_org_asset", "org_id", "primary_asset_id"),
    )


class ExposureConditionEvidence(Base):
    """Phase 3: Append-only evidence link mapping authoritative inputs to an ExposureCondition."""
    __tablename__ = "exposure_condition_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    condition_id: Mapped[str] = mapped_column(String(36), ForeignKey("exposure_conditions.id"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)  # asset, relationship, observation, discovery_evidence, change, risk_assessment, finding, context, decision
    evidence_ref_id: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    condition: Mapped["ExposureCondition"] = relationship("ExposureCondition", back_populates="evidence_links")

    __table_args__ = (
        Index("idx_exp_ev_org_cond", "org_id", "condition_id"),
        Index("idx_exp_ev_ref", "evidence_type", "evidence_ref_id"),
    )


class ExposurePath(Base):
    """Phase 3: Graph-derived exposure path chain."""
    __tablename__ = "exposure_paths"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    condition_id: Mapped[str] = mapped_column(String(36), ForeignKey("exposure_conditions.id"), nullable=False)
    start_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    end_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    path_length: Mapped[int] = mapped_column(nullable=False, default=1)
    nodes_snapshot: Mapped[list] = mapped_column(JSON, nullable=False)
    edges_snapshot: Mapped[list] = mapped_column(JSON, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    condition: Mapped["ExposureCondition"] = relationship("ExposureCondition", back_populates="paths")
    start_asset: Mapped["Asset"] = relationship("Asset", foreign_keys=[start_asset_id])
    end_asset: Mapped["Asset"] = relationship("Asset", foreign_keys=[end_asset_id])

    __table_args__ = (
        Index("idx_exp_path_org_cond", "org_id", "condition_id"),
        Index("idx_exp_path_start_end", "start_asset_id", "end_asset_id"),
    )


class IntelligenceSource(Base):
    """Phase 4: Configured external intelligence feed source."""
    __tablename__ = "intelligence_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_retrieved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    runs: Mapped[List["IntelligenceRun"]] = relationship("IntelligenceRun", back_populates="source")

    __table_args__ = (
        Index("uix_intel_source_org_name", "org_id", "source_name", unique=True),
        Index("idx_intel_source_org_type", "org_id", "source_type"),
    )


class IntelligenceRun(Base):
    """Phase 4: Ingestion & processing execution log for an intelligence source."""
    __tablename__ = "intelligence_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    source_id: Mapped[str] = mapped_column(String(36), ForeignKey("intelligence_sources.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    records_ingested: Mapped[int] = mapped_column(nullable=False, default=0)
    records_updated: Mapped[int] = mapped_column(nullable=False, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    run_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    source: Mapped["IntelligenceSource"] = relationship("IntelligenceSource", back_populates="runs")

    __table_args__ = (
        Index("idx_intel_run_org_status", "org_id", "status"),
        Index("idx_intel_run_created", "created_at"),
    )


class IntelligenceRecord(Base):
    """Phase 4: Canonical normalized vulnerability/threat intelligence record."""
    __tablename__ = "intelligence_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    source_id: Mapped[str] = mapped_column(String(36), ForeignKey("intelligence_sources.id"), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., CVE-2021-41773
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="medium")
    cvss_v3_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cwe_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    affected_product: Mapped[str] = mapped_column(String(255), nullable=False)
    affected_vendor: Mapped[str] = mapped_column(String(255), nullable=False)
    affected_cpe: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    affected_version_range: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_cisa_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exploit_availability: Mapped[str] = mapped_column(String(50), nullable=False, default="none")
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    freshness_status: Mapped[str] = mapped_column(String(50), nullable=False, default="CURRENT")
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")
    source: Mapped["IntelligenceSource"] = relationship("IntelligenceSource")
    correlations: Mapped[List["IntelligenceCorrelation"]] = relationship("IntelligenceCorrelation", back_populates="intelligence_record")

    __table_args__ = (
        Index("uix_intel_rec_org_source_ext", "org_id", "source_id", "external_id", unique=True),
        Index("idx_intel_rec_org_prod", "org_id", "affected_vendor", "affected_product"),
        Index("idx_intel_rec_org_ext", "org_id", "external_id"),
    )


class IntelligenceCorrelation(Base):
    """Phase 4: Derived correlation between observed asset/service and intelligence record."""
    __tablename__ = "intelligence_correlations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    intelligence_record_id: Mapped[str] = mapped_column(String(36), ForeignKey("intelligence_records.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    exposure_condition_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("exposure_conditions.id"), nullable=True)
    correlation_state: Mapped[str] = mapped_column(String(50), nullable=False, default="POTENTIAL_MATCH")
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    confidence_band: Mapped[str] = mapped_column(String(50), nullable=False, default="MEDIUM")
    confidence_breakdown: Mapped[dict] = mapped_column(JSON, nullable=False)
    match_reason: Mapped[str] = mapped_column(Text, nullable=False)
    rule_version: Mapped[str] = mapped_column(String(20), nullable=False, default="v1")
    observed_technology: Mapped[str] = mapped_column(String(255), nullable=False)
    observed_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    conflict_status: Mapped[str] = mapped_column(String(50), nullable=False, default="NO_CONFLICT")
    conflict_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    first_correlated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_correlated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")
    intelligence_record: Mapped["IntelligenceRecord"] = relationship("IntelligenceRecord", back_populates="correlations")
    asset: Mapped["Asset"] = relationship("Asset")
    exposure_condition: Mapped[Optional["ExposureCondition"]] = relationship("ExposureCondition")
    evidence_items: Mapped[List["IntelligenceEvidence"]] = relationship("IntelligenceEvidence", back_populates="correlation")

    __table_args__ = (
        Index("uix_intel_corr_org_rec_asset", "org_id", "intelligence_record_id", "asset_id", unique=True),
        Index("idx_intel_corr_org_state", "org_id", "correlation_state"),
        Index("idx_intel_corr_org_asset", "org_id", "asset_id"),
    )


class IntelligenceEvidence(Base):
    """Phase 4: Append-only evidence item backing an intelligence correlation."""
    __tablename__ = "intelligence_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(36), ForeignKey("intelligence_correlations.id"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    evidence_ref_id: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    correlation: Mapped["IntelligenceCorrelation"] = relationship("IntelligenceCorrelation", back_populates="evidence_items")

    __table_args__ = (
        Index("idx_intel_ev_org_corr", "org_id", "correlation_id"),
        Index("idx_intel_ev_ref", "evidence_type", "evidence_ref_id"),
    )


class AIConversation(Base):
    """Phase 5: Tenant-isolated AI assistance conversation thread."""
    __tablename__ = "ai_conversations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="Security Investigation")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    user: Mapped["User"] = relationship("User")
    messages: Mapped[List["AIMessage"]] = relationship("AIMessage", back_populates="conversation", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_ai_conv_org_user", "org_id", "user_id"),
        Index("idx_ai_conv_updated", "org_id", "updated_at"),
    )


class AIMessage(Base):
    """Phase 5: Message within a tenant AI assistance conversation thread."""
    __tablename__ = "ai_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    conversation_id: Mapped[str] = mapped_column(String(36), ForeignKey("ai_conversations.id"), nullable=False)
    sender_type: Mapped[str] = mapped_column(String(50), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    structured_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    provenance: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    conversation: Mapped["AIConversation"] = relationship("AIConversation", back_populates="messages")

    __table_args__ = (
        Index("idx_ai_msg_org_conv", "org_id", "conversation_id"),
        Index("idx_ai_msg_created", "org_id", "created_at"),
    )


class AutomationPolicy(Base):
    """Phase 6: Tenant-scoped automation policy governing execution & approval requirements."""
    __tablename__ = "automation_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allow_auto_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    max_risk_class: Mapped[str] = mapped_column(String(50), nullable=False, default="CLASS_B_LOW_RISK_REVERSIBLE")
    allowed_action_types: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    target_environment_constraints: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    rules: Mapped[List["AutomationRule"]] = relationship("AutomationRule", back_populates="policy", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_auto_policy_org", "org_id"),
        Index("idx_auto_policy_enabled", "org_id", "is_enabled"),
    )


class AutomationRule(Base):
    """Phase 6: Deterministic trigger-action mapping rule inside an AutomationPolicy."""
    __tablename__ = "automation_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(36), ForeignKey("automation_policies.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    trigger_event: Mapped[str] = mapped_column(String(100), nullable=False)
    trigger_conditions: Mapped[dict] = mapped_column(JSON, nullable=False)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    action_parameters_template: Mapped[dict] = mapped_column(JSON, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    policy: Mapped["AutomationPolicy"] = relationship("AutomationPolicy", back_populates="rules")

    __table_args__ = (
        Index("idx_auto_rule_org_trigger", "org_id", "trigger_event"),
        Index("idx_auto_rule_policy", "policy_id"),
    )


class ActionExecution(Base):
    """Phase 6: Auditable action execution state machine."""
    __tablename__ = "action_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    risk_class: Mapped[str] = mapped_column(String(50), nullable=False)
    execution_state: Mapped[str] = mapped_column(String(50), nullable=False, default="PROPOSED")
    authorization_state: Mapped[str] = mapped_column(String(50), nullable=False, default="UNAUTHORIZED")
    approval_requirement: Mapped[str] = mapped_column(String(50), nullable=False, default="REQUIRE_APPROVAL")
    requested_by: Mapped[str] = mapped_column(String(36), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    action_parameters: Mapped[dict] = mapped_column(JSON, nullable=False)
    execution_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_state: Mapped[str] = mapped_column(String(50), nullable=False, default="UNVERIFIED")
    result_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rollback_state: Mapped[str] = mapped_column(String(50), nullable=False, default="NOT_APPLICABLE")
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False, default="v1")
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(255), nullable=False)
    automation_depth: Mapped[int] = mapped_column(nullable=False, default=0)
    parent_execution_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    approvals: Mapped[List["ActionApproval"]] = relationship("ActionApproval", back_populates="action_execution", cascade="all, delete-orphan")
    verifications: Mapped[List["ActionVerification"]] = relationship("ActionVerification", back_populates="action_execution", cascade="all, delete-orphan")
    rollbacks: Mapped[List["ActionRollback"]] = relationship("ActionRollback", back_populates="action_execution", cascade="all, delete-orphan")

    __table_args__ = (
        Index("uix_action_exec_org_idem", "org_id", "idempotency_key", unique=True),
        Index("idx_action_exec_org_state", "org_id", "execution_state"),
        Index("idx_action_exec_org_target", "org_id", "target_identifier"),
        Index("idx_action_exec_corr", "correlation_id"),
    )


class ActionApproval(Base):
    """Phase 6: Authenticated human approval record for explicit action execution."""
    __tablename__ = "action_approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    action_execution_id: Mapped[str] = mapped_column(String(36), ForeignKey("action_executions.id"), nullable=False)
    approver_user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approved_parameters_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    action_execution: Mapped["ActionExecution"] = relationship("ActionExecution", back_populates="approvals")
    approver: Mapped["User"] = relationship("User")

    __table_args__ = (
        Index("idx_action_appr_org_exec", "org_id", "action_execution_id"),
        Index("idx_action_appr_approver", "approver_user_id"),
    )


class ActionVerification(Base):
    """Phase 6: Verification record confirming whether remediation or action succeeded."""
    __tablename__ = "action_verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    action_execution_id: Mapped[str] = mapped_column(String(36), ForeignKey("action_executions.id"), nullable=False)
    verification_method: Mapped[str] = mapped_column(String(100), nullable=False)
    verification_state: Mapped[str] = mapped_column(String(50), nullable=False)
    evidence_ref_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    action_execution: Mapped["ActionExecution"] = relationship("ActionExecution", back_populates="verifications")

    __table_args__ = (
        Index("idx_action_verif_org_exec", "org_id", "action_execution_id"),
    )


class ActionRollback(Base):
    """Phase 6: Reversal and rollback log for reversible actions."""
    __tablename__ = "action_rollbacks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    action_execution_id: Mapped[str] = mapped_column(String(36), ForeignKey("action_executions.id"), nullable=False)
    rollback_action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    rollback_state: Mapped[str] = mapped_column(String(50), nullable=False)
    rolled_back_by: Mapped[str] = mapped_column(String(36), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped["Organization"] = relationship("Organization")
    action_execution: Mapped["ActionExecution"] = relationship("ActionExecution", back_populates="rollbacks")

    __table_args__ = (
        Index("idx_action_roll_org_exec", "org_id", "action_execution_id"),
    )





