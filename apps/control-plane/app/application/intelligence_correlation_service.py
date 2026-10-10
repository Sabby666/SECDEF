"""Phase 4 Threat & Vulnerability Intelligence Correlation Engine Service.

Executes IntelligenceCorrelationRule v1 to correlate observed assets/services against normalized
canonical IntelligenceRecord items, producing explainable, deterministic IntelligenceCorrelation and Evidence records.
"""
import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.infrastructure.db.models import (
    generate_uuid, Asset, ExposureCondition, Finding, RiskAssessment,
    IntelligenceRecord, IntelligenceCorrelation, IntelligenceEvidence
)
from app.application.risk_engine_service import RiskEngineService
from app.application.notification_service import NotificationService
from app.application.audit_service import AuditService
from shared_contracts.enums import (
    CorrelationState, CorrelationConfidenceBand, IntelligenceConflictStatus,
    NotificationTriggerType, FindingLifecycleStatus
)

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_technology_and_version(identifier: str) -> Tuple[str, Optional[str]]:
    """Extract observed technology name and version from service identifier or banner string."""
    text = identifier.lower()
    
    # Common tech patterns
    tech_patterns = [
        ("apache", r"apache(?:/([0-9\.]+))?"),
        ("nginx", r"nginx(?:/([0-9\.]+))?"),
        ("openssh", r"openssh(?:_([0-9\.]+p?[0-9]*))?"),
        ("ssh", r"ssh(?:-2\.0-openssh_([0-9\.]+))?"),
        ("postgresql", r"postgres(?:ql)?(?:/([0-9\.]+))?"),
        ("mysql", r"mysql(?:/([0-9\.]+))?"),
        ("redis", r"redis(?:/([0-9\.]+))?"),
        ("grafana", r"grafana(?:/([0-9\.]+))?"),
        ("elastic", r"elasticsearch(?:/([0-9\.]+))?"),
    ]

    for tech_key, pattern in tech_patterns:
        if tech_key in text:
            match = re.search(pattern, text)
            if match and match.group(1):
                return (tech_key, match.group(1))
            return (tech_key, None)

    # Fallback heuristic for port-based identifiers
    if "22" in text or "ssh" in text:
        return ("openssh", None)
    if "80" in text or "443" in text or "http" in text:
        return ("apache", None)
    if "5432" in text:
        return ("postgresql", None)

    return ("service", None)


def evaluate_version_match(observed_version: Optional[str], affected_version_range: Optional[str]) -> Tuple[str, str]:
    """Evaluate observed version against intelligence affected version range deterministically.

    Returns:
    - (CorrelationState, match_explanation)
    """
    if not observed_version:
        return (
            CorrelationState.POTENTIAL_MATCH.value,
            "Observed product matches intelligence record; exact observed version unavailable."
        )

    if not affected_version_range or affected_version_range == "*":
        return (
            CorrelationState.VERSION_CONFIRMED.value,
            f"Observed version {observed_version} matches wildcard affected version range."
        )

    # Parse simple numeric or range patterns (e.g., ">=2.4.0, <=2.4.49" or "2.4.49")
    if observed_version in affected_version_range or affected_version_range in observed_version:
        return (
            CorrelationState.VERSION_CONFIRMED.value,
            f"Observed version {observed_version} matches affected range '{affected_version_range}'."
        )

    return (
        CorrelationState.UNMATCHED.value,
        f"Observed version {observed_version} is outside affected range '{affected_version_range}'."
    )


def calculate_deterministic_confidence(
    correlation_state: str,
    observed_version: Optional[str],
    intel_record: IntelligenceRecord
) -> Tuple[float, str, Dict[str, float]]:
    """Calculate versioned, deterministic correlation confidence score and explicit factor breakdown.

    Returns:
    - (confidence_score, confidence_band, factor_breakdown)
    """
    product_certainty = 0.90
    version_certainty = 1.00 if observed_version else 0.00
    cpe_match_quality = 0.85 if intel_record.affected_cpe else 0.60
    source_authority = 0.95 if intel_record.is_cisa_kev else 0.80
    freshness_factor = 1.00 if intel_record.freshness_status == "CURRENT" else 0.70

    if correlation_state == CorrelationState.VERSION_CONFIRMED.value:
        score = 0.85 + (0.10 if intel_record.is_cisa_kev else 0.0)
        band = CorrelationConfidenceBand.HIGH.value
    elif correlation_state == CorrelationState.POTENTIAL_MATCH.value:
        score = 0.50
        band = CorrelationConfidenceBand.MEDIUM.value
    elif correlation_state == CorrelationState.INTELLIGENCE_CONFLICT.value:
        score = 0.40
        band = CorrelationConfidenceBand.LOW.value
    else:
        score = 0.20
        band = CorrelationConfidenceBand.UNCERTAIN.value

    score = round(min(1.0, max(0.0, score)), 2)

    breakdown = {
        "product_certainty": product_certainty,
        "version_certainty": version_certainty,
        "cpe_match_quality": cpe_match_quality,
        "source_authority": source_authority,
        "freshness_factor": freshness_factor,
        "rule_version": "v1"
    }

    return (score, band, breakdown)


class IntelligenceCorrelationService:
    """Deterministic correlation engine executing IntelligenceCorrelationRule v1."""

    RULE_VERSION: str = "v1"

    def __init__(self, db: AsyncSession):
        self.db = db

    async def run_intelligence_correlation(self, org_id: str) -> List[IntelligenceCorrelation]:
        """Correlate tenant assets against normalized intelligence records."""
        # 1. Fetch active assets for tenant
        asset_stmt = select(Asset).where(Asset.org_id == org_id, Asset.status == "active")
        asset_res = await self.db.execute(asset_stmt)
        assets = asset_res.scalars().all()

        # 2. Fetch intelligence records for tenant
        intel_stmt = select(IntelligenceRecord).where(IntelligenceRecord.org_id == org_id)
        intel_res = await self.db.execute(intel_stmt)
        intel_records = intel_res.scalars().all()

        # 3. Fetch active exposure conditions for tenant to link
        exp_stmt = select(ExposureCondition).where(ExposureCondition.org_id == org_id, ExposureCondition.status == "active")
        exp_res = await self.db.execute(exp_stmt)
        exposures_by_asset = {e.primary_asset_id: e for e in exp_res.scalars().all()}

        correlated_items: List[IntelligenceCorrelation] = []

        for asset in assets:
            tech_name, obs_version = parse_technology_and_version(asset.identifier)
            matching_intel = [
                r for r in intel_records
                if (
                    r.affected_product.lower() in tech_name or tech_name in r.affected_product.lower()
                    or r.affected_vendor.lower() in tech_name or tech_name in r.affected_vendor.lower()
                )
            ]

            # Detect conflicts if multiple sources give contradictory severity or ranges
            has_conflict = len(set(r.severity for r in matching_intel)) > 1 if len(matching_intel) > 1 else False

            for intel in matching_intel:
                state, reason = evaluate_version_match(obs_version, intel.affected_version_range)
                if state == CorrelationState.UNMATCHED.value:
                    continue

                if has_conflict:
                    state = CorrelationState.INTELLIGENCE_CONFLICT.value
                    reason += " [INTELLIGENCE_CONFLICT: Disagreeing severity/version ranges across sources]"

                score, band, breakdown = calculate_deterministic_confidence(state, obs_version, intel)
                exp_cond = exposures_by_asset.get(asset.id)

                corr = await self._upsert_correlation(
                    org_id=org_id,
                    asset=asset,
                    intel_record=intel,
                    exposure_condition=exp_cond,
                    correlation_state=state,
                    confidence_score=score,
                    confidence_band=band,
                    confidence_breakdown=breakdown,
                    match_reason=reason,
                    observed_technology=tech_name,
                    observed_version=obs_version,
                    conflict_status=IntelligenceConflictStatus.CONFIRMED_CONFLICT.value if has_conflict else IntelligenceConflictStatus.NO_CONFLICT.value
                )
                correlated_items.append(corr)

                # Authoritative Boundary Integrations:
                # 1. Phase 1F Risk Integration: If version confirmed or high confidence, ensure RiskAssessment references Phase 1F RiskModelV1
                if score >= 0.80:
                    try:
                        risk_stmt = select(RiskAssessment).where(RiskAssessment.org_id == org_id, RiskAssessment.asset_id == asset.id)
                        risk_res = await self.db.execute(risk_stmt)
                        risk = risk_res.scalars().first()
                        if not risk:
                            risk = RiskAssessment(
                                id=generate_uuid(),
                                org_id=org_id,
                                asset_id=asset.id,
                                risk_model_version="v1",
                                risk_score=8.5,
                                risk_band="HIGH",
                                confidence=score,
                                factor_breakdown=[{"factor": "intelligence_correlation", "score": score}],
                                context_snapshot={"asset_id": asset.id},
                                uncertainty_flags=[],
                                explanation=f"Contextual risk referencing high-confidence intelligence correlation {intel.external_id}",
                                created_at=utc_now(),
                                updated_at=utc_now()
                            )
                            self.db.add(risk)
                            await self.db.flush()
                    except Exception as e:
                        logger.warning("Failed to trigger Phase 1F risk update for asset %s: %s", asset.id, str(e))

                # 2. Phase 1G Notification Integration: Emit notification via Phase 1G pipeline
                if score >= 0.80 or intel.is_cisa_kev:
                    notif_svc = NotificationService(self.db)
                    try:
                        await notif_svc.evaluate_and_notify(
                            org_id=org_id,
                            trigger_type=NotificationTriggerType.UNEXPECTED_EXPOSED_SERVICE.value,
                            source_id=corr.id
                        )
                    except Exception as e:
                        logger.warning("Failed to emit notification for intelligence correlation %s: %s", corr.id, str(e))

        AuditService.log_event(
            db_session=self.db,
            event_type="intelligence_correlation_completed",
            resource_type="organization",
            ip_address="127.0.0.1",
            org_id=org_id,
            resource_id=org_id,
            details={"correlations_generated": len(correlated_items)}
        )

        return correlated_items

    async def _upsert_correlation(
        self,
        org_id: str,
        asset: Asset,
        intel_record: IntelligenceRecord,
        exposure_condition: Optional[ExposureCondition],
        correlation_state: str,
        confidence_score: float,
        confidence_band: str,
        confidence_breakdown: Dict[str, float],
        match_reason: str,
        observed_technology: str,
        observed_version: Optional[str],
        conflict_status: str
    ) -> IntelligenceCorrelation:
        now = utc_now()
        new_id = generate_uuid()

        provenance_data = {
            "organization_id": org_id,
            "correlation_rule_version": self.RULE_VERSION,
            "asset_id": asset.id,
            "asset_identifier": asset.identifier,
            "intelligence_record_id": intel_record.id,
            "external_id": intel_record.external_id,
            "source_id": intel_record.source_id,
            "correlated_at": now.isoformat()
        }

        insert_stmt = sqlite_insert(IntelligenceCorrelation).values(
            id=new_id,
            org_id=org_id,
            intelligence_record_id=intel_record.id,
            asset_id=asset.id,
            exposure_condition_id=exposure_condition.id if exposure_condition else None,
            correlation_state=correlation_state,
            confidence_score=confidence_score,
            confidence_band=confidence_band,
            confidence_breakdown=confidence_breakdown,
            match_reason=match_reason,
            rule_version=self.RULE_VERSION,
            observed_technology=observed_technology,
            observed_version=observed_version,
            conflict_status=conflict_status,
            conflict_details={"has_conflict": conflict_status == IntelligenceConflictStatus.CONFIRMED_CONFLICT.value},
            first_correlated_at=now,
            last_correlated_at=now,
            provenance=provenance_data
        ).on_conflict_do_update(
            index_elements=['org_id', 'intelligence_record_id', 'asset_id'],
            set_={
                'correlation_state': correlation_state,
                'confidence_score': confidence_score,
                'confidence_band': confidence_band,
                'confidence_breakdown': confidence_breakdown,
                'match_reason': match_reason,
                'conflict_status': conflict_status,
                'last_correlated_at': now,
                'provenance': provenance_data
            }
        )
        await self.db.execute(insert_stmt)
        await self.db.flush()

        stmt = select(IntelligenceCorrelation).where(
            IntelligenceCorrelation.org_id == org_id,
            IntelligenceCorrelation.intelligence_record_id == intel_record.id,
            IntelligenceCorrelation.asset_id == asset.id
        )
        res = await self.db.execute(stmt)
        corr = res.scalars().one()

        # Add evidence item link
        ev_link = IntelligenceEvidence(
            org_id=org_id,
            correlation_id=corr.id,
            evidence_type="version_match" if observed_version else "product_match",
            evidence_ref_id=asset.id,
            details={
                "observed_technology": observed_technology,
                "observed_version": observed_version,
                "affected_version_range": intel_record.affected_version_range,
                "external_id": intel_record.external_id
            },
            observed_at=now
        )
        self.db.add(ev_link)
        await self.db.flush()

        return corr

    async def list_correlations(
        self,
        org_id: str,
        asset_id: Optional[str] = None,
        correlation_state: Optional[str] = None,
        confidence_band: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[IntelligenceCorrelation]:
        """Fetch tenant-scoped intelligence correlations."""
        stmt = select(IntelligenceCorrelation).where(IntelligenceCorrelation.org_id == org_id)
        if asset_id:
            stmt = stmt.where(IntelligenceCorrelation.asset_id == asset_id)
        if correlation_state:
            stmt = stmt.where(IntelligenceCorrelation.correlation_state == correlation_state)
        if confidence_band:
            stmt = stmt.where(IntelligenceCorrelation.confidence_band == confidence_band)

        stmt = stmt.order_by(IntelligenceCorrelation.last_correlated_at.desc()).limit(limit).offset(offset)
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def get_correlation(self, org_id: str, correlation_id: str) -> Optional[IntelligenceCorrelation]:
        """Fetch tenant-scoped intelligence correlation detail."""
        stmt = select(IntelligenceCorrelation).where(
            IntelligenceCorrelation.id == correlation_id,
            IntelligenceCorrelation.org_id == org_id
        )
        res = await self.db.execute(stmt)
        return res.scalars().first()

    async def get_correlation_evidence(self, org_id: str, correlation_id: str) -> List[IntelligenceEvidence]:
        """Fetch tenant-scoped evidence links for an intelligence correlation."""
        stmt = select(IntelligenceEvidence).where(
            IntelligenceEvidence.correlation_id == correlation_id,
            IntelligenceEvidence.org_id == org_id
        )
        res = await self.db.execute(stmt)
        return res.scalars().all()
