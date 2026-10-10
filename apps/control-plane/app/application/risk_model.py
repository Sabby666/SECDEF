"""Phase 1F: Deterministic Risk Model V1 Engine.

Computes reconstructable, factor-backed contextual risk scores (0.0 - 100.0),
risk bands (CRITICAL, HIGH, MEDIUM, LOW, INFO), confidence metrics, and human-readable explanations.

RULES & INVARIANTS:
1. Reconstructable Factor Breakdown: Score is 100% derived from explicit factor contributions.
2. Missing Data Handling: Missing/unknown context incurs explicit uncertainty weights (+10 to +15) and uncertainty flags.
3. Conflict Handling: CONFLICT_REQUIRES_REVIEW triggers an explicit uncertainty flag and +20 contribution.
4. No Feedback Loop: Does NOT write to or modify organizational memory or asset context.
"""

from typing import Dict, Any, List, Tuple, Optional
from shared_contracts.enums import RiskBand, RiskModelVersion
from shared_contracts.schemas import RiskFactorDetail, ContextResolutionResponse


HIGH_RISK_PORTS = {3389, 22, 3306, 5432, 27017, 6379, 8443, 8080, 9200, 11211, 23, 21}
WEB_PORTS = {80, 443}


class RiskModelV1:
    """Deterministic Phase 1F Risk Model Engine V1."""

    @classmethod
    def calculate_risk(
        self,
        change_type: Optional[str],
        entity_type: Optional[str],
        entity_identifier: str,
        context_res: ContextResolutionResponse,
        evidence_payload: Optional[Dict[str, Any]] = None,
    ) -> Tuple[float, RiskBand, float, List[RiskFactorDetail], Dict[str, Any], List[str], str]:
        """Calculate deterministic risk score and return (score, band, confidence, factor_breakdown, context_snapshot, uncertainty_flags, explanation)."""

        factors: List[RiskFactorDetail] = []
        uncertainty_flags: List[str] = []

        # Snapshot of context at calculation time
        context_snapshot = {
            "target_identifier": context_res.target_identifier,
            "target_type": context_res.target_type,
            "expected_state": context_res.expected_state,
            "environment": context_res.environment,
            "criticality": context_res.criticality,
            "owner_id": context_res.owner_id,
            "owner_team": context_res.owner_team,
            "conflict_detected": context_res.conflict_detected,
            "resolution_status": context_res.resolution_status,
        }

        # 1. Asset Criticality Factor
        crit = (context_res.criticality or "unknown").lower()
        if crit == "critical":
            factors.append(
                RiskFactorDetail(
                    factor_name="asset_criticality",
                    factor_value="critical",
                    contribution=30.0,
                    source_type="asset_context",
                    source_id=context_res.target_identifier,
                    evidence_ref={"criticality": "critical", "target": context_res.target_identifier},
                )
            )
        elif crit == "high":
            factors.append(
                RiskFactorDetail(
                    factor_name="asset_criticality",
                    factor_value="high",
                    contribution=20.0,
                    source_type="asset_context",
                    source_id=context_res.target_identifier,
                    evidence_ref={"criticality": "high", "target": context_res.target_identifier},
                )
            )
        elif crit == "medium":
            factors.append(
                RiskFactorDetail(
                    factor_name="asset_criticality",
                    factor_value="medium",
                    contribution=10.0,
                    source_type="asset_context",
                    source_id=context_res.target_identifier,
                    evidence_ref={"criticality": "medium", "target": context_res.target_identifier},
                )
            )
        elif crit == "low":
            factors.append(
                RiskFactorDetail(
                    factor_name="asset_criticality",
                    factor_value="low",
                    contribution=5.0,
                    source_type="asset_context",
                    source_id=context_res.target_identifier,
                    evidence_ref={"criticality": "low", "target": context_res.target_identifier},
                )
            )
        else:
            uncertainty_flags.append("UNKNOWN_CRITICALITY")
            factors.append(
                RiskFactorDetail(
                    factor_name="asset_criticality",
                    factor_value="unknown",
                    contribution=10.0,
                    source_type="asset_context",
                    source_id=context_res.target_identifier,
                    uncertainty_flag="UNKNOWN_CRITICALITY",
                    evidence_ref={"criticality": "unknown", "target": context_res.target_identifier},
                )
            )

        # 2. Environment Factor
        env = (context_res.environment or "unknown").lower()
        if env == "production":
            factors.append(
                RiskFactorDetail(
                    factor_name="environment",
                    factor_value="production",
                    contribution=25.0,
                    source_type="asset_context",
                    source_id=context_res.target_identifier,
                    evidence_ref={"environment": "production", "target": context_res.target_identifier},
                )
            )
        elif env == "staging":
            factors.append(
                RiskFactorDetail(
                    factor_name="environment",
                    factor_value="staging",
                    contribution=15.0,
                    source_type="asset_context",
                    source_id=context_res.target_identifier,
                    evidence_ref={"environment": "staging", "target": context_res.target_identifier},
                )
            )
        elif env in ("development", "dev", "test"):
            factors.append(
                RiskFactorDetail(
                    factor_name="environment",
                    factor_value=env,
                    contribution=5.0,
                    source_type="asset_context",
                    source_id=context_res.target_identifier,
                    evidence_ref={"environment": env, "target": context_res.target_identifier},
                )
            )
        else:
            uncertainty_flags.append("UNKNOWN_ENVIRONMENT")
            factors.append(
                RiskFactorDetail(
                    factor_name="environment",
                    factor_value="unknown",
                    contribution=15.0,
                    source_type="asset_context",
                    source_id=context_res.target_identifier,
                    uncertainty_flag="UNKNOWN_ENVIRONMENT",
                    evidence_ref={"environment": "unknown", "target": context_res.target_identifier},
                )
            )

        # 3. Expected State Factor
        exp_state = context_res.expected_state
        prov_source_id = context_res.provenance[0].source_id if context_res.provenance else None
        if exp_state == "UNEXPECTED":
            factors.append(
                RiskFactorDetail(
                    factor_name="expected_state",
                    factor_value="UNEXPECTED",
                    contribution=30.0,
                    source_type="organizational_memory",
                    source_id=prov_source_id,
                    evidence_ref={"expected_state": "UNEXPECTED", "source_id": prov_source_id},
                )
            )
        elif exp_state == "CONFLICT_REQUIRES_REVIEW":
            uncertainty_flags.append("EXPECTED_STATE_CONFLICT")
            factors.append(
                RiskFactorDetail(
                    factor_name="expected_state",
                    factor_value="CONFLICT_REQUIRES_REVIEW",
                    contribution=20.0,
                    source_type="organizational_memory",
                    source_id=prov_source_id,
                    uncertainty_flag="EXPECTED_STATE_CONFLICT",
                    evidence_ref={"conflict_detected": True, "source_id": prov_source_id},
                )
            )
        elif exp_state == "UNSPECIFIED":
            uncertainty_flags.append("UNSPECIFIED_EXPECTED_STATE")
            factors.append(
                RiskFactorDetail(
                    factor_name="expected_state",
                    factor_value="UNSPECIFIED",
                    contribution=10.0,
                    source_type="organizational_memory",
                    source_id=None,
                    uncertainty_flag="UNSPECIFIED_EXPECTED_STATE",
                    evidence_ref={"expected_state": "UNSPECIFIED"},
                )
            )
        else:  # EXPECTED
            factors.append(
                RiskFactorDetail(
                    factor_name="expected_state",
                    factor_value="EXPECTED",
                    contribution=0.0,
                    source_type="organizational_memory",
                    source_id=prov_source_id,
                    evidence_ref={"expected_state": "EXPECTED", "source_id": prov_source_id},
                )
            )

        # 4. Change Significance Factor
        c_type = (change_type or "").lower()
        if c_type == "asset_added":
            factors.append(
                RiskFactorDetail(
                    factor_name="change_significance",
                    factor_value="asset_added",
                    contribution=20.0,
                    source_type="change_detection",
                    source_id=entity_identifier,
                    evidence_ref={"change_type": "asset_added", "payload": evidence_payload},
                )
            )
        elif c_type == "relationship_added":
            factors.append(
                RiskFactorDetail(
                    factor_name="change_significance",
                    factor_value="relationship_added",
                    contribution=15.0,
                    source_type="change_detection",
                    source_id=entity_identifier,
                    evidence_ref={"change_type": "relationship_added", "payload": evidence_payload},
                )
            )
        elif c_type == "asset_property_changed":
            factors.append(
                RiskFactorDetail(
                    factor_name="change_significance",
                    factor_value="asset_property_changed",
                    contribution=10.0,
                    source_type="change_detection",
                    source_id=entity_identifier,
                    evidence_ref={"change_type": "asset_property_changed", "payload": evidence_payload},
                )
            )
        elif c_type == "asset_removed":
            factors.append(
                RiskFactorDetail(
                    factor_name="change_significance",
                    factor_value="asset_removed",
                    contribution=5.0,
                    source_type="change_detection",
                    source_id=entity_identifier,
                    evidence_ref={"change_type": "asset_removed", "payload": evidence_payload},
                )
            )
        elif c_type == "relationship_removed":
            factors.append(
                RiskFactorDetail(
                    factor_name="change_significance",
                    factor_value="relationship_removed",
                    contribution=0.0,
                    source_type="change_detection",
                    source_id=entity_identifier,
                    evidence_ref={"change_type": "relationship_removed", "payload": evidence_payload},
                )
            )

        # 5. Service / Exposure Classification Factor (Mutually Exclusive Order: High Risk > Web > Custom)
        port = None
        if ":" in entity_identifier:
            try:
                port = int(entity_identifier.split(":")[-1])
            except ValueError:
                port = None

        if port in HIGH_RISK_PORTS:
            factors.append(
                RiskFactorDetail(
                    factor_name="service_exposure",
                    factor_value=f"high_risk_port_{port}",
                    contribution=20.0,
                    source_type="observation",
                    source_id=entity_identifier,
                    evidence_ref={"port": port, "classification": "high_risk"},
                )
            )
        elif port in WEB_PORTS or (entity_type and entity_type in ("subdomain", "service")):
            factors.append(
                RiskFactorDetail(
                    factor_name="service_exposure",
                    factor_value=f"web_exposure_{port if port else 'default'}",
                    contribution=10.0,
                    source_type="observation",
                    source_id=entity_identifier,
                    evidence_ref={"port": port, "classification": "web_exposure"},
                )
            )
        elif port is not None:
            factors.append(
                RiskFactorDetail(
                    factor_name="service_exposure",
                    factor_value=f"custom_port_{port}",
                    contribution=15.0,
                    source_type="observation",
                    source_id=entity_identifier,
                    evidence_ref={"port": port, "classification": "custom_port"},
                )
            )

        # 6. Ownership Attribution Factor
        if not context_res.owner_id and not context_res.owner_team:
            uncertainty_flags.append("MISSING_OWNER")
            factors.append(
                RiskFactorDetail(
                    factor_name="ownership_attribution",
                    factor_value="unassigned",
                    contribution=10.0,
                    source_type="asset_context",
                    uncertainty_flag="MISSING_OWNER",
                )
            )
        else:
            factors.append(
                RiskFactorDetail(
                    factor_name="ownership_attribution",
                    factor_value=f"team:{context_res.owner_team or context_res.owner_id}",
                    contribution=0.0,
                    source_type="asset_context",
                )
            )

        # Calculate final raw score and clamp (0.0 - 100.0)
        raw_score = sum(f.contribution for f in factors)
        risk_score = round(min(100.0, max(0.0, raw_score)), 1)

        # Determine Risk Band
        if risk_score >= 80.0:
            risk_band = RiskBand.CRITICAL
        elif risk_score >= 60.0:
            risk_band = RiskBand.HIGH
        elif risk_score >= 40.0:
            risk_band = RiskBand.MEDIUM
        elif risk_score >= 20.0:
            risk_band = RiskBand.LOW
        else:
            risk_band = RiskBand.INFO

        # Calculate Confidence Score (Starts at 1.0, reduced per uncertainty flag)
        confidence = round(max(0.2, 1.0 - (len(uncertainty_flags) * 0.15)), 2)

        # Generate Human-Readable Structured Explanation
        explanation = self._build_explanation(
            entity_identifier=entity_identifier,
            change_type=change_type,
            risk_score=risk_score,
            risk_band=risk_band,
            confidence=confidence,
            factors=factors,
            uncertainty_flags=uncertainty_flags,
            context_res=context_res,
        )

        return (
            risk_score,
            risk_band,
            confidence,
            factors,
            context_snapshot,
            uncertainty_flags,
            explanation,
        )

    @classmethod
    def _build_explanation(
        self,
        entity_identifier: str,
        change_type: Optional[str],
        risk_score: float,
        risk_band: RiskBand,
        confidence: float,
        factors: List[RiskFactorDetail],
        uncertainty_flags: List[str],
        context_res: ContextResolutionResponse,
    ) -> str:
        lines = [
            f"### Contextual Risk Assessment: {risk_band.value} ({risk_score}/100.0)",
            f"- **Target**: `{entity_identifier}` ({context_res.target_type})",
            f"- **Evaluated Change**: `{change_type or 'N/A'}`",
            f"- **Model Version**: `v1`",
            f"- **Confidence Score**: `{confidence}`",
            "",
            "#### Organizational Context Snapshot",
            f"- **Environment**: `{context_res.environment}`",
            f"- **Criticality**: `{context_res.criticality}`",
            f"- **Expected State**: `{context_res.expected_state}`",
            f"- **Ownership**: `{context_res.owner_team or context_res.owner_id or 'Unassigned'}`",
            "",
            "#### Risk Factor Breakdown",
        ]

        for f in factors:
            flag_str = f" *(Uncertainty Flag: {f.uncertainty_flag})*" if f.uncertainty_flag else ""
            lines.append(
                f"- **{f.factor_name}** (`{f.factor_value}`): **+{f.contribution}** points (Source: `{f.source_type}`){flag_str}"
            )

        if uncertainty_flags:
            lines.extend(["", "#### Uncertainty & Missing Data Flags"])
            for flag in uncertainty_flags:
                lines.append(f"- `{flag}`")

        return "\n".join(lines)


class RiskModelV2(RiskModelV1):
    """Deterministic Phase 1F Risk Model Engine V2 (Updated factor weights)."""

    @classmethod
    def calculate_risk(
        self,
        change_type: Optional[str],
        entity_type: Optional[str],
        entity_identifier: str,
        context_res: ContextResolutionResponse,
        evidence_payload: Optional[Dict[str, Any]] = None,
    ) -> Tuple[float, RiskBand, float, List[RiskFactorDetail], Dict[str, Any], List[str], str]:
        """Calculate risk using V2 weights (High Risk Port = 25.0, Criticality Critical = 35.0)."""
        score, band, confidence, factors, context_snapshot, uncertainty_flags, _ = super().calculate_risk(
            change_type=change_type,
            entity_type=entity_type,
            entity_identifier=entity_identifier,
            context_res=context_res,
            evidence_payload=evidence_payload,
        )

        # Apply V2 distinct factor adjustments
        adjusted_factors: List[RiskFactorDetail] = []
        for f in factors:
            if f.factor_name == "service_exposure" and "high_risk_port" in f.factor_value:
                adjusted_factors.append(
                    RiskFactorDetail(
                        factor_name=f.factor_name,
                        factor_value=f.factor_value,
                        contribution=25.0,  # V2 weight
                        source_type=f.source_type,
                        source_id=f.source_id,
                        evidence_ref=f.evidence_ref,
                    )
                )
            elif f.factor_name == "asset_criticality" and f.factor_value == "critical":
                adjusted_factors.append(
                    RiskFactorDetail(
                        factor_name=f.factor_name,
                        factor_value=f.factor_value,
                        contribution=35.0,  # V2 weight
                        source_type=f.source_type,
                        source_id=f.source_id,
                        evidence_ref=f.evidence_ref,
                    )
                )
            else:
                adjusted_factors.append(f)

        raw_score = sum(f.contribution for f in adjusted_factors)
        v2_score = round(min(100.0, max(0.0, raw_score)), 1)

        # Determine Risk Band for V2
        if v2_score >= 80.0:
            v2_band = RiskBand.CRITICAL
        elif v2_score >= 60.0:
            v2_band = RiskBand.HIGH
        elif v2_score >= 40.0:
            v2_band = RiskBand.MEDIUM
        elif v2_score >= 20.0:
            v2_band = RiskBand.LOW
        else:
            v2_band = RiskBand.INFO

        v2_explanation = self._build_explanation(
            entity_identifier=entity_identifier,
            change_type=change_type,
            risk_score=v2_score,
            risk_band=v2_band,
            confidence=confidence,
            factors=adjusted_factors,
            uncertainty_flags=uncertainty_flags,
            context_res=context_res,
        ).replace("`v1`", "`v2`")

        return (
            v2_score,
            v2_band,
            confidence,
            adjusted_factors,
            context_snapshot,
            uncertainty_flags,
            v2_explanation,
        )


SUPPORTED_RISK_MODELS = {
    RiskModelVersion.V1.value: RiskModelV1,
    RiskModelVersion.V2.value: RiskModelV2,
}


def get_risk_model(version: str):
    """Retrieve risk model class for the requested version string, raising ValueError if unsupported."""
    if version not in SUPPORTED_RISK_MODELS:
        raise ValueError(
            f"Unsupported or invalid risk_model_version: '{version}'. "
            f"Supported versions are: {list(SUPPORTED_RISK_MODELS.keys())}"
        )
    return SUPPORTED_RISK_MODELS[version]

