"""Deterministic candidate correlation service."""
import logging
from datetime import datetime, timezone
from typing import List, Tuple, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.infrastructure.db.models import DiscoveryCandidate, DiscoveryEvidence
from app.application.discovery_providers.base import RawCandidateEvidence
from shared_contracts.enums import ValidationState, DiscoveryConfidence, ExposureState

logger = logging.getLogger(__name__)


CONFIDENCE_PRIORITY = {
    DiscoveryConfidence.HIGH.value: 3,
    DiscoveryConfidence.MEDIUM.value: 2,
    DiscoveryConfidence.LOW.value: 1,
    DiscoveryConfidence.UNVERIFIED.value: 0,
}


class CandidateCorrelationService:
    """Correlates evidence from multiple discovery sources into distinct, tenant-scoped candidates."""

    @staticmethod
    def correlate_and_store_evidence(
        db: Session,
        org_id: str,
        run_id: str,
        source_type: str,
        evidences: List[RawCandidateEvidence],
    ) -> Tuple[int, int]:
        """Process raw evidence items, inserting or updating candidates and creating evidence records.
        
        Returns (new_candidates_count, correlated_existing_count).
        """
        new_count = 0
        correlated_count = 0

        for ev in evidences:
            ident = ev.canonical_identifier.strip().lower().rstrip(".")
            cand_type = ev.candidate_type.strip().lower()

            # Query existing candidate for (org_id, candidate_type, canonical_identifier)
            stmt = select(DiscoveryCandidate).where(
                DiscoveryCandidate.org_id == org_id,
                DiscoveryCandidate.candidate_type == cand_type,
                DiscoveryCandidate.canonical_identifier == ident,
            )
            candidate = db.scalars(stmt).first()

            if not candidate:
                candidate = DiscoveryCandidate(
                    org_id=org_id,
                    discovery_run_id=run_id,
                    canonical_identifier=ident,
                    candidate_type=cand_type,
                    source_type=source_type,
                    validation_state=ValidationState.UNVALIDATED.value,
                    confidence=ev.confidence,
                    exposure_state=ev.exposure_state,
                    first_seen_at=ev.observed_at,
                    last_seen_at=ev.observed_at,
                    candidate_metadata={
                        "initial_source": source_type,
                        "provenance": ev.provenance,
                    },
                )
                db.add(candidate)
                db.flush()
                new_count += 1
            else:
                correlated_count += 1
                candidate.last_seen_at = max(candidate.last_seen_at, ev.observed_at)
                
                # Upgrade confidence if incoming evidence is stronger
                curr_prio = CONFIDENCE_PRIORITY.get(candidate.confidence, 0)
                new_prio = CONFIDENCE_PRIORITY.get(ev.confidence, 0)
                if new_prio > curr_prio:
                    candidate.confidence = ev.confidence

                # Upgrade exposure_state if currently UNKNOWN
                if candidate.exposure_state == ExposureState.UNKNOWN.value and ev.exposure_state != ExposureState.UNKNOWN.value:
                    candidate.exposure_state = ev.exposure_state

            # Create individual evidence record
            evidence_record = DiscoveryEvidence(
                org_id=org_id,
                candidate_id=candidate.id,
                source_type=source_type,
                raw_data=ev.raw_data,
                provenance=ev.provenance,
                observed_at=ev.observed_at,
            )
            db.add(evidence_record)

        db.commit()
        return new_count, correlated_count
