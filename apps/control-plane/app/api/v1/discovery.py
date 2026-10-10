"""FastAPI endpoints for Phase 2 Discovery & Exposure Intelligence."""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_admin, require_member, require_viewer
from app.application.discovery_service import DiscoveryService
from app.application.candidate_validation_service import CandidateValidationService

router = APIRouter(tags=["Discovery"])


# Request DTOs
class CreateDiscoverySourceRequest(BaseModel):
    source_type: str
    name: str
    config: Optional[Dict[str, Any]] = None


class TriggerDiscoveryRunRequest(BaseModel):
    domain_id: str
    source_type: str
    config: Optional[Dict[str, Any]] = None


class ValidateCandidateRequest(BaseModel):
    validation_override: Optional[str] = None


class RejectCandidateRequest(BaseModel):
    reason: Optional[str] = None


def verify_tenant_access(org_id: str, auth_ctx: dict):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )


@router.get("/organizations/{org_id}/discovery/sources")
async def list_discovery_sources(
    org_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List registered discovery sources for organization."""
    verify_tenant_access(org_id, auth_ctx)
    service = DiscoveryService(db)
    sources = await service.list_sources(org_id)
    return [
        {
            "id": s.id,
            "org_id": s.org_id,
            "source_type": s.source_type,
            "name": s.name,
            "is_active": s.is_active,
            "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
            "config": s.config,
        }
        for s in sources
    ]


@router.post("/organizations/{org_id}/discovery/sources", status_code=status.HTTP_201_CREATED)
async def create_discovery_source(
    org_id: str,
    payload: CreateDiscoverySourceRequest,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session),
):
    """Configure a new discovery source. Requires Admin or Owner role."""
    verify_tenant_access(org_id, auth_ctx)
    service = DiscoveryService(db)
    source = await service.create_source(
        org_id=org_id,
        source_type=payload.source_type,
        name=payload.name,
        config=payload.config,
    )
    return {
        "id": source.id,
        "org_id": source.org_id,
        "source_type": source.source_type,
        "name": source.name,
        "is_active": source.is_active,
        "config": source.config,
    }



@router.post("/organizations/{org_id}/discovery/runs", status_code=status.HTTP_201_CREATED)
async def trigger_discovery_run(
    org_id: str,
    payload: TriggerDiscoveryRunRequest,
    auth_ctx: dict = Depends(require_member),
    db: AsyncSession = Depends(get_db_session),
):
    """Trigger a new discovery run for a verified organization domain."""
    verify_tenant_access(org_id, auth_ctx)
    service = DiscoveryService(db)
    run = await service.start_discovery_run(
        org_id=org_id,
        domain_id=payload.domain_id,
        source_type=payload.source_type,
        config_override=payload.config,
    )
    return {
        "id": run.id,
        "org_id": run.org_id,
        "source_id": run.source_id,
        "domain_id": run.domain_id,
        "status": run.status,
        "candidates_discovered": run.candidates_discovered,
        "candidates_validated": run.candidates_validated,
        "candidates_rejected": run.candidates_rejected,
        "error_message": run.error_message,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }


@router.get("/organizations/{org_id}/discovery/runs")
async def list_discovery_runs(
    org_id: str,
    domain_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List discovery runs for organization."""
    verify_tenant_access(org_id, auth_ctx)
    service = DiscoveryService(db)
    runs = await service.list_runs(org_id, domain_id=domain_id, limit=limit)
    return [
        {
            "id": r.id,
            "org_id": r.org_id,
            "source_id": r.source_id,
            "domain_id": r.domain_id,
            "status": r.status,
            "candidates_discovered": r.candidates_discovered,
            "candidates_validated": r.candidates_validated,
            "candidates_rejected": r.candidates_rejected,
            "error_message": r.error_message,
            "created_at": r.created_at.isoformat(),
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in runs
    ]


@router.get("/organizations/{org_id}/discovery/runs/{run_id}")
async def get_discovery_run(
    org_id: str,
    run_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get single discovery run by ID."""
    verify_tenant_access(org_id, auth_ctx)
    service = DiscoveryService(db)
    run = await service.get_run(run_id, org_id)
    return {
        "id": run.id,
        "org_id": run.org_id,
        "source_id": run.source_id,
        "domain_id": run.domain_id,
        "status": run.status,
        "candidates_discovered": run.candidates_discovered,
        "candidates_validated": run.candidates_validated,
        "candidates_rejected": run.candidates_rejected,
        "error_message": run.error_message,
        "run_metadata": run.run_metadata,
        "created_at": run.created_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }


@router.get("/organizations/{org_id}/discovery/candidates")
async def list_discovery_candidates(
    org_id: str,
    validation_state: Optional[str] = Query(None),
    candidate_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List discovery candidates scoped by tenant and optional validation state filters."""
    verify_tenant_access(org_id, auth_ctx)
    service = DiscoveryService(db)
    candidates = await service.list_candidates(
        org_id, validation_state=validation_state, candidate_type=candidate_type, limit=limit
    )
    return [
        {
            "id": c.id,
            "org_id": c.org_id,
            "discovery_run_id": c.discovery_run_id,
            "canonical_identifier": c.canonical_identifier,
            "candidate_type": c.candidate_type,
            "source_type": c.source_type,
            "validation_state": c.validation_state,
            "confidence": c.confidence,
            "exposure_state": c.exposure_state,
            "promoted_asset_id": c.promoted_asset_id,
            "first_seen_at": c.first_seen_at.isoformat(),
            "last_seen_at": c.last_seen_at.isoformat(),
        }
        for c in candidates
    ]


@router.get("/organizations/{org_id}/discovery/candidates/{candidate_id}")
async def get_discovery_candidate(
    org_id: str,
    candidate_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get discovery candidate details."""
    verify_tenant_access(org_id, auth_ctx)
    service = DiscoveryService(db)
    cand = await service.get_candidate(candidate_id, org_id)
    return {
        "id": cand.id,
        "org_id": cand.org_id,
        "discovery_run_id": cand.discovery_run_id,
        "canonical_identifier": cand.canonical_identifier,
        "candidate_type": cand.candidate_type,
        "source_type": cand.source_type,
        "validation_state": cand.validation_state,
        "confidence": cand.confidence,
        "exposure_state": cand.exposure_state,
        "promoted_asset_id": cand.promoted_asset_id,
        "candidate_metadata": cand.candidate_metadata,
        "first_seen_at": cand.first_seen_at.isoformat(),
        "last_seen_at": cand.last_seen_at.isoformat(),
    }


@router.get("/organizations/{org_id}/discovery/candidates/{candidate_id}/evidence")
async def get_candidate_evidence(
    org_id: str,
    candidate_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get all evidence items for a discovery candidate."""
    verify_tenant_access(org_id, auth_ctx)
    service = DiscoveryService(db)
    evidences = await service.get_candidate_evidence(candidate_id, org_id)
    return [
        {
            "id": e.id,
            "org_id": e.org_id,
            "candidate_id": e.candidate_id,
            "source_type": e.source_type,
            "raw_data": e.raw_data,
            "provenance": e.provenance,
            "observed_at": e.observed_at.isoformat(),
        }
        for e in evidences
    ]


@router.post("/organizations/{org_id}/discovery/candidates/{candidate_id}/validate")
async def validate_discovery_candidate(
    org_id: str,
    candidate_id: str,
    payload: Optional[ValidateCandidateRequest] = None,
    auth_ctx: dict = Depends(require_member),
    db: AsyncSession = Depends(get_db_session),
):
    """Validate a candidate and promote it to Phase 1 Asset graph."""
    verify_tenant_access(org_id, auth_ctx)
    val_service = CandidateValidationService(db)
    override = payload.validation_override if payload else None
    cand = await val_service.validate_candidate(candidate_id, org_id, validation_override=override)
    return {
        "id": cand.id,
        "org_id": cand.org_id,
        "canonical_identifier": cand.canonical_identifier,
        "validation_state": cand.validation_state,
        "promoted_asset_id": cand.promoted_asset_id,
        "updated_at": cand.last_seen_at.isoformat(),
    }


@router.post("/organizations/{org_id}/discovery/candidates/{candidate_id}/reject")
async def reject_discovery_candidate(
    org_id: str,
    candidate_id: str,
    payload: Optional[RejectCandidateRequest] = None,
    auth_ctx: dict = Depends(require_member),
    db: AsyncSession = Depends(get_db_session),
):
    """Reject a discovery candidate."""
    verify_tenant_access(org_id, auth_ctx)
    val_service = CandidateValidationService(db)
    cand = await val_service.reject_candidate(candidate_id, org_id)
    return {
        "id": cand.id,
        "org_id": cand.org_id,
        "canonical_identifier": cand.canonical_identifier,
        "validation_state": cand.validation_state,
        "updated_at": cand.last_seen_at.isoformat(),
    }
