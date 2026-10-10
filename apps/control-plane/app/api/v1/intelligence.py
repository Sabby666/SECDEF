"""FastAPI endpoints for Phase 4 Threat & Vulnerability Intelligence Correlation."""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.session import get_db_session
from app.api.dependencies.auth import require_admin, require_member, require_viewer
from app.application.intelligence_ingestion_service import IntelligenceIngestionService
from app.application.intelligence_correlation_service import IntelligenceCorrelationService

router = APIRouter(tags=["Intelligence"])


def verify_tenant_access(org_id: str, auth_ctx: dict):
    if org_id != auth_ctx["org"].id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )


# Request & Response DTOs
class IngestPayloadRequest(BaseModel):
    source_name: str = Field(..., max_length=100)
    source_type: str = Field(..., max_length=50)
    payload_content: str = Field(..., max_length=10 * 1024 * 1024)


class IntelligenceRunResponse(BaseModel):
    id: str
    org_id: str
    source_id: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    records_ingested: int
    records_updated: int
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class IntelligenceRecordResponse(BaseModel):
    id: str
    org_id: str
    source_id: str
    external_id: str
    title: str
    description: str
    severity: str
    cvss_v3_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_ids: List[str] = []
    affected_product: str
    affected_vendor: str
    affected_cpe: Optional[str] = None
    affected_version_range: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_cisa_kev: bool
    exploit_availability: str
    published_at: Optional[str] = None
    updated_at: Optional[str] = None
    retrieved_at: str
    freshness_status: str
    provenance: Dict[str, Any]

    class Config:
        from_attributes = True


class IntelligenceCorrelationResponse(BaseModel):
    id: str
    org_id: str
    intelligence_record_id: str
    asset_id: str
    exposure_condition_id: Optional[str] = None
    correlation_state: str
    confidence_score: float
    confidence_band: str
    confidence_breakdown: Dict[str, Any]
    match_reason: str
    rule_version: str
    observed_technology: str
    observed_version: Optional[str] = None
    conflict_status: str
    conflict_details: Optional[Dict[str, Any]] = None
    first_correlated_at: str
    last_correlated_at: str
    provenance: Dict[str, Any]

    class Config:
        from_attributes = True


class IntelligenceEvidenceResponse(BaseModel):
    id: str
    org_id: str
    correlation_id: str
    evidence_type: str
    evidence_ref_id: str
    details: Optional[Dict[str, Any]] = None
    observed_at: str

    class Config:
        from_attributes = True


@router.get(
    "/organizations/{org_id}/intelligence",
    response_model=List[IntelligenceRecordResponse],
)
async def list_intelligence_records(
    org_id: str,
    source_id: Optional[str] = Query(None),
    affected_vendor: Optional[str] = Query(None),
    affected_product: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List tenant-scoped intelligence records (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = IntelligenceIngestionService(db)
    records = await svc.list_records(
        org_id=org_id,
        source_id=source_id,
        affected_vendor=affected_vendor,
        affected_product=affected_product,
        limit=limit,
        offset=offset
    )
    return [
        IntelligenceRecordResponse(
            id=r.id,
            org_id=r.org_id,
            source_id=r.source_id,
            external_id=r.external_id,
            title=r.title,
            description=r.description,
            severity=r.severity,
            cvss_v3_score=r.cvss_v3_score,
            cvss_vector=r.cvss_vector,
            cwe_ids=r.cwe_ids or [],
            affected_product=r.affected_product,
            affected_vendor=r.affected_vendor,
            affected_cpe=r.affected_cpe,
            affected_version_range=r.affected_version_range,
            epss_score=r.epss_score,
            epss_percentile=r.epss_percentile,
            is_cisa_kev=r.is_cisa_kev,
            exploit_availability=r.exploit_availability,
            published_at=r.published_at.isoformat() if r.published_at else None,
            updated_at=r.updated_at.isoformat() if r.updated_at else None,
            retrieved_at=r.retrieved_at.isoformat() if r.retrieved_at else "",
            freshness_status=r.freshness_status,
            provenance=r.provenance or {},
        )
        for r in records
    ]


@router.get(
    "/organizations/{org_id}/intelligence/{id}",
    response_model=IntelligenceRecordResponse,
)
async def get_intelligence_record(
    org_id: str,
    id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get tenant-scoped intelligence record detail (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = IntelligenceIngestionService(db)
    r = await svc.get_record(org_id, id)
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Intelligence record not found",
        )
    return IntelligenceRecordResponse(
        id=r.id,
        org_id=r.org_id,
        source_id=r.source_id,
        external_id=r.external_id,
        title=r.title,
        description=r.description,
        severity=r.severity,
        cvss_v3_score=r.cvss_v3_score,
        cvss_vector=r.cvss_vector,
        cwe_ids=r.cwe_ids or [],
        affected_product=r.affected_product,
        affected_vendor=r.affected_vendor,
        affected_cpe=r.affected_cpe,
        affected_version_range=r.affected_version_range,
        epss_score=r.epss_score,
        epss_percentile=r.epss_percentile,
        is_cisa_kev=r.is_cisa_kev,
        exploit_availability=r.exploit_availability,
        published_at=r.published_at.isoformat() if r.published_at else None,
        updated_at=r.updated_at.isoformat() if r.updated_at else None,
        retrieved_at=r.retrieved_at.isoformat() if r.retrieved_at else "",
        freshness_status=r.freshness_status,
        provenance=r.provenance or {},
    )


@router.get(
    "/organizations/{org_id}/correlations",
    response_model=List[IntelligenceCorrelationResponse],
)
async def list_intelligence_correlations(
    org_id: str,
    asset_id: Optional[str] = Query(None),
    correlation_state: Optional[str] = Query(None),
    confidence_band: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """List tenant-scoped intelligence correlations (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = IntelligenceCorrelationService(db)
    correlations = await svc.list_correlations(
        org_id=org_id,
        asset_id=asset_id,
        correlation_state=correlation_state,
        confidence_band=confidence_band,
        limit=limit,
        offset=offset
    )
    return [
        IntelligenceCorrelationResponse(
            id=c.id,
            org_id=c.org_id,
            intelligence_record_id=c.intelligence_record_id,
            asset_id=c.asset_id,
            exposure_condition_id=c.exposure_condition_id,
            correlation_state=c.correlation_state,
            confidence_score=c.confidence_score,
            confidence_band=c.confidence_band,
            confidence_breakdown=c.confidence_breakdown or {},
            match_reason=c.match_reason,
            rule_version=c.rule_version,
            observed_technology=c.observed_technology,
            observed_version=c.observed_version,
            conflict_status=c.conflict_status,
            conflict_details=c.conflict_details,
            first_correlated_at=c.first_correlated_at.isoformat() if c.first_correlated_at else "",
            last_correlated_at=c.last_correlated_at.isoformat() if c.last_correlated_at else "",
            provenance=c.provenance or {},
        )
        for c in correlations
    ]


@router.get(
    "/organizations/{org_id}/correlations/{id}",
    response_model=IntelligenceCorrelationResponse,
)
async def get_intelligence_correlation(
    org_id: str,
    id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get tenant-scoped intelligence correlation detail (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = IntelligenceCorrelationService(db)
    c = await svc.get_correlation(org_id, id)
    if not c:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Intelligence correlation not found",
        )
    return IntelligenceCorrelationResponse(
        id=c.id,
        org_id=c.org_id,
        intelligence_record_id=c.intelligence_record_id,
        asset_id=c.asset_id,
        exposure_condition_id=c.exposure_condition_id,
        correlation_state=c.correlation_state,
        confidence_score=c.confidence_score,
        confidence_band=c.confidence_band,
        confidence_breakdown=c.confidence_breakdown or {},
        match_reason=c.match_reason,
        rule_version=c.rule_version,
        observed_technology=c.observed_technology,
        observed_version=c.observed_version,
        conflict_status=c.conflict_status,
        conflict_details=c.conflict_details,
        first_correlated_at=c.first_correlated_at.isoformat() if c.first_correlated_at else "",
        last_correlated_at=c.last_correlated_at.isoformat() if c.last_correlated_at else "",
        provenance=c.provenance or {},
    )


@router.get(
    "/organizations/{org_id}/correlations/{id}/evidence",
    response_model=List[IntelligenceEvidenceResponse],
)
async def get_correlation_evidence(
    org_id: str,
    id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get evidence links for an intelligence correlation (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = IntelligenceCorrelationService(db)
    c = await svc.get_correlation(org_id, id)
    if not c:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Intelligence correlation not found",
        )
    ev_items = await svc.get_correlation_evidence(org_id, id)
    return [
        IntelligenceEvidenceResponse(
            id=ev.id,
            org_id=ev.org_id,
            correlation_id=ev.correlation_id,
            evidence_type=ev.evidence_type,
            evidence_ref_id=ev.evidence_ref_id,
            details=ev.details,
            observed_at=ev.observed_at.isoformat() if ev.observed_at else "",
        )
        for ev in ev_items
    ]


@router.get(
    "/organizations/{org_id}/assets/{asset_id}/intelligence",
    response_model=List[IntelligenceCorrelationResponse],
)
async def get_asset_intelligence(
    org_id: str,
    asset_id: str,
    auth_ctx: dict = Depends(require_viewer),
    db: AsyncSession = Depends(get_db_session),
):
    """Get intelligence correlations specifically attached to an asset (RBAC: Viewer+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = IntelligenceCorrelationService(db)
    correlations = await svc.list_correlations(org_id=org_id, asset_id=asset_id)
    return [
        IntelligenceCorrelationResponse(
            id=c.id,
            org_id=c.org_id,
            intelligence_record_id=c.intelligence_record_id,
            asset_id=c.asset_id,
            exposure_condition_id=c.exposure_condition_id,
            correlation_state=c.correlation_state,
            confidence_score=c.confidence_score,
            confidence_band=c.confidence_band,
            confidence_breakdown=c.confidence_breakdown or {},
            match_reason=c.match_reason,
            rule_version=c.rule_version,
            observed_technology=c.observed_technology,
            observed_version=c.observed_version,
            conflict_status=c.conflict_status,
            conflict_details=c.conflict_details,
            first_correlated_at=c.first_correlated_at.isoformat() if c.first_correlated_at else "",
            last_correlated_at=c.last_correlated_at.isoformat() if c.last_correlated_at else "",
            provenance=c.provenance or {},
        )
        for c in correlations
    ]


@router.post(
    "/organizations/{org_id}/intelligence/ingest",
    response_model=IntelligenceRunResponse,
    status_code=status.HTTP_201_CREATED,
)
async def ingest_intelligence_feed(
    org_id: str,
    req: IngestPayloadRequest,
    auth_ctx: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db_session),
):
    """Ingest external feed payload for organization (RBAC: Admin+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = IntelligenceIngestionService(db)
    run = await svc.ingest_feed_payload(
        org_id=org_id,
        source_name=req.source_name,
        source_type=req.source_type,
        payload_content=req.payload_content,
        actor_id=auth_ctx["user"].id
    )
    return IntelligenceRunResponse(
        id=run.id,
        org_id=run.org_id,
        source_id=run.source_id,
        status=run.status,
        started_at=run.started_at.isoformat() if run.started_at else None,
        completed_at=run.completed_at.isoformat() if run.completed_at else None,
        records_ingested=run.records_ingested,
        records_updated=run.records_updated,
        error_message=run.error_message,
    )


@router.post(
    "/organizations/{org_id}/intelligence/correlate",
    response_model=List[IntelligenceCorrelationResponse],
    status_code=status.HTTP_201_CREATED,
)
async def trigger_intelligence_correlation(
    org_id: str,
    auth_ctx: dict = Depends(require_member),
    db: AsyncSession = Depends(get_db_session),
):
    """Trigger threat & vulnerability correlation run for organization (RBAC: Member+)."""
    verify_tenant_access(org_id, auth_ctx)
    svc = IntelligenceCorrelationService(db)
    correlations = await svc.run_intelligence_correlation(org_id)
    return [
        IntelligenceCorrelationResponse(
            id=c.id,
            org_id=c.org_id,
            intelligence_record_id=c.intelligence_record_id,
            asset_id=c.asset_id,
            exposure_condition_id=c.exposure_condition_id,
            correlation_state=c.correlation_state,
            confidence_score=c.confidence_score,
            confidence_band=c.confidence_band,
            confidence_breakdown=c.confidence_breakdown or {},
            match_reason=c.match_reason,
            rule_version=c.rule_version,
            observed_technology=c.observed_technology,
            observed_version=c.observed_version,
            conflict_status=c.conflict_status,
            conflict_details=c.conflict_details,
            first_correlated_at=c.first_correlated_at.isoformat() if c.first_correlated_at else "",
            last_correlated_at=c.last_correlated_at.isoformat() if c.last_correlated_at else "",
            provenance=c.provenance or {},
        )
        for c in correlations
    ]
