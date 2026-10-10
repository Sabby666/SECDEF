"""Phase 5 Secure Read-Only AI Tools Framework.

Provides controlled, tenant-isolated read-only tool functions for the AI context layer.
Strictly enforces tenant scoping (org_id), schema parameter validation, and execution bounds.
"""
import logging
from typing import Dict, Any, List, Optional, Callable
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.models import (
    Asset, ExposureCondition, Finding, RiskAssessment,
    IntelligenceCorrelation, AuditEvent
)

logger = logging.getLogger(__name__)


class AIToolExecutionError(Exception):
    """Raised when an AI tool execution fails or violates security bounds."""
    pass


class AIToolRegistry:
    """Registry and execution engine for tenant-scoped read-only AI tools."""

    MAX_TOOL_CALLS_PER_REQUEST: int = 5

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_asset_details(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Fetch tenant-scoped asset details."""
        stmt = select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
        res = await self.db.execute(stmt)
        asset = res.scalars().first()
        if not asset:
            return {"status": "not_found", "message": f"Asset {asset_id} not found under org {org_id}"}
        return {
            "id": asset.id,
            "org_id": asset.org_id,
            "asset_type": asset.asset_type,
            "identifier": asset.identifier,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "status": asset.status,
            "created_at": asset.first_seen_at.isoformat() if asset.first_seen_at else None
        }

    async def get_exposure_summary(self, org_id: str, exposure_id: Optional[str] = None, asset_id: Optional[str] = None) -> Dict[str, Any]:
        """Fetch tenant-scoped exposure condition summary."""
        stmt = select(ExposureCondition).where(ExposureCondition.org_id == org_id)
        if exposure_id:
            stmt = stmt.where(ExposureCondition.id == exposure_id)
        if asset_id:
            stmt = stmt.where(ExposureCondition.primary_asset_id == asset_id)

        res = await self.db.execute(stmt)
        conditions = res.scalars().all()
        return {
            "count": len(conditions),
            "exposures": [
                {
                    "id": c.id,
                    "condition_type": c.condition_type,
                    "priority_band": c.priority_band,
                    "status": c.status,
                    "primary_asset_id": c.primary_asset_id
                } for c in conditions[:10]
            ]
        }

    async def get_risk_assessment(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Fetch tenant-scoped risk assessment."""
        stmt = select(RiskAssessment).where(RiskAssessment.org_id == org_id, RiskAssessment.asset_id == asset_id)
        res = await self.db.execute(stmt)
        risk = res.scalars().first()
        if not risk:
            return {"status": "not_found", "message": f"No risk assessment found for asset {asset_id}"}
        return {
            "id": risk.id,
            "org_id": risk.org_id,
            "asset_id": risk.asset_id,
            "risk_score": risk.risk_score,
            "risk_band": risk.risk_band,
            "risk_model_version": risk.risk_model_version,
            "explanation": risk.explanation
        }

    async def get_finding_details(self, org_id: str, finding_id: str) -> Dict[str, Any]:
        """Fetch tenant-scoped finding details."""
        stmt = select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id)
        res = await self.db.execute(stmt)
        finding = res.scalars().first()
        if not finding:
            return {"status": "not_found", "message": f"Finding {finding_id} not found"}
        return {
            "id": finding.id,
            "org_id": finding.org_id,
            "asset_id": finding.asset_id,
            "title": finding.title,
            "status": finding.status,
            "created_at": finding.created_at.isoformat() if finding.created_at else None
        }

    async def get_intelligence_correlation(self, org_id: str, correlation_id: Optional[str] = None, asset_id: Optional[str] = None) -> Dict[str, Any]:
        """Fetch tenant-scoped intelligence correlations."""
        stmt = select(IntelligenceCorrelation).where(IntelligenceCorrelation.org_id == org_id)
        if correlation_id:
            stmt = stmt.where(IntelligenceCorrelation.id == correlation_id)
        if asset_id:
            stmt = stmt.where(IntelligenceCorrelation.asset_id == asset_id)

        res = await self.db.execute(stmt)
        corrs = res.scalars().all()
        return {
            "count": len(corrs),
            "correlations": [
                {
                    "id": c.id,
                    "asset_id": c.asset_id,
                    "intelligence_record_id": c.intelligence_record_id,
                    "correlation_state": c.correlation_state,
                    "confidence_score": c.confidence_score,
                    "confidence_band": c.confidence_band,
                    "observed_technology": c.observed_technology,
                    "observed_version": c.observed_version,
                    "match_reason": c.match_reason
                } for c in corrs[:10]
            ]
        }

    async def execute_tool(self, org_id: str, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute named read-only tool enforcing tenant scoping and parameter bounds."""
        if not org_id:
            raise AIToolExecutionError("Tool execution missing required tenant org_id")

        if tool_name == "get_asset_details":
            asset_id = arguments.get("asset_id")
            if not asset_id or not isinstance(asset_id, str):
                raise AIToolExecutionError("Tool get_asset_details requires string asset_id")
            return await self.get_asset_details(org_id, asset_id)

        elif tool_name == "get_exposure_summary":
            return await self.get_exposure_summary(org_id, exposure_id=arguments.get("exposure_id"), asset_id=arguments.get("asset_id"))

        elif tool_name == "get_risk_assessment":
            asset_id = arguments.get("asset_id")
            if not asset_id or not isinstance(asset_id, str):
                raise AIToolExecutionError("Tool get_risk_assessment requires string asset_id")
            return await self.get_risk_assessment(org_id, asset_id)

        elif tool_name == "get_finding_details":
            finding_id = arguments.get("finding_id")
            if not finding_id or not isinstance(finding_id, str):
                raise AIToolExecutionError("Tool get_finding_details requires string finding_id")
            return await self.get_finding_details(org_id, finding_id)

        elif tool_name == "get_intelligence_correlation":
            return await self.get_intelligence_correlation(org_id, correlation_id=arguments.get("correlation_id"), asset_id=arguments.get("asset_id"))

        else:
            raise AIToolExecutionError(f"Unknown or unauthorized tool: {tool_name}")
