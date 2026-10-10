import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.infrastructure.db.models import Asset, AssetRelationship, Observation
from app.application.asset_normalizer import (
    normalize_hostname,
    normalize_ip,
    normalize_service_endpoint,
)

logger = logging.getLogger(__name__)


class AssetResolutionService:
    def __init__(self, db: AsyncSession):
        self.db = db

    def normalize_identifier_by_type(self, asset_type: str, raw_identifier: str) -> str:
        """Helper to normalize an identifier strictly according to asset_type."""
        if asset_type in ("subdomain", "domain", "fqdn"):
            return normalize_hostname(raw_identifier)
        elif asset_type == "ip_address":
            return normalize_ip(raw_identifier)
        elif asset_type == "service":
            if ":" in raw_identifier:
                parts = raw_identifier.rsplit(":", 1)
                return normalize_service_endpoint(parts[0], parts[1])
            else:
                raise ValueError(f"Service identifier must be in ip:port format, got '{raw_identifier}'")
        elif asset_type == "certificate":
            cleaned = raw_identifier.strip().lower()
            if not cleaned.startswith("sha256:"):
                cleaned = f"sha256:{cleaned}"
            return cleaned
        else:
            return raw_identifier.strip()

    async def resolve_or_create_asset(
        self,
        org_id: str,
        asset_type: str,
        raw_identifier: str,
        domain_id: Optional[str] = None
    ) -> Asset:
        """
        Deterministic, tenant-isolated asset identity resolution.
        Uses atomic ON CONFLICT DO UPDATE upsert pattern for race-safe deduplication.
        """
        norm_identifier = self.normalize_identifier_by_type(asset_type, raw_identifier)
        now = datetime.now(timezone.utc)
        asset_id = str(uuid.uuid4())

        stmt = (
            sqlite_insert(Asset)
            .values(
                id=asset_id,
                org_id=org_id,
                domain_id=domain_id,
                asset_type=asset_type,
                identifier=norm_identifier,
                environment="unknown",
                criticality="medium",
                first_seen_at=now,
                last_seen_at=now,
                status="active"
            )
            .on_conflict_do_update(
                index_elements=["org_id", "asset_type", "identifier"],
                set_={"last_seen_at": now}
            )
        )
        await self.db.execute(stmt)

        result = await self.db.execute(
            select(Asset).where(
                Asset.org_id == org_id,
                Asset.asset_type == asset_type,
                Asset.identifier == norm_identifier
            )
        )
        return result.scalars().one()

    async def resolve_or_create_relationship(
        self,
        org_id: str,
        source_asset_id: str,
        target_asset_id: str,
        relationship_type: str,
        confidence: str = "HIGH",
        evidence: Optional[Dict[str, Any]] = None
    ) -> AssetRelationship:
        """
        Deterministic, tenant-isolated relationship edge resolution.
        Validates source and target belong to org_id.
        Uses atomic ON CONFLICT DO UPDATE upsert pattern for race-safe deduplication.
        """
        source_result = await self.db.execute(select(Asset).where(Asset.id == source_asset_id, Asset.org_id == org_id))
        source_asset = source_result.scalars().first()

        target_result = await self.db.execute(select(Asset).where(Asset.id == target_asset_id, Asset.org_id == org_id))
        target_asset = target_result.scalars().first()

        if not source_asset or not target_asset:
            raise ValueError(f"Cross-tenant or invalid relationship attempted for org '{org_id}'")

        now = datetime.now(timezone.utc)
        rel_id = str(uuid.uuid4())

        stmt = (
            sqlite_insert(AssetRelationship)
            .values(
                id=rel_id,
                org_id=org_id,
                source_asset_id=source_asset_id,
                target_asset_id=target_asset_id,
                relationship_type=relationship_type,
                confidence=confidence,
                evidence=evidence,
                first_seen_at=now,
                last_seen_at=now,
                status="active"
            )
            .on_conflict_do_update(
                index_elements=["org_id", "source_asset_id", "target_asset_id", "relationship_type"],
                set_={"last_seen_at": now, "evidence": evidence}
            )
        )
        await self.db.execute(stmt)

        result = await self.db.execute(
            select(AssetRelationship).where(
                AssetRelationship.org_id == org_id,
                AssetRelationship.source_asset_id == source_asset_id,
                AssetRelationship.target_asset_id == target_asset_id,
                AssetRelationship.relationship_type == relationship_type
            )
        )
        return result.scalars().one()

    async def resolve_observations_for_scan(
        self,
        scan_id: str,
        org_id: str,
        domain_id: Optional[str],
        observations: List[Observation]
    ) -> List[Asset]:
        """
        Processes a list of persisted Observation objects from a scan execution:
        - Resolves raw observations into canonical Asset nodes
        - Sets observation.asset_id for traceability
        - Constructs directed AssetRelationship edges with explicit evidence provenance
        """
        resolved_assets: List[Asset] = []

        for obs in observations:
            obs_type = obs.observation_type
            target = obs.target
            raw = obs.raw_data or {}
            provenance = {
                "scan_id": scan_id,
                "observation_id": obs.id,
                "observed_at": obs.observed_at.isoformat() if obs.observed_at else None,
            }

            if obs_type == "dns_record":
                # Subdomain / FQDN Asset
                try:
                    sub_asset = await self.resolve_or_create_asset(
                        org_id=org_id,
                        asset_type="subdomain",
                        raw_identifier=target,
                        domain_id=domain_id
                    )
                    obs.asset_id = sub_asset.id
                    resolved_assets.append(sub_asset)

                    # Resolved IPs -> IP Address Assets & resolves_to Edges
                    resolved_ips = raw.get("resolved_ips", [])
                    for ip_str in resolved_ips:
                        try:
                            ip_asset = await self.resolve_or_create_asset(
                                org_id=org_id,
                                asset_type="ip_address",
                                raw_identifier=ip_str,
                                domain_id=domain_id
                            )
                            resolved_assets.append(ip_asset)

                            await self.resolve_or_create_relationship(
                                org_id=org_id,
                                source_asset_id=sub_asset.id,
                                target_asset_id=ip_asset.id,
                                relationship_type="resolves_to",
                                confidence="HIGH",
                                evidence={**provenance, "reason": "Observed DNS A/AAAA record"}
                            )
                        except ValueError as e:
                            logger.warning(f"Skipping invalid IP '{ip_str}' in DNS record observation: {e}")
                except ValueError as e:
                    logger.warning(f"Skipping invalid hostname target '{target}' in DNS record: {e}")

            elif obs_type == "open_port":
                # Target format ip:port
                if ":" in target:
                    ip_part, port_part = target.rsplit(":", 1)
                    try:
                        ip_asset = await self.resolve_or_create_asset(
                            org_id=org_id,
                            asset_type="ip_address",
                            raw_identifier=ip_part,
                            domain_id=domain_id
                        )
                        resolved_assets.append(ip_asset)

                        svc_asset = await self.resolve_or_create_asset(
                            org_id=org_id,
                            asset_type="service",
                            raw_identifier=target,
                            domain_id=domain_id
                        )
                        obs.asset_id = svc_asset.id
                        resolved_assets.append(svc_asset)

                        await self.resolve_or_create_relationship(
                            org_id=org_id,
                            source_asset_id=ip_asset.id,
                            target_asset_id=svc_asset.id,
                            relationship_type="runs_service",
                            confidence="HIGH",
                            evidence={**provenance, "reason": "Observed open TCP port"}
                        )
                    except ValueError as e:
                        logger.warning(f"Skipping open_port target '{target}': {e}")

            elif obs_type in ("http_banner", "tech_stack"):
                if ":" in target:
                    try:
                        svc_asset = await self.resolve_or_create_asset(
                            org_id=org_id,
                            asset_type="service",
                            raw_identifier=target,
                            domain_id=domain_id
                        )
                        obs.asset_id = svc_asset.id
                        resolved_assets.append(svc_asset)
                    except ValueError as e:
                        logger.warning(f"Skipping {obs_type} target '{target}': {e}")

            elif obs_type == "tls_cert":
                if ":" in target:
                    try:
                        svc_asset = await self.resolve_or_create_asset(
                            org_id=org_id,
                            asset_type="service",
                            raw_identifier=target,
                            domain_id=domain_id
                        )
                        obs.asset_id = svc_asset.id
                        resolved_assets.append(svc_asset)

                        fp = raw.get("fingerprint_sha256")
                        if fp:
                            cert_asset = await self.resolve_or_create_asset(
                                org_id=org_id,
                                asset_type="certificate",
                                raw_identifier=f"sha256:{fp}",
                                domain_id=domain_id
                            )
                            resolved_assets.append(cert_asset)

                            await self.resolve_or_create_relationship(
                                org_id=org_id,
                                source_asset_id=svc_asset.id,
                                target_asset_id=cert_asset.id,
                                relationship_type="presents_cert",
                                confidence="HIGH",
                                evidence={**provenance, "reason": "TLS certificate presented on service endpoint"}
                            )

                            # SAN domains
                            sans = raw.get("san", [])
                            for san_domain in sans:
                                try:
                                    san_asset = await self.resolve_or_create_asset(
                                        org_id=org_id,
                                        asset_type="subdomain",
                                        raw_identifier=san_domain,
                                        domain_id=domain_id
                                    )
                                    resolved_assets.append(san_asset)

                                    await self.resolve_or_create_relationship(
                                        org_id=org_id,
                                        source_asset_id=cert_asset.id,
                                        target_asset_id=san_asset.id,
                                        relationship_type="associated_with",
                                        confidence="MEDIUM",
                                        evidence={**provenance, "reason": "Certificate Subject Alternative Name (SAN)"}
                                    )
                                except ValueError as e:
                                    logger.warning(f"Skipping invalid SAN hostname '{san_domain}': {e}")
                    except ValueError as e:
                        logger.warning(f"Skipping tls_cert target '{target}': {e}")

        return resolved_assets
