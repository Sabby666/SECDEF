"""Phase 3 Exposure Graph & Bounded Path Traversal Service.

Implements graph traversal over asset relationships with strict tenant isolation,
cycle prevention, depth bounds, and node/edge resource limits.
"""
import logging
from typing import List, Dict, Any, Set, Tuple, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.db.models import Asset, AssetRelationship, ExposureCondition, ExposurePath
from shared_contracts.enums import ExposurePriorityBand

logger = logging.getLogger(__name__)


class ExposureGraphService:
    """Bounded, tenant-isolated graph traversal service for exposure path correlation."""

    MAX_TRAVERSAL_DEPTH: int = 5
    MAX_NODES_PER_TRAVERSAL: int = 50
    MAX_EDGES_PROCESSED: int = 200
    MAX_RETURNED_PATHS: int = 20

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_org_asset(self, org_id: str, asset_id: str) -> Optional[Asset]:
        """Fetch asset strictly scoped to org_id."""
        stmt = select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
        res = await self.db.execute(stmt)
        return res.scalars().first()

    async def find_exposure_paths(
        self,
        org_id: str,
        condition: ExposureCondition,
        start_asset_id: Optional[str] = None
    ) -> List[ExposurePath]:
        """Find deterministic exposure paths starting from primary asset or specified asset.

        Enforces:
        - Strict org_id filtering on all database queries
        - Cycle detection via visited node set
        - MAX_TRAVERSAL_DEPTH = 5
        - MAX_NODES_PER_TRAVERSAL = 50
        - MAX_EDGES_PROCESSED = 200
        - MAX_RETURNED_PATHS = 20
        """
        root_id = start_asset_id or condition.primary_asset_id
        root_asset = await self.get_org_asset(org_id, root_id)
        if not root_asset:
            return []

        # Fetch all active relationships for org_id
        rel_stmt = select(AssetRelationship).where(
            AssetRelationship.org_id == org_id,
            AssetRelationship.status == "active"
        )
        rel_res = await self.db.execute(rel_stmt)
        relationships = rel_res.scalars().all()

        # Build adjacency graph for tenant
        adj: Dict[str, List[AssetRelationship]] = {}
        edge_count = 0
        for rel in relationships:
            if edge_count >= self.MAX_EDGES_PROCESSED:
                break
            adj.setdefault(rel.source_asset_id, []).append(rel)
            edge_count += 1

        # Fetch all assets for tenant to populate node snapshots quickly
        asset_stmt = select(Asset).where(Asset.org_id == org_id)
        asset_res = await self.db.execute(asset_stmt)
        assets_by_id = {a.id: a for a in asset_res.scalars().all()}

        paths_found: List[List[Tuple[Asset, Optional[AssetRelationship]]]] = []
        nodes_processed = 0

        # DFS traversal
        def dfs(
            current_id: str,
            current_path: List[Tuple[Asset, Optional[AssetRelationship]]],
            visited: Set[str]
        ):
            nonlocal nodes_processed
            if len(paths_found) >= self.MAX_RETURNED_PATHS or nodes_processed >= self.MAX_NODES_PER_TRAVERSAL:
                return

            nodes_processed += 1
            current_asset = assets_by_id.get(current_id)
            if not current_asset:
                return

            out_edges = sorted(adj.get(current_id, []), key=lambda r: (r.target_asset_id, r.id))

            # If path length > 1 (meaning we traversed at least one edge), record path
            if len(current_path) > 1:
                paths_found.append(list(current_path))

            if len(current_path) >= self.MAX_TRAVERSAL_DEPTH:
                return

            for edge in out_edges:
                next_id = edge.target_asset_id
                # Cycle check
                if next_id in visited:
                    continue

                next_asset = assets_by_id.get(next_id)
                if not next_asset:
                    continue

                visited.add(next_id)
                current_path.append((next_asset, edge))

                dfs(next_id, current_path, visited)

                current_path.pop()
                visited.remove(next_id)

        # Initial call
        visited_set = {root_id}
        dfs(root_id, [(root_asset, None)], visited_set)

        created_paths: List[ExposurePath] = []
        for path in paths_found[:self.MAX_RETURNED_PATHS]:
            start_node = path[0][0]
            end_node = path[-1][0]
            
            nodes_snapshot = [
                {
                    "id": a.id,
                    "identifier": a.identifier,
                    "asset_type": a.asset_type,
                    "environment": a.environment,
                    "criticality": a.criticality
                }
                for a, _ in path
            ]

            edges_snapshot = [
                {
                    "id": rel.id,
                    "source_asset_id": rel.source_asset_id,
                    "target_asset_id": rel.target_asset_id,
                    "relationship_type": rel.relationship_type,
                    "confidence": rel.confidence
                }
                for _, rel in path if rel is not None
            ]

            path_explanation = (
                f"Exposure chain from {start_node.asset_type} ({start_node.identifier}) "
                f"to {end_node.asset_type} ({end_node.identifier}) spanning {len(edges_snapshot)} relationship hop(s)."
            )

            exp_path = ExposurePath(
                org_id=org_id,
                condition_id=condition.id,
                start_asset_id=start_node.id,
                end_asset_id=end_node.id,
                path_length=len(edges_snapshot),
                nodes_snapshot=nodes_snapshot,
                edges_snapshot=edges_snapshot,
                explanation=path_explanation
            )
            self.db.add(exp_path)
            created_paths.append(exp_path)

        await self.db.flush()
        return created_paths
