"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { GitFork, Server, RefreshCw, Filter, ShieldCheck, ArrowRight, Layers, Database } from "lucide-react";
import { listRelationships, listAssets, getSession } from "../lib/api";
import { Asset, AssetRelationship } from "../lib/types";
import Badge from "../components/Badge";

export default function AssetGraphPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [relationships, setRelationships] = useState<AssetRelationship[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  // Filters
  const [nodeTypeFilter, setNodeTypeFilter] = useState<string>("all");
  const [depthFilter, setDepthFilter] = useState<number>(2);

  const loadGraphData = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      const orgId = session.orgId;

      const [relRes, astRes] = await Promise.all([
        listRelationships(orgId),
        listAssets(orgId)
      ]);

      setRelationships(relRes.items || []);
      setAssets(astRes.items || []);
      if (astRes.items && astRes.items.length > 0 && !selectedAssetId) {
        setSelectedAssetId(astRes.items[0].id);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load asset graph relationships");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGraphData();
  }, []);

  const assetMap = new Map<string, Asset>(assets.map(a => [a.id, a]));
  const selectedAsset = selectedAssetId ? assetMap.get(selectedAssetId) : null;

  const filteredAssets = assets.filter(a => nodeTypeFilter === "all" || a.asset_type === nodeTypeFilter);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 80px)", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 24px", borderBottom: "1px solid #E5E7EB", backgroundColor: "#FFFFFF" }}>
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Asset Graph
          </h1>
          <p style={{ fontSize: "12px", color: "#4B5563", marginTop: "2px", margin: 0 }}>
            Topology & directed relationships ({assets.length} nodes, {relationships.length} edges)
          </p>
        </div>
        <button 
          onClick={loadGraphData} 
          className="btn-secondary" 
          style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "34px" }}
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} />
          Refresh Graph
        </button>
      </div>

      {/* Three-pane layout */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden", backgroundColor: "#F8F9FB" }}>
        {/* LEFT PANE: 240px Filters */}
        <div style={{ width: "240px", borderRight: "1px solid #E5E7EB", backgroundColor: "#FFFFFF", padding: "16px", display: "flex", flexDirection: "column", gap: "16px" }}>
          <div style={{ fontSize: "13px", fontWeight: 600, color: "#111827", display: "flex", alignItems: "center", gap: "6px" }}>
            <Filter size={14} style={{ color: "#4B5563" }} /> Graph Filters
          </div>

          <div>
            <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>
              Node Type
            </label>
            <select
              className="input-field"
              value={nodeTypeFilter}
              onChange={(e) => setNodeTypeFilter(e.target.value)}
              style={{ width: "100%", height: "34px", fontSize: "12px" }}
            >
              <option value="all">All Types</option>
              <option value="domain">Domain / Subdomain</option>
              <option value="ip">IP Address</option>
              <option value="service">Service</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>
              Graph Traversal Depth
            </label>
            <select
              className="input-field"
              value={depthFilter}
              onChange={(e) => setDepthFilter(Number(e.target.value))}
              style={{ width: "100%", height: "34px", fontSize: "12px" }}
            >
              <option value={1}>1 Hop (Direct)</option>
              <option value={2}>2 Hops (Subdomain → IP → Service)</option>
              <option value={3}>3 Hops (Full Exposure)</option>
            </select>
          </div>

          <div style={{ borderTop: "1px solid #E5E7EB", paddingTop: "12px", marginTop: "auto" }}>
            <div style={{ fontSize: "11px", color: "#9CA3AF" }}>Node Count: {filteredAssets.length}</div>
            <div style={{ fontSize: "11px", color: "#9CA3AF" }}>Active Edges: {relationships.filter(r => r.status === "active").length}</div>
          </div>
        </div>

        {/* CENTER PANE: Flexible Topology List & Canvas */}
        <div style={{ flex: 1, padding: "16px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Visual Topology Diagram Card */}
          <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "16px" }}>
            <div style={{ fontSize: "14px", fontWeight: 600, color: "#111827", marginBottom: "12px" }}>
              Graph Topology Map
            </div>
            <div style={{ backgroundColor: "#F8F9FB", border: "1px dashed #D1D5DB", borderRadius: "6px", padding: "24px", minHeight: "180px", display: "flex", flexWrap: "wrap", gap: "12px", alignItems: "center", justifyContent: "center" }}>
              {filteredAssets.length === 0 ? (
                <div style={{ color: "#9CA3AF", fontSize: "13px" }}>No asset nodes match the active filter.</div>
              ) : (
                filteredAssets.map(ast => (
                  <button
                    key={ast.id}
                    onClick={() => setSelectedAssetId(ast.id)}
                    style={{
                      padding: "8px 12px",
                      borderRadius: "6px",
                      backgroundColor: selectedAssetId === ast.id ? "#EFF6FF" : "#FFFFFF",
                      border: `1px solid ${selectedAssetId === ast.id ? "#2563EB" : "#E5E7EB"}`,
                      color: selectedAssetId === ast.id ? "#2563EB" : "#111827",
                      cursor: "pointer",
                      fontSize: "12px",
                      fontFamily: "monospace",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px"
                    }}
                  >
                    <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: ast.criticality === "critical" ? "#DC2626" : ast.criticality === "high" ? "#D97706" : "#2563EB" }} />
                    {ast.identifier}
                  </button>
                ))
              )}
            </div>
          </div>

          {/* Relationships Table */}
          <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "16px" }}>
            <div style={{ fontSize: "14px", fontWeight: 600, color: "#111827", marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
              <GitFork size={16} style={{ color: "#2563EB" }} /> Directed Graph Edges ({relationships.length})
            </div>

            {relationships.length === 0 ? (
              <div style={{ padding: "24px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
                No directed relationship edges found in graph topology.
              </div>
            ) : (
              <table className="asm-table">
                <thead>
                  <tr>
                    <th>Source Node</th>
                    <th>Edge Type</th>
                    <th>Target Node</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {relationships.map(r => {
                    const sourceAst = assetMap.get(r.source_asset_id);
                    const targetAst = assetMap.get(r.target_asset_id);
                    return (
                      <tr key={r.id}>
                        <td style={{ fontFamily: "monospace", fontSize: "12px" }}>
                          <Link href={`/assets?id=${r.source_asset_id}`} style={{ color: "#2563EB", textDecoration: "none" }}>
                            {sourceAst ? sourceAst.identifier : r.source_asset_id.substring(0, 8)}
                          </Link>
                        </td>
                        <td>
                          <Badge variant="medium">{r.relationship_type.replace(/_/g, " ")}</Badge>
                        </td>
                        <td style={{ fontFamily: "monospace", fontSize: "12px" }}>
                          <Link href={`/assets?id=${r.target_asset_id}`} style={{ color: "#2563EB", textDecoration: "none" }}>
                            {targetAst ? targetAst.identifier : r.target_asset_id.substring(0, 8)}
                          </Link>
                        </td>
                        <td>
                          <Badge variant={r.confidence === "HIGH" ? "verified" : "low"}>{r.confidence}</Badge>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* RIGHT PANE: 320px Selected Node Details */}
        <div style={{ width: "320px", borderLeft: "1px solid #E5E7EB", backgroundColor: "#FFFFFF", padding: "16px", overflowY: "auto" }}>
          <div style={{ fontSize: "13px", fontWeight: 600, color: "#111827", marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
            <Server size={14} style={{ color: "#4B5563" }} /> Selected Node Context
          </div>

          {selectedAsset ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "13px" }}>
              <div>
                <div style={{ fontSize: "11px", color: "#9CA3AF" }}>Identifier</div>
                <div style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600, color: "#111827", wordBreak: "break-all" }}>
                  {selectedAsset.identifier}
                </div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "#9CA3AF" }}>Asset Type</div>
                <div style={{ color: "#4B5563" }}>{selectedAsset.asset_type}</div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "#9CA3AF" }}>Environment</div>
                <div style={{ color: "#4B5563" }}>{selectedAsset.environment}</div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "#9CA3AF" }}>Criticality</div>
                <Badge variant={selectedAsset.criticality}>
                  {selectedAsset.criticality}
                </Badge>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "#9CA3AF" }}>Last Seen</div>
                <div style={{ color: "#4B5563", fontSize: "12px" }}>
                  {new Date(selectedAsset.last_seen_at).toLocaleString()}
                </div>
              </div>

              <div style={{ borderTop: "1px solid #E5E7EB", paddingTop: "12px", marginTop: "8px" }}>
                <Link 
                  href={`/assets?id=${selectedAsset.id}`} 
                  className="btn-primary" 
                  style={{ display: "block", textAlign: "center", textDecoration: "none", fontSize: "12px", padding: "6px 12px" }}
                >
                  View Full Asset Workspace
                </Link>
              </div>
            </div>
          ) : (
            <div style={{ color: "#9CA3AF", fontSize: "12px" }}>
              Select a node from the topology map to inspect node context.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

