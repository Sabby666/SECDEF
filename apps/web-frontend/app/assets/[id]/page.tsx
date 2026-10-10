"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { 
  Server, Shield, Cpu, GitFork, ArrowLeft, Save, 
  CheckCircle2, AlertTriangle, UserCheck
} from "lucide-react";
import { 
  getAsset, getAssetRelationships, updateAssetContext, 
  resolveContext, getSession 
} from "../../lib/api";
import { 
  Asset, AssetRelationship, ContextResolutionResponse, UserRole 
} from "../../lib/types";
import { Badge } from "../../components/ui/Badge";
import { Card } from "../../components/ui/Card";
import { Table, Column } from "../../components/ui/Table";
import { ErrorAlert } from "../../components/ui/ErrorAlert";
import { RBACGate } from "../../components/ui/RBACGate";
import { EvidenceViewer } from "../../components/ui/EvidenceViewer";

export default function AssetDetailPage() {
  const params = useParams();
  const router = useRouter();
  const assetId = params.id as string;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [asset, setAsset] = useState<Asset | null>(null);
  const [relationships, setRelationships] = useState<AssetRelationship[]>([]);
  const [resolution, setResolution] = useState<ContextResolutionResponse | null>(null);
  const [role, setRole] = useState<UserRole>("ADMIN");

  // Context Edit Form State
  const [ownerTeam, setOwnerTeam] = useState("");
  const [environment, setEnvironment] = useState("");
  const [criticality, setCriticality] = useState("");
  const [businessPurpose, setBusinessPurpose] = useState("");
  const [expectedExposure, setExpectedExposure] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const loadAssetDetails = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      setRole(session.userRole);
      const orgId = session.orgId;

      const [ast, relsRes] = await Promise.all([
        getAsset(orgId, assetId),
        getAssetRelationships(orgId, assetId)
      ]);

      setAsset(ast);
      setRelationships(relsRes.items || []);
      setOwnerTeam(ast.owner_team || "");
      setEnvironment(ast.environment || "unknown");
      setCriticality(ast.criticality || "medium");

      // Resolve expected state trace
      try {
        const res = await resolveContext(orgId, ast.asset_type, ast.identifier);
        setResolution(res);
      } catch (e) {
        // non-blocking
      }
    } catch (err: any) {
      setError(err.message || "Failed to load asset details");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (assetId) {
      loadAssetDetails();
    }
  }, [assetId]);

  const handleContextSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSaveSuccess(false);
    setError(null);
    try {
      const session = getSession();
      await updateAssetContext(session.orgId, assetId, {
        owner_team: ownerTeam,
        environment,
        criticality,
        business_purpose: businessPurpose,
        expected_exposure: expectedExposure
      });
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      await loadAssetDetails();
    } catch (err: any) {
      setError(err.message || "Failed to update asset context");
    } finally {
      setSaving(false);
    }
  };

  const relColumns: Column<AssetRelationship>[] = [
    {
      key: "relationship_type",
      header: "Relationship Type",
      render: (r) => <Badge variant="INFO" label={r.relationship_type.replace(/_/g, " ")} />
    },
    {
      key: "target",
      header: "Connected Asset ID",
      render: (r) => (
        <span className="font-mono text-xs text-slate-200">
          {r.source_asset_id === assetId ? r.target_asset_id : r.source_asset_id}
        </span>
      )
    },
    {
      key: "confidence",
      header: "Confidence",
      render: (r) => <Badge variant={r.confidence} />
    },
    {
      key: "last_seen_at",
      header: "Last Observed",
      render: (r) => <span className="text-slate-400 text-xs">{new Date(r.last_seen_at).toLocaleString()}</span>
    }
  ];

  if (loading) {
    return <div className="p-8 text-center text-slate-400 font-mono text-sm">Loading asset details...</div>;
  }

  if (!asset) {
    return (
      <div className="p-8">
        <ErrorAlert message={error || "Asset not found"} />
        <Link href="/assets" className="text-xs font-mono text-sky-400 hover:underline">
          ← Return to Asset Inventory
        </Link>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Back Button */}
      <div>
        <Link href="/assets" className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1.5 w-fit">
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Asset Inventory</span>
        </Link>
      </div>

      {/* Asset Identity Banner */}
      <Card>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <Badge variant={asset.asset_type} />
              <h1 className="mono" style={{ fontSize: "20px", fontWeight: 700, color: "var(--text-primary)" }}>{asset.identifier}</h1>
            </div>
            <div className="mono" style={{ fontSize: "12px", color: "var(--text-tertiary)", marginTop: "6px" }}>
              Asset ID: {asset.id} • Org ID: {asset.org_id}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Badge variant={asset.environment} />
            <Badge variant={asset.criticality} />
            <Badge variant={asset.status} />
          </div>
        </div>
      </Card>

      {error && <ErrorAlert message={error} />}

      {/* Grid: Context Editor & Context Resolution Trace */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
        {/* Context Editor (Member+) */}
        <Card title="Organizational Context Metadata" subtitle="Human context assertions provided by security operations team">
          <RBACGate requiredRole="MEMBER" currentRole={role}>
            <form onSubmit={handleContextSave} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label className="mono" style={{ fontSize: "11.5px", color: "var(--text-secondary)", display: "block", marginBottom: "4px" }}>Owner Team</label>
                <input
                  type="text"
                  value={ownerTeam}
                  onChange={(e) => setOwnerTeam(e.target.value)}
                  placeholder="e.g. Platform Engineering / SecOps"
                  className="asm-input"
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <div>
                  <label className="mono" style={{ fontSize: "11.5px", color: "var(--text-secondary)", display: "block", marginBottom: "4px" }}>Environment</label>
                  <select
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                    className="asm-input"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                    <option value="testing">Testing</option>
                    <option value="unknown">Unknown</option>
                  </select>
                </div>

                <div>
                  <label className="mono" style={{ fontSize: "11.5px", color: "var(--text-secondary)", display: "block", marginBottom: "4px" }}>Criticality</label>
                  <select
                    value={criticality}
                    onChange={(e) => setCriticality(e.target.value)}
                    className="asm-input"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="unknown">Unknown</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="mono" style={{ fontSize: "11.5px", color: "var(--text-secondary)", display: "block", marginBottom: "4px" }}>Business Purpose</label>
                <input
                  type="text"
                  value={businessPurpose}
                  onChange={(e) => setBusinessPurpose(e.target.value)}
                  placeholder="e.g. Public API Gateway for Customer Mobile App"
                  className="asm-input"
                />
              </div>

              <div>
                <label className="mono" style={{ fontSize: "11.5px", color: "var(--text-secondary)", display: "block", marginBottom: "4px" }}>Expected Exposure</label>
                <input
                  type="text"
                  value={expectedExposure}
                  onChange={(e) => setExpectedExposure(e.target.value)}
                  placeholder="e.g. Intentionally Public HTTP Service"
                  className="asm-input"
                />
              </div>

              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: "6px" }}>
                {saveSuccess && (
                  <span className="mono" style={{ fontSize: "12px", color: "var(--success-text)", display: "flex", alignItems: "center", gap: "4px" }}>
                    <CheckCircle2 style={{ width: "14px", height: "14px" }} />
                    Context updated successfully!
                  </span>
                )}
                <button type="submit" disabled={saving} className="asm-btn asm-btn-primary" style={{ marginLeft: "auto" }}>
                  <Save style={{ width: "14px", height: "14px" }} />
                  <span>{saving ? "Saving..." : "Update Context"}</span>
                </button>
              </div>
            </form>
          </RBACGate>
        </Card>

        {/* Expected State Resolution Trace */}
        <Card title="Expected State Resolution Trace" subtitle="Evaluation of organizational memory & inheritance rules">
          {resolution ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", backgroundColor: "var(--bg-secondary)", borderRadius: "5px", border: "1px solid var(--border-primary)" }}>
                <span className="mono" style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Expected Exposure State:</span>
                <Badge variant={resolution.expected_state} />
              </div>

              <div style={{ fontSize: "12.5px", color: "var(--text-secondary)" }}>
                <div>Resolution Status: <span className="mono" style={{ color: "var(--text-primary)", fontWeight: 600 }}>{resolution.resolution_status}</span></div>
                <div>Conflict Flag: <span className="mono" style={{ color: "var(--text-primary)", fontWeight: 600 }}>{resolution.conflict_detected ? "YES" : "NO"}</span></div>
              </div>

              <div className="mono" style={{ fontSize: "12px", color: "var(--text-primary)", fontWeight: 600, marginTop: "6px" }}>Provenance Explanation Trace ({resolution.provenance.length}):</div>
              {resolution.provenance.length === 0 ? (
                <div className="mono" style={{ fontSize: "12px", color: "var(--text-tertiary)", fontStyle: "italic" }}>No inheritance rules matched. Default baseline applied.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {resolution.provenance.map((p, idx) => (
                    <div key={idx} className="mono" style={{ padding: "8px 10px", backgroundColor: "var(--bg-secondary)", border: "1px solid var(--border-primary)", borderRadius: "4px", fontSize: "12px" }}>
                      <div style={{ color: "var(--accent)", fontWeight: 600 }}>{p.claim_type} ({p.scope_level})</div>
                      <div style={{ color: "var(--text-secondary)", marginTop: "2px" }}>{p.reason}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="mono" style={{ fontSize: "12px", color: "var(--text-tertiary)", fontStyle: "italic" }}>No context resolution trace available.</div>
          )}
        </Card>
      </div>

      {/* Asset Relationships Section */}
      <Card title={`Directed Asset Relationships (${relationships.length})`} subtitle="Connected nodes in Asset Graph">
        <Table
          columns={relColumns}
          data={relationships}
          keyExtractor={(r) => r.id}
          emptyMessage="No directed relationships recorded for this asset."
        />
      </Card>
    </div>
  );
}
