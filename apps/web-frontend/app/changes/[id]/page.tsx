"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { 
  Zap, ArrowLeft, RefreshCw, ShieldAlert, CheckCircle2 
} from "lucide-react";
import { getChange, recalculateRisk, getSession } from "../../lib/api";
import { Change, UserRole, RiskAssessment } from "../../lib/types";
import { Badge } from "../../components/ui/Badge";
import { Card } from "../../components/ui/Card";
import { ErrorAlert } from "../../components/ui/ErrorAlert";
import { RBACGate } from "../../components/ui/RBACGate";
import { EvidenceViewer } from "../../components/ui/EvidenceViewer";

export default function ChangeDetailPage() {
  const params = useParams();
  const router = useRouter();
  const changeId = params.id as string;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [change, setChange] = useState<Change | null>(null);
  const [role, setRole] = useState<UserRole>("ADMIN");

  const [recalculating, setRecalculating] = useState(false);
  const [recalcResult, setRecalcResult] = useState<RiskAssessment | null>(null);

  const loadChangeDetail = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      setRole(session.userRole);
      const orgId = session.orgId;

      const chg = await getChange(orgId, changeId);
      setChange(chg);
    } catch (err: any) {
      setError(err.message || "Failed to load change details");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (changeId) {
      loadChangeDetail();
    }
  }, [changeId]);

  const handleRecalculateRisk = async () => {
    setRecalculating(true);
    setError(null);
    try {
      const session = getSession();
      const res = await recalculateRisk(session.orgId, {
        change_id: changeId,
        risk_model_version: "v1"
      });
      setRecalcResult(res);
    } catch (err: any) {
      setError(err.message || "Risk recalculation failed");
    } finally {
      setRecalculating(false);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-slate-400 font-mono text-sm">Loading change observation details...</div>;
  }

  if (!change) {
    return (
      <div className="p-8">
        <ErrorAlert message={error || "Change observation not found"} />
        <Link href="/changes" className="text-xs font-mono text-sky-400 hover:underline">
          ← Return to Change Intelligence Timeline
        </Link>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      <div>
        <Link href="/changes" className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1.5 w-fit">
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Change Intelligence Timeline</span>
        </Link>
      </div>

      {/* Change Identity Card */}
      <Card>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <Badge variant={change.change_type} label={change.change_type.replace(/_/g, " ")} />
              <h1 className="font-mono text-xl font-bold text-slate-100">{change.entity_identifier}</h1>
            </div>
            <div style={{ fontSize: "12px", color: "var(--text-tertiary)", fontFamily: "var(--font-mono)", marginTop: "6px" }}>
              Change ID: {change.id} • Entity Type: {change.entity_type} • Detected: {new Date(change.detected_at).toLocaleString()}
            </div>
          </div>

          <RBACGate requiredRole="MEMBER" currentRole={role}>
            <button
              onClick={handleRecalculateRisk}
              disabled={recalculating}
              className="asm-btn asm-btn-primary"
            >
              <ShieldAlert style={{ width: "14px", height: "14px" }} />
              <span>{recalculating ? "Evaluating..." : "Recalculate Contextual Risk"}</span>
            </button>
          </RBACGate>
        </div>
      </Card>

      {error && <ErrorAlert message={error} />}

      {recalcResult && (
        <Card className="border-l-4 border-l-emerald-500">
          <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--success)", fontWeight: 600, fontSize: "14px" }}>
            <CheckCircle2 className="w-4 h-4" />
            <span>Deterministic Risk Assessment Recalculated!</span>
          </div>
          <div className="text-xs font-mono text-slate-300 mt-2">
            Assessment ID: {recalcResult.id} • Band: <Badge variant={recalcResult.risk_band} /> • Score: <span className="font-bold">{recalcResult.risk_score.toFixed(1)}</span>
          </div>
          <div className="text-xs text-slate-400 mt-1">{recalcResult.explanation}</div>
        </Card>
      )}

      {/* State Diff Section */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
        <Card title="Previous State Snapshot" subtitle={`From Scan ID: ${change.previous_scan_id || "None (Baseline)"}`}>
          <EvidenceViewer data={change.previous_state} title="Previous State Payload" defaultExpanded={true} />
        </Card>

        <Card title="Current State Snapshot" subtitle={`From Scan ID: ${change.current_scan_id}`}>
          <EvidenceViewer data={change.current_state} title="Current State Payload" defaultExpanded={true} />
        </Card>
      </div>

      {/* Evidence Payload */}
      <Card title="Change Evidence Payload" subtitle="Delta metadata produced by scan comparison engine">
        <EvidenceViewer data={change.evidence} title="Delta Evidence" defaultExpanded={true} />
      </Card>
    </div>
  );
}
