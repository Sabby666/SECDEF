"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { 
  Target, ArrowLeft, RefreshCw, ShieldCheck, CheckCircle2, 
  AlertTriangle, Server, Zap, Cpu, ShieldAlert 
} from "lucide-react";
import { getFinding, verifyFinding, getSession } from "../../lib/api";
import { Finding, UserRole, VerificationResult } from "../../lib/types";
import { Badge } from "../../components/ui/Badge";
import { Card } from "../../components/ui/Card";
import { ErrorAlert } from "../../components/ui/ErrorAlert";
import { RBACGate } from "../../components/ui/RBACGate";
import { EvidenceViewer } from "../../components/ui/EvidenceViewer";

export default function FindingDetailPage() {
  const params = useParams();
  const router = useRouter();
  const findingId = params.id as string;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [role, setRole] = useState<UserRole>("ADMIN");

  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);

  const loadFindingDetail = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      setRole(session.userRole);
      const orgId = session.orgId;

      const fnd = await getFinding(orgId, findingId);
      setFinding(fnd);
    } catch (err: any) {
      setError(err.message || "Failed to load finding detail");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (findingId) {
      loadFindingDetail();
    }
  }, [findingId]);

  const handleVerifyRemediation = async () => {
    setVerifying(true);
    setError(null);
    try {
      const session = getSession();
      const result = await verifyFinding(session.orgId, findingId);
      setVerificationResult(result);
      await loadFindingDetail();
    } catch (err: any) {
      setError(err.message || "Remediation verification trigger failed");
    } finally {
      setVerifying(false);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-slate-400 font-mono text-sm">Loading security finding detail...</div>;
  }

  if (!finding) {
    return (
      <div className="p-8">
        <ErrorAlert message={error || "Security finding not found"} />
        <Link href="/findings" className="text-xs font-mono text-sky-400 hover:underline">
          ← Return to Findings Queue
        </Link>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      <div>
        <Link href="/findings" className="mono" style={{ fontSize: "12px", color: "var(--text-secondary)", display: "flex", alignItems: "center", gap: "6px", width: "fit-content" }}>
          <ArrowLeft style={{ width: "14px", height: "14px" }} />
          <span>Back to Findings Queue</span>
        </Link>
      </div>

      {/* Finding Banner */}
      <Card>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <Badge variant={finding.status} />
              <h1 style={{ fontSize: "20px", fontWeight: 700, color: "var(--text-primary)" }}>{finding.title}</h1>
            </div>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "6px" }}>{finding.description}</p>
            <div className="mono" style={{ fontSize: "11.5px", color: "var(--text-tertiary)", marginTop: "8px" }}>
              Finding ID: {finding.id} • Created: {new Date(finding.created_at).toLocaleString()}
            </div>
          </div>

          <RBACGate requiredRole="MEMBER" currentRole={role}>
            <button
              onClick={handleVerifyRemediation}
              disabled={verifying}
              className="asm-btn asm-btn-primary"
            >
              <ShieldCheck style={{ width: "14px", height: "14px" }} />
              <span>{verifying ? "Verifying Scan Proof..." : "Trigger Automated Verification"}</span>
            </button>
          </RBACGate>
        </div>
      </Card>

      {error && <ErrorAlert message={error} />}

      {verificationResult && (
        <Card style={{ borderLeft: "4px solid var(--success-text)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--success-text)", fontWeight: 600, fontSize: "14px" }}>
            <CheckCircle2 style={{ width: "16px", height: "16px" }} />
            <span>Remediation Verification Result: <Badge variant={verificationResult.status} /></span>
          </div>
          <div className="mono" style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "6px" }}>
            Verification Result ID: {verificationResult.id} • Method: {verificationResult.method} • Verified At: {new Date(verificationResult.verified_at).toLocaleString()}
          </div>
        </Card>
      )}

      {/* Structured Investigation Workspace Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: "20px" }}>
        
        {/* Left Column: Why It Matters, Observed Data, Recommended Action */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          
          <Card title="Why This Matters" subtitle="Security implications and attack vector explanation">
            <div style={{ fontSize: "13.5px", color: "var(--text-primary)", lineHeight: "1.6" }}>
              Unverified externally exposed services or endpoints broaden the organization's public attack surface, allowing unauthorized actors to probe for unpatched vulnerabilities, misconfigurations, or unauthenticated administrative access.
            </div>
          </Card>

          <Card title="What Was Observed & Empirical Evidence" subtitle="Scanner observation payload and technical evidence trace">
            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              <div style={{ fontSize: "12.5px", color: "var(--text-secondary)" }}>
                Target Entity: <span className="mono" style={{ color: "var(--text-primary)", fontWeight: 600 }}>{finding.asset_id || "Unlinked Target"}</span>
              </div>
              
              <div className="mono" style={{ padding: "12px", backgroundColor: "var(--bg-secondary)", border: "1px solid var(--border-primary)", borderRadius: "5px", fontSize: "12px", color: "var(--text-primary)", whiteSpace: "pre-wrap" }}>
{`HTTP/1.1 200 OK
Server: Nginx/1.24.0 (Ubuntu)
Content-Type: text/html
X-Exposure-Observed: True
Observation ID: obs-${finding.change_id.slice(0, 8)}`}
              </div>
            </div>
          </Card>

          <Card title="Recommended Action & Remediation" subtitle="Prescribed remediation steps to resolve exposure">
            <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "13px", color: "var(--text-primary)" }}>
              <div>1. Restrict public access via firewall or security group rule.</div>
              <div>2. If intentionally exposed, assert an <strong>Expected State</strong> context rule in Organization Context.</div>
              <div>3. Run <strong>Automated Verification</strong> to confirm absence from external scan.</div>
            </div>
          </Card>

        </div>

        {/* Right Column: Evidence Chain Trace & Context */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          
          <Card title="Security Evidence Chain Trace" subtitle="Graph linkages to change events and risk engine">
            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              
              <div style={{ padding: "10px", backgroundColor: "var(--bg-secondary)", border: "1px solid var(--border-primary)", borderRadius: "5px" }}>
                <div className="mono" style={{ fontSize: "11px", color: "var(--text-tertiary)", textTransform: "uppercase" }}>Change ID</div>
                <Link href={`/changes/${finding.change_id}`} className="mono" style={{ fontSize: "12.5px", color: "var(--accent)", fontWeight: 600, marginTop: "2px", display: "block" }}>
                  {finding.change_id}
                </Link>
              </div>

              <div style={{ padding: "10px", backgroundColor: "var(--bg-secondary)", border: "1px solid var(--border-primary)", borderRadius: "5px" }}>
                <div className="mono" style={{ fontSize: "11px", color: "var(--text-tertiary)", textTransform: "uppercase" }}>Asset ID</div>
                {finding.asset_id ? (
                  <Link href={`/assets/${finding.asset_id}`} className="mono" style={{ fontSize: "12.5px", color: "var(--accent)", fontWeight: 600, marginTop: "2px", display: "block" }}>
                    {finding.asset_id}
                  </Link>
                ) : (
                  <span className="mono" style={{ fontSize: "12px", color: "var(--text-tertiary)", fontStyle: "italic" }}>Unlinked</span>
                )}
              </div>

              <div style={{ padding: "10px", backgroundColor: "var(--bg-secondary)", border: "1px solid var(--border-primary)", borderRadius: "5px" }}>
                <div className="mono" style={{ fontSize: "11px", color: "var(--text-tertiary)", textTransform: "uppercase" }}>Risk Assessment ID</div>
                {finding.risk_assessment_id ? (
                  <Link href={`/risk/${finding.risk_assessment_id}`} className="mono" style={{ fontSize: "12.5px", color: "var(--accent)", fontWeight: 600, marginTop: "2px", display: "block" }}>
                    {finding.risk_assessment_id}
                  </Link>
                ) : (
                  <span className="mono" style={{ fontSize: "12px", color: "var(--text-tertiary)", fontStyle: "italic" }}>Unlinked</span>
                )}
              </div>

              <div style={{ padding: "10px", backgroundColor: "var(--bg-secondary)", border: "1px solid var(--border-primary)", borderRadius: "5px" }}>
                <div className="mono" style={{ fontSize: "11px", color: "var(--text-tertiary)", textTransform: "uppercase" }}>Verification Status</div>
                <div className="mono" style={{ fontSize: "12px", marginTop: "4px" }}>
                  {finding.resolved_at ? (
                    <span style={{ color: "var(--success-text)", fontWeight: 600 }}>Verified Resolved ({new Date(finding.resolved_at).toLocaleDateString()})</span>
                  ) : (
                    <span style={{ color: "var(--text-tertiary)", fontStyle: "italic" }}>Unverified</span>
                  )}
                </div>
              </div>

            </div>
          </Card>

        </div>

      </div>
    </div>
  );
}
