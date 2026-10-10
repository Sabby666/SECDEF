"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ShieldAlert, ArrowLeft, RefreshCw, Cpu, AlertTriangle } from "lucide-react";
import { getRiskAssessment, getSession } from "../../lib/api";
import { RiskAssessment, RiskFactorDetail } from "../../lib/types";
import Badge from "../../components/Badge";

export default function RiskDetailPage() {
  const params = useParams();
  const assessmentId = params.id as string;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assessment, setAssessment] = useState<RiskAssessment | null>(null);

  const loadAssessmentDetail = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      const res = await getRiskAssessment(session.orgId, assessmentId);
      setAssessment(res);
    } catch (err: any) {
      setError(err.message || "Failed to load risk assessment detail");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (assessmentId) {
      loadAssessmentDetail();
    }
  }, [assessmentId]);

  if (loading) {
    return <div style={{ padding: "32px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading risk assessment details...</div>;
  }

  if (!assessment) {
    return (
      <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
        <div style={{ marginBottom: "16px", padding: "10px 14px", backgroundColor: "#FEF2F2", border: "1px solid #FCA5A5", color: "#DC2626", borderRadius: "6px", fontSize: "13px" }}>
          {error || "Risk assessment record not found"}
        </div>
        <Link href="/risk" className="btn-secondary" style={{ fontSize: "13px", display: "inline-flex", alignItems: "center", gap: "6px", textDecoration: "none" }}>
          <ArrowLeft size={14} /> Return to Risk Engine
        </Link>
      </div>
    );
  }

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      <div style={{ marginBottom: "16px" }}>
        <Link href="/risk" style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "#4B5563", textDecoration: "none" }}>
          <ArrowLeft size={14} /> Back to Risk Engine
        </Link>
      </div>

      {/* Identity Banner */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "20px", marginBottom: "24px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "8px" }}>
          <Badge variant={assessment.risk_band === "CRITICAL" ? "critical" : assessment.risk_band === "HIGH" ? "high" : "medium"}>
            {assessment.risk_band}
          </Badge>
          <span style={{ fontSize: "24px", fontWeight: 700, color: "#111827", fontFamily: "monospace" }}>
            Score: {assessment.risk_score.toFixed(1)} / 100
          </span>
        </div>
        <p style={{ fontSize: "14px", color: "#4B5563", margin: "4px 0 12px 0" }}>{assessment.explanation}</p>
        <div style={{ fontSize: "12px", color: "#9CA3AF", fontFamily: "monospace" }}>
          Assessment ID: {assessment.id} • Model Version: {assessment.risk_model_version} • Confidence: {(assessment.confidence * 100).toFixed(0)}%
        </div>
      </div>

      {/* Factor Breakdown Table */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden", marginBottom: "24px" }}>
        <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
          Risk Factor Contribution Breakdown ({assessment.factor_breakdown.length} Factors)
        </div>

        {assessment.factor_breakdown.length === 0 ? (
          <div style={{ padding: "32px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            No factor breakdown data available.
          </div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Factor Name</th>
                <th>Impact (+/-)</th>
                <th>Value</th>
                <th>Source Domain</th>
                <th>Uncertainty Flag</th>
              </tr>
            </thead>
            <tbody>
              {assessment.factor_breakdown.map((f, idx) => (
                <tr key={idx}>
                  <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600, color: "#111827" }}>
                    {f.factor_name}
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 700, color: f.contribution > 0 ? "#DC2626" : "#16A34A" }}>
                    {f.contribution > 0 ? `+${f.contribution.toFixed(1)}` : f.contribution.toFixed(1)}
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>
                    {JSON.stringify(f.factor_value)}
                  </td>
                  <td>
                    <Badge variant="medium">{f.source_type}</Badge>
                  </td>
                  <td>
                    {f.uncertainty_flag ? (
                      <Badge variant="high">{f.uncertainty_flag}</Badge>
                    ) : (
                      <span style={{ color: "#9CA3AF", fontSize: "12px", fontStyle: "italic" }}>Certain</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Context Snapshot JSON view */}
      <div style={{ backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "16px" }}>
        <div style={{ fontSize: "14px", fontWeight: 600, color: "#111827", marginBottom: "8px" }}>
          Evaluated Context Snapshot
        </div>
        <pre style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "4px", padding: "12px", fontSize: "12px", fontFamily: "monospace", overflowX: "auto", margin: 0 }}>
          {JSON.stringify(assessment.context_snapshot, null, 2)}
        </pre>
      </div>
    </div>
  );
}

