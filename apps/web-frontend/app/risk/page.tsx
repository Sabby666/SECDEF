"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { ShieldAlert, Filter, ArrowRight, RefreshCw, Cpu } from "lucide-react";
import { listRiskAssessments, getSession } from "../lib/api";
import { RiskAssessment } from "../lib/types";
import Badge from "../components/Badge";

export default function RiskBrowserPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assessments, setAssessments] = useState<RiskAssessment[]>([]);

  const [bandFilter, setBandFilter] = useState<string>("");

  const loadRiskData = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      const res = await listRiskAssessments(session.orgId, {
        risk_band: bandFilter || undefined,
        limit: 50
      });
      setAssessments(res.items || []);
    } catch (err: any) {
      setError(err.message || "Failed to load risk assessments");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRiskData();
  }, [bandFilter]);

  const topAssessment = assessments.length > 0 ? assessments[0] : null;

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Page Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Risk Engine
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Deterministic risk derivation based on exposure, blindspots, and organizational context.
          </p>
        </div>
        <button 
          onClick={loadRiskData} 
          className="btn-secondary"
          style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} />
          Refresh
        </button>
      </div>

      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 14px", backgroundColor: "#FEF2F2", border: "1px solid #FCA5A5", color: "#DC2626", borderRadius: "6px", fontSize: "13px" }}>
          {error}
        </div>
      )}

      {/* Overall Risk & Derivation Section */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "16px", marginBottom: "24px" }}>
        {/* Overall Score */}
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "20px" }}>
          <div style={{ fontSize: "12px", color: "#9CA3AF" }}>Overall Attack Surface Risk</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: "10px", marginTop: "8px" }}>
            <span style={{ fontSize: "36px", fontWeight: 700, color: "#111827", fontFamily: "monospace" }}>
              {topAssessment ? topAssessment.risk_score.toFixed(0) : "0"}
            </span>
            <span style={{ fontSize: "16px", color: "#9CA3AF" }}>/ 100</span>
            <Badge variant={topAssessment ? (topAssessment.risk_band === "CRITICAL" ? "critical" : topAssessment.risk_band === "HIGH" ? "high" : "medium") : "low"}>
              {topAssessment ? topAssessment.risk_band : "NO RISK EVALUATED"}
            </Badge>
          </div>
          <div style={{ fontSize: "12px", color: "#4B5563", marginTop: "12px" }}>
            Confidence Level: {topAssessment ? `${(topAssessment.confidence * 100).toFixed(0)}%` : "100%"} (Deterministic)
          </div>
        </div>

        {/* Risk Derivation Formula */}
        <div style={{ backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "20px" }}>
          <div style={{ fontSize: "13px", fontWeight: 600, color: "#111827", marginBottom: "8px" }}>
            Risk Score Derivation Model
          </div>
          <div style={{ fontSize: "13px", fontFamily: "monospace", color: "#111827", backgroundColor: "#FFFFFF", padding: "10px 14px", borderRadius: "6px", border: "1px solid #E5E7EB", marginBottom: "12px" }}>
            {topAssessment ? topAssessment.explanation : "Score = Base Exposure (0) + Context Risk (0)"}
          </div>
          <div style={{ fontSize: "12px", color: "#4B5563" }}>
            SECDEF risk calculations are fully explainable, rule-based formulas. No black-box AI scores.
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div style={{ backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "12px 16px", marginBottom: "20px", display: "flex", gap: "12px", alignItems: "center" }}>
        <Filter size={16} style={{ color: "#9CA3AF" }} />
        <span style={{ fontSize: "12px", color: "#4B5563" }}>Filter by Risk Band:</span>
        <select
          value={bandFilter}
          onChange={(e) => setBandFilter(e.target.value)}
          className="input-field"
          style={{ height: "36px", fontSize: "13px" }}
        >
          <option value="">All Risk Bands</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="INFO">INFO</option>
        </select>
      </div>

      {/* Assessments Data Table */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
        <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
          Evaluated Risk Assessments ({assessments.length})
        </div>

        {loading ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            Loading risk assessments...
          </div>
        ) : assessments.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            No risk assessments found matching filter.
          </div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Risk Band</th>
                <th>Score</th>
                <th>Confidence</th>
                <th>Model Version</th>
                <th>Explanation & Trace</th>
                <th>Assessed At</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {assessments.map(r => (
                <tr key={r.id}>
                  <td>
                    <Badge variant={r.risk_band === "CRITICAL" ? "critical" : r.risk_band === "HIGH" ? "high" : r.risk_band === "MEDIUM" ? "medium" : "low"}>
                      {r.risk_band}
                    </Badge>
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600 }}>
                    {r.risk_score.toFixed(1)}
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    {(r.confidence * 100).toFixed(0)}%
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>
                    {r.risk_model_version}
                  </td>
                  <td>
                    <div style={{ fontSize: "13px", color: "#111827", maxWidth: "450px" }}>
                      {r.explanation}
                    </div>
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <Link href={`/risk/${r.id}`} className="btn-secondary" style={{ padding: "4px 8px", fontSize: "12px", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: "4px" }}>
                      Inspect Factors <ArrowRight size={12} />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

