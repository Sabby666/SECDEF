"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { getSession, listIntelligenceCorrelations, triggerIntelligenceCorrelation } from "../lib/api";
import { IntelligenceCorrelation } from "../lib/types";

export default function CorrelationsListPage() {
  const [correlations, setCorrelations] = useState<IntelligenceCorrelation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [triggering, setTriggering] = useState(false);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const session = getSession();
        const data = await listIntelligenceCorrelations(session.orgId);
        setCorrelations(data);
      } catch (err: any) {
        setError(err.message || "Failed to load correlations");
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleTriggerCorrelation = async () => {
    try {
      setTriggering(true);
      const session = getSession();
      const newCorrs = await triggerIntelligenceCorrelation(session.orgId);
      setCorrelations(newCorrs);
    } catch (err: any) {
      setError(err.message || "Failed to trigger correlation run");
    } finally {
      setTriggering(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 700, color: "var(--text-primary)" }}>
            Intelligence Correlations
          </h1>
          <p style={{ fontSize: "14px", color: "var(--text-secondary)", marginTop: "4px" }}>
            Deterministic correlations between observed asset technologies and threat intelligence.
          </p>
        </div>
        <button
          onClick={handleTriggerCorrelation}
          disabled={triggering}
          style={{
            padding: "8px 16px",
            borderRadius: "6px",
            backgroundColor: "var(--accent)",
            color: "#fff",
            fontWeight: 600,
            border: "none",
            cursor: triggering ? "not-allowed" : "pointer"
          }}
        >
          {triggering ? "Correlating..." : "Run Intelligence Correlation"}
        </button>
      </div>

      {loading && <div style={{ color: "var(--text-secondary)" }}>Loading correlations...</div>}
      {error && <div style={{ color: "#ef4444", backgroundColor: "rgba(239,68,68,0.1)", padding: "12px", borderRadius: "6px" }}>{error}</div>}

      {!loading && !error && (
        <div style={{ backgroundColor: "var(--bg-secondary)", borderRadius: "8px", border: "1px solid var(--border-primary)", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border-primary)", backgroundColor: "var(--bg-tertiary)", color: "var(--text-secondary)" }}>
                <th style={{ padding: "12px 16px" }}>Observed Tech</th>
                <th style={{ padding: "12px 16px" }}>Correlation State</th>
                <th style={{ padding: "12px 16px" }}>Confidence</th>
                <th style={{ padding: "12px 16px" }}>Match Reason</th>
                <th style={{ padding: "12px 16px" }}>Asset ID</th>
                <th style={{ padding: "12px 16px" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {correlations.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: "24px", textAlign: "center", color: "var(--text-tertiary)" }}>
                    No intelligence correlations found. Run correlation to evaluate assets.
                  </td>
                </tr>
              ) : (
                correlations.map((c) => (
                  <tr key={c.id} style={{ borderBottom: "1px solid var(--border-primary)" }}>
                    <td style={{ padding: "12px 16px", color: "var(--text-primary)" }}>
                      <div className="mono" style={{ fontWeight: 600 }}>{c.observed_technology}</div>
                      <div style={{ fontSize: "11px", color: "var(--text-tertiary)" }}>Ver: {c.observed_version || "Unknown"}</div>
                    </td>
                    <td style={{ padding: "12px 16px" }}>
                      <span className="mono" style={{
                        padding: "2px 8px",
                        borderRadius: "4px",
                        fontSize: "11px",
                        fontWeight: 600,
                        backgroundColor: c.correlation_state === "VERSION_CONFIRMED" ? "rgba(239, 68, 68, 0.2)" : "rgba(59, 130, 246, 0.2)",
                        color: c.correlation_state === "VERSION_CONFIRMED" ? "#ef4444" : "#3b82f6"
                      }}>
                        {c.correlation_state}
                      </span>
                    </td>
                    <td style={{ padding: "12px 16px" }}>
                      <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>{(c.confidence_score * 100).toFixed(0)}%</div>
                      <div style={{ fontSize: "11px", color: "var(--text-tertiary)" }}>Band: {c.confidence_band}</div>
                    </td>
                    <td style={{ padding: "12px 16px", color: "var(--text-secondary)", maxWidth: "300px" }}>
                      {c.match_reason}
                    </td>
                    <td style={{ padding: "12px 16px" }}>
                      <Link href={`/assets/${c.asset_id}`} className="mono" style={{ color: "var(--accent)" }}>
                        {c.asset_id.slice(0, 8)}...
                      </Link>
                    </td>
                    <td style={{ padding: "12px 16px" }}>
                      <Link href={`/correlations/${c.id}`} style={{ color: "var(--accent)", fontSize: "12px" }}>
                        View Detail
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
