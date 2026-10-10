"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { getSession, getIntelligenceCorrelation, getCorrelationEvidence } from "../../lib/api";
import { IntelligenceCorrelation, IntelligenceEvidence } from "../../lib/types";

export default function CorrelationDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const [correlation, setCorrelation] = useState<IntelligenceCorrelation | null>(null);
  const [evidence, setEvidence] = useState<IntelligenceEvidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadDetail() {
      try {
        setLoading(true);
        const session = getSession();
        const data = await getIntelligenceCorrelation(session.orgId, id);
        setCorrelation(data);
        const evItems = await getCorrelationEvidence(session.orgId, id);
        setEvidence(evItems);
      } catch (err: any) {
        setError(err.message || "Failed to load correlation detail");
      } finally {
        setLoading(false);
      }
    }
    if (id) loadDetail();
  }, [id]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      <div>
        <Link href="/correlations" style={{ fontSize: "13px", color: "var(--accent)" }}>
          ← Back to Correlations
        </Link>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "var(--text-primary)", marginTop: "8px" }}>
          Intelligence Correlation Detail
        </h1>
      </div>

      {loading && <div style={{ color: "var(--text-secondary)" }}>Loading correlation...</div>}
      {error && <div style={{ color: "#ef4444", backgroundColor: "rgba(239,68,68,0.1)", padding: "12px", borderRadius: "6px" }}>{error}</div>}

      {correlation && (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          <div style={{ backgroundColor: "var(--bg-secondary)", borderRadius: "8px", border: "1px solid var(--border-primary)", padding: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 style={{ fontSize: "18px", fontWeight: 700, color: "var(--text-primary)" }}>
                {correlation.observed_technology} (Version: {correlation.observed_version || "Unknown"})
              </h2>
              <span className="mono" style={{
                padding: "4px 12px",
                borderRadius: "6px",
                fontSize: "12px",
                fontWeight: 700,
                backgroundColor: correlation.correlation_state === "VERSION_CONFIRMED" ? "rgba(239, 68, 68, 0.2)" : "rgba(59, 130, 246, 0.2)",
                color: correlation.correlation_state === "VERSION_CONFIRMED" ? "#ef4444" : "#3b82f6"
              }}>
                {correlation.correlation_state}
              </span>
            </div>

            <p style={{ fontSize: "14px", color: "var(--text-secondary)", marginTop: "12px" }}>
              <strong>Match Reason:</strong> {correlation.match_reason}
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
            <div style={{ backgroundColor: "var(--bg-secondary)", borderRadius: "8px", border: "1px solid var(--border-primary)", padding: "16px" }}>
              <div style={{ fontSize: "12px", color: "var(--text-tertiary)", textTransform: "uppercase", marginBottom: "8px" }}>
                Confidence & Model Breakdown
              </div>
              <div style={{ fontSize: "13px", color: "var(--text-secondary)", display: "flex", flexDirection: "column", gap: "6px" }}>
                <div>Confidence Score: <span className="mono" style={{ color: "var(--text-primary)", fontWeight: 700 }}>{(correlation.confidence_score * 100).toFixed(0)}%</span></div>
                <div>Confidence Band: <span style={{ color: "var(--text-primary)" }}>{correlation.confidence_band}</span></div>
                <div>Rule Version: <span className="mono" style={{ color: "var(--text-primary)" }}>{correlation.rule_version}</span></div>
                <div>Conflict Status: <span style={{ color: correlation.conflict_status === "CONFIRMED_CONFLICT" ? "#f59e0b" : "var(--text-tertiary)" }}>{correlation.conflict_status}</span></div>
              </div>
            </div>

            <div style={{ backgroundColor: "var(--bg-secondary)", borderRadius: "8px", border: "1px solid var(--border-primary)", padding: "16px" }}>
              <div style={{ fontSize: "12px", color: "var(--text-tertiary)", textTransform: "uppercase", marginBottom: "8px" }}>
                Provenancial Links
              </div>
              <div style={{ fontSize: "13px", color: "var(--text-secondary)", display: "flex", flexDirection: "column", gap: "6px" }}>
                <div>Asset: <Link href={`/assets/${correlation.asset_id}`} className="mono" style={{ color: "var(--accent)" }}>{correlation.asset_id}</Link></div>
                <div>Intelligence Record: <Link href={`/intelligence/${correlation.intelligence_record_id}`} className="mono" style={{ color: "var(--accent)" }}>{correlation.intelligence_record_id}</Link></div>
                {correlation.exposure_condition_id && <div>Exposure Condition: <Link href={`/exposures/${correlation.exposure_condition_id}`} className="mono" style={{ color: "var(--accent)" }}>{correlation.exposure_condition_id}</Link></div>}
              </div>
            </div>
          </div>

          <div style={{ backgroundColor: "var(--bg-secondary)", borderRadius: "8px", border: "1px solid var(--border-primary)", padding: "20px" }}>
            <h3 style={{ fontSize: "14px", fontWeight: 600, color: "var(--text-primary)", marginBottom: "12px" }}>
              Evidence Links ({evidence.length})
            </h3>
            {evidence.length === 0 ? (
              <div style={{ fontSize: "13px", color: "var(--text-tertiary)" }}>No specific evidence items linked.</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {evidence.map((ev) => (
                  <div key={ev.id} style={{ padding: "10px", borderRadius: "6px", backgroundColor: "var(--bg-tertiary)", border: "1px solid var(--border-primary)", fontSize: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", color: "var(--text-secondary)" }}>
                      <span>Type: <strong>{ev.evidence_type}</strong></span>
                      <span className="mono">{new Date(ev.observed_at).toLocaleString()}</span>
                    </div>
                    {ev.details && (
                      <pre style={{ marginTop: "6px", fontSize: "11px", color: "var(--text-tertiary)", whiteSpace: "pre-wrap" }}>
                        {JSON.stringify(ev.details, null, 2)}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
