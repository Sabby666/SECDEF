"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { getSession, getIntelligenceRecord } from "../../lib/api";
import { IntelligenceRecord } from "../../lib/types";

export default function IntelligenceDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const [record, setRecord] = useState<IntelligenceRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadDetail() {
      try {
        setLoading(true);
        const session = getSession();
        const data = await getIntelligenceRecord(session.orgId, id);
        setRecord(data);
      } catch (err: any) {
        setError(err.message || "Failed to load record");
      } finally {
        setLoading(false);
      }
    }
    if (id) loadDetail();
  }, [id]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      <div>
        <Link href="/intelligence" style={{ fontSize: "13px", color: "var(--accent)" }}>
          ← Back to Intelligence Records
        </Link>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "var(--text-primary)", marginTop: "8px" }}>
          {record ? record.external_id : "Intelligence Record Detail"}
        </h1>
      </div>

      {loading && <div style={{ color: "var(--text-secondary)" }}>Loading record...</div>}
      {error && <div style={{ color: "#ef4444", backgroundColor: "rgba(239,68,68,0.1)", padding: "12px", borderRadius: "6px" }}>{error}</div>}

      {record && (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          <div style={{ backgroundColor: "var(--bg-secondary)", borderRadius: "8px", border: "1px solid var(--border-primary)", padding: "20px" }}>
            <h2 style={{ fontSize: "16px", fontWeight: 600, color: "var(--text-primary)", marginBottom: "12px" }}>
              {record.title}
            </h2>
            <p style={{ fontSize: "14px", color: "var(--text-secondary)", lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
              {record.description}
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
            <div style={{ backgroundColor: "var(--bg-secondary)", borderRadius: "8px", border: "1px solid var(--border-primary)", padding: "16px" }}>
              <div style={{ fontSize: "12px", color: "var(--text-tertiary)", textTransform: "uppercase", marginBottom: "8px" }}>
                Target Details
              </div>
              <div style={{ fontSize: "13px", color: "var(--text-secondary)", display: "flex", flexDirection: "column", gap: "6px" }}>
                <div>Vendor: <span style={{ color: "var(--text-primary)" }}>{record.affected_vendor}</span></div>
                <div>Product: <span style={{ color: "var(--text-primary)" }}>{record.affected_product}</span></div>
                <div>Version Range: <span className="mono" style={{ color: "var(--text-primary)" }}>{record.affected_version_range || "*"}</span></div>
                {record.affected_cpe && <div>CPE: <span className="mono" style={{ color: "var(--text-primary)" }}>{record.affected_cpe}</span></div>}
              </div>
            </div>

            <div style={{ backgroundColor: "var(--bg-secondary)", borderRadius: "8px", border: "1px solid var(--border-primary)", padding: "16px" }}>
              <div style={{ fontSize: "12px", color: "var(--text-tertiary)", textTransform: "uppercase", marginBottom: "8px" }}>
                Severity & Threat Signals
              </div>
              <div style={{ fontSize: "13px", color: "var(--text-secondary)", display: "flex", flexDirection: "column", gap: "6px" }}>
                <div>Severity: <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>{record.severity.toUpperCase()}</span></div>
                {record.cvss_v3_score && <div>CVSS v3 Score: <span className="mono" style={{ color: "var(--text-primary)" }}>{record.cvss_v3_score}</span></div>}
                {record.epss_score && <div>EPSS Probability: <span className="mono" style={{ color: "var(--text-primary)" }}>{(record.epss_score * 100).toFixed(2)}%</span></div>}
                <div>CISA KEV Status: <span style={{ color: record.is_cisa_kev ? "#ef4444" : "var(--text-tertiary)", fontWeight: record.is_cisa_kev ? 700 : 400 }}>{record.is_cisa_kev ? "KNOWN EXPLOITED" : "Not listed"}</span></div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
