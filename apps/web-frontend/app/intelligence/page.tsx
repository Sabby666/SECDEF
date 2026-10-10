"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { getSession, listIntelligenceRecords } from "../lib/api";
import { IntelligenceRecord } from "../lib/types";

export default function IntelligenceListPage() {
  const [records, setRecords] = useState<IntelligenceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const session = getSession();
        const data = await listIntelligenceRecords(session.orgId);
        setRecords(data);
      } catch (err: any) {
        setError(err.message || "Failed to load intelligence records");
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      <div>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "var(--text-primary)" }}>
          Threat & Vulnerability Intelligence
        </h1>
        <p style={{ fontSize: "14px", color: "var(--text-secondary)", marginTop: "4px" }}>
          Normalized CVE records, CISA KEV catalog items, and EPSS scores.
        </p>
      </div>

      {loading && <div style={{ color: "var(--text-secondary)" }}>Loading intelligence records...</div>}
      {error && <div style={{ color: "#ef4444", backgroundColor: "rgba(239,68,68,0.1)", padding: "12px", borderRadius: "6px" }}>{error}</div>}

      {!loading && !error && (
        <div style={{ backgroundColor: "var(--bg-secondary)", borderRadius: "8px", border: "1px solid var(--border-primary)", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border-primary)", backgroundColor: "var(--bg-tertiary)", color: "var(--text-secondary)" }}>
                <th style={{ padding: "12px 16px" }}>External ID</th>
                <th style={{ padding: "12px 16px" }}>Title / Product</th>
                <th style={{ padding: "12px 16px" }}>Severity</th>
                <th style={{ padding: "12px 16px" }}>CVSS / EPSS</th>
                <th style={{ padding: "12px 16px" }}>CISA KEV</th>
                <th style={{ padding: "12px 16px" }}>Retrieved</th>
              </tr>
            </thead>
            <tbody>
              {records.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: "24px", textAlign: "center", color: "var(--text-tertiary)" }}>
                    No intelligence records found. Ingest a feed to get started.
                  </td>
                </tr>
              ) : (
                records.map((r) => (
                  <tr key={r.id} style={{ borderBottom: "1px solid var(--border-primary)" }}>
                    <td style={{ padding: "12px 16px" }}>
                      <Link href={`/intelligence/${r.id}`} className="mono" style={{ color: "var(--accent)", fontWeight: 600 }}>
                        {r.external_id}
                      </Link>
                    </td>
                    <td style={{ padding: "12px 16px", color: "var(--text-primary)" }}>
                      <div>{r.title}</div>
                      <div style={{ fontSize: "11px", color: "var(--text-tertiary)" }}>
                        {r.affected_vendor}/{r.affected_product} {r.affected_version_range || ""}
                      </div>
                    </td>
                    <td style={{ padding: "12px 16px" }}>
                      <span className="mono" style={{
                        padding: "2px 8px",
                        borderRadius: "4px",
                        fontSize: "11px",
                        fontWeight: 600,
                        backgroundColor: r.severity.toLowerCase() === "critical" ? "rgba(239, 68, 68, 0.2)" : "rgba(245, 158, 11, 0.2)",
                        color: r.severity.toLowerCase() === "critical" ? "#ef4444" : "#f59e0b"
                      }}>
                        {r.severity.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>
                      {r.cvss_v3_score ? `CVSS ${r.cvss_v3_score}` : r.epss_score ? `EPSS ${(r.epss_score * 100).toFixed(1)}%` : "-"}
                    </td>
                    <td style={{ padding: "12px 16px" }}>
                      {r.is_cisa_kev ? (
                        <span style={{ color: "#ef4444", fontWeight: 700, fontSize: "11px" }}>YES (ACTIVE EXPLOIT)</span>
                      ) : (
                        <span style={{ color: "var(--text-tertiary)", fontSize: "11px" }}>No</span>
                      )}
                    </td>
                    <td style={{ padding: "12px 16px", color: "var(--text-tertiary)" }} className="mono">
                      {new Date(r.retrieved_at).toLocaleDateString()}
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
