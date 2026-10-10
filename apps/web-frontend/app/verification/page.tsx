"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { CheckCircle2, ShieldCheck, RefreshCw, AlertTriangle, ArrowRight } from "lucide-react";
import { listFindings, listComparisons, verifyFinding, getSession } from "../lib/api";
import { Finding, ComparisonRun, UserRole } from "../lib/types";
import Badge from "../components/Badge";

export default function VerificationPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [findings, setFindings] = useState<Finding[]>([]);
  const [comparisons, setComparisons] = useState<ComparisonRun[]>([]);
  const [role, setRole] = useState<UserRole>("ADMIN");

  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  const loadVerificationData = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      setRole(session.userRole);
      const orgId = session.orgId;

      const [fndRes, compRes] = await Promise.all([
        listFindings(orgId, { limit: 50 }),
        listComparisons(orgId, { limit: 20 })
      ]);

      setFindings(fndRes.items || []);
      setComparisons(compRes.items || []);
    } catch (err: any) {
      setError(err.message || "Failed to load remediation verification log");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadVerificationData();
  }, []);

  const handleVerify = async (findingId: string) => {
    setVerifyingId(findingId);
    setError(null);
    setFeedback(null);
    try {
      const session = getSession();
      const res = await verifyFinding(session.orgId, findingId);
      setFeedback(`Verification result status: ${res.status}`);
      await loadVerificationData();
    } catch (err: any) {
      setError(err.message || "Verification failed");
    } finally {
      setVerifyingId(null);
    }
  };

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Remediation Verification Log
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Automated verification requires completeness-gated scan proof for finding resolution.
          </p>
        </div>
        <button 
          onClick={loadVerificationData} 
          className="btn-secondary" 
          style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
        </button>
      </div>

      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 14px", backgroundColor: "#FEF2F2", border: "1px solid #FCA5A5", color: "#DC2626", borderRadius: "6px", fontSize: "13px" }}>
          {error}
        </div>
      )}

      {feedback && (
        <div style={{ marginBottom: "16px", padding: "10px 14px", backgroundColor: "#F0FDF4", border: "1px solid #86EFAC", color: "#16A34A", borderRadius: "6px", fontSize: "13px" }}>
          {feedback}
        </div>
      )}

      {/* Findings Verification Status Table */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden", marginBottom: "24px" }}>
        <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
          Findings Verification Queue ({findings.length})
        </div>

        {loading ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading findings for verification...</div>
        ) : findings.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No findings recorded for verification.</div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Finding Status</th>
                <th>Finding Title</th>
                <th>Verification Proof</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td>
                    <Badge variant={f.status}>
                      {f.status}
                    </Badge>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: "#111827", fontSize: "13px" }}>{f.title}</div>
                    <div style={{ fontFamily: "monospace", fontSize: "11px", color: "#9CA3AF" }}>ID: {f.id.substring(0, 8)}...</div>
                  </td>
                  <td style={{ fontSize: "12px" }}>
                    {f.resolved_at ? (
                      <span style={{ color: "#16A34A", fontWeight: 500 }}>Resolved {new Date(f.resolved_at).toLocaleDateString()}</span>
                    ) : f.reopened_at ? (
                      <span style={{ color: "#DC2626", fontWeight: 500 }}>Reopened {new Date(f.reopened_at).toLocaleDateString()}</span>
                    ) : (
                      <span style={{ color: "#9CA3AF", fontStyle: "italic" }}>Unverified</span>
                    )}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "flex", gap: "6px", justifyContent: "flex-end" }}>
                      {(role === "ADMIN" || role === "MEMBER") && (
                        <button
                          onClick={() => handleVerify(f.id)}
                          disabled={verifyingId === f.id}
                          className="btn-primary"
                          style={{ padding: "3px 8px", fontSize: "12px" }}
                        >
                          {verifyingId === f.id ? "Verifying..." : "Run Verification"}
                        </button>
                      )}
                      <Link
                        href={`/findings/${f.id}`}
                        className="btn-secondary"
                        style={{ padding: "3px 8px", fontSize: "12px", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: "4px" }}
                      >
                        Trace <ArrowRight size={12} />
                      </Link>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Comparison Runs Table */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
        <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
          Scan-over-Scan Comparison Runs ({comparisons.length})
        </div>

        {comparisons.length === 0 ? (
          <div style={{ padding: "32px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No comparison run records found.</div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Completeness Gate</th>
                <th>Changes Detected</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {comparisons.map((c) => (
                <tr key={c.id}>
                  <td>
                    <Badge variant={c.status === "completed" ? "verified" : "medium"}>{c.status.toUpperCase()}</Badge>
                  </td>
                  <td>
                    <Badge variant={c.current_scan_completeness === "complete" ? "verified" : "high"}>
                      {c.current_scan_completeness}
                    </Badge>
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600, color: "#111827" }}>
                    {c.changes_detected}
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    {new Date(c.created_at).toLocaleString()}
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

