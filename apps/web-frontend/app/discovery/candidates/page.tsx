"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { 
  Radar, CheckCircle, XCircle, Search, Filter, RefreshCw, 
  ExternalLink, FileText, ArrowLeft, ShieldCheck 
} from "lucide-react";
import { 
  listDiscoveryCandidates, getCandidateEvidence, validateDiscoveryCandidate, 
  rejectDiscoveryCandidate, getSession 
} from "../../lib/api";
import { 
  DiscoveryCandidate, DiscoveryEvidence 
} from "../../lib/types";
import Badge from "../../components/Badge";

export default function CandidateExplorerPage() {
  const [candidates, setCandidates] = useState<DiscoveryCandidate[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterState, setFilterState] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Drawer detail state
  const [selectedCandidate, setSelectedCandidate] = useState<DiscoveryCandidate | null>(null);
  const [evidences, setEvidences] = useState<DiscoveryEvidence[]>([]);
  const [modalLoading, setModalLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadCandidates = async () => {
    setLoading(true);
    try {
      const session = getSession();
      const valState = filterState === "all" ? undefined : filterState;
      const data = await listDiscoveryCandidates(session.orgId, valState);
      setCandidates(data);
    } catch (e) {
      console.error("Failed to load candidates", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCandidates();
  }, [filterState]);

  const handleOpenDetail = async (cand: DiscoveryCandidate) => {
    setSelectedCandidate(cand);
    setModalLoading(true);
    try {
      const session = getSession();
      const evData = await getCandidateEvidence(session.orgId, cand.id);
      setEvidences(evData);
    } catch (e) {
      console.error("Failed to load evidence", e);
    } finally {
      setModalLoading(false);
    }
  };

  const handleValidate = async (candidateId: string) => {
    try {
      const session = getSession();
      await validateDiscoveryCandidate(session.orgId, candidateId);
      setActionMessage("Candidate successfully validated and promoted to Asset Inventory.");
      await loadCandidates();
      if (selectedCandidate && selectedCandidate.id === candidateId) {
        setSelectedCandidate(prev => prev ? { ...prev, validation_state: "dns_confirmed" } : null);
      }
    } catch (e: any) {
      setActionMessage(`Validation failed: ${e.message}`);
    }
  };

  const handleReject = async (candidateId: string) => {
    try {
      const session = getSession();
      await rejectDiscoveryCandidate(session.orgId, candidateId);
      setActionMessage("Candidate state updated to Rejected.");
      await loadCandidates();
      if (selectedCandidate && selectedCandidate.id === candidateId) {
        setSelectedCandidate(prev => prev ? { ...prev, validation_state: "rejected" } : null);
      }
    } catch (e: any) {
      setActionMessage(`Rejection failed: ${e.message}`);
    }
  };

  const filteredCandidates = candidates.filter(c => 
    c.canonical_identifier.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
        <div>
          <Link href="/discovery" style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "#4B5563", marginBottom: "6px", textDecoration: "none" }}>
            <ArrowLeft size={14} /> Back to Discovery
          </Link>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Candidate Explorer
          </h1>
        </div>
        <button onClick={loadCandidates} className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}>
          <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
        </button>
      </div>

      {actionMessage && (
        <div style={{ padding: "10px 14px", backgroundColor: "#EFF6FF", border: "1px solid #93C5FD", color: "#2563EB", borderRadius: "6px", fontSize: "13px", marginBottom: "16px" }}>
          {actionMessage}
        </div>
      )}

      {/* Filter Toolbar */}
      <div style={{ backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "12px 16px", marginBottom: "20px", display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ flex: 1, minWidth: "240px", position: "relative" }}>
          <Search size={16} style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)", color: "#9CA3AF" }} />
          <input
            type="text"
            className="input-field"
            placeholder="Search candidate identifier (e.g. api.example.com)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ paddingLeft: "32px", width: "100%", height: "36px", fontSize: "13px" }}
          />
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <span style={{ fontSize: "12px", color: "#4B5563" }}>Validation:</span>
          <select
            className="input-field"
            value={filterState}
            onChange={(e) => setFilterState(e.target.value)}
            style={{ height: "36px", fontSize: "13px" }}
          >
            <option value="all">All States</option>
            <option value="unvalidated">Unvalidated Only</option>
            <option value="dns_confirmed">DNS Confirmed</option>
            <option value="rejected">Rejected</option>
          </select>
        </div>
      </div>

      {/* Candidates Table */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
        {loading ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading discovery candidates...</div>
        ) : filteredCandidates.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            No candidates found matching the selected criteria.
          </div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Hostname / Identifier</th>
                <th>Type</th>
                <th>Source</th>
                <th>Exposure</th>
                <th>Validation State</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredCandidates.map((c) => (
                <tr key={c.id}>
                  <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 500 }}>
                    <button
                      onClick={() => handleOpenDetail(c)}
                      style={{ background: "none", border: "none", color: "#2563EB", cursor: "pointer", padding: 0, textAlign: "left", fontFamily: "monospace", fontSize: "13px", fontWeight: 500 }}
                    >
                      {c.canonical_identifier}
                    </button>
                  </td>
                  <td>
                    <span style={{ fontSize: "12px", color: "#4B5563" }}>
                      {c.candidate_type}
                    </span>
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    {c.source_type.replace("_", " ")}
                  </td>
                  <td>
                    <Badge variant={c.exposure_state === "CURRENT" ? "verified" : "high"}>
                      {c.exposure_state}
                    </Badge>
                  </td>
                  <td>
                    <Badge variant={c.validation_state === "dns_confirmed" ? "verified" : c.validation_state === "rejected" ? "low" : "medium"}>
                      {c.validation_state.toUpperCase()}
                    </Badge>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "flex", gap: "6px", justifyContent: "flex-end" }}>
                      <button
                        onClick={() => handleOpenDetail(c)}
                        className="btn-secondary"
                        style={{ padding: "3px 8px", fontSize: "12px" }}
                      >
                        Evidence
                      </button>
                      {c.validation_state === "unvalidated" && (
                        <>
                          <button
                            onClick={() => handleValidate(c.id)}
                            className="btn-primary"
                            style={{ padding: "3px 8px", fontSize: "12px" }}
                          >
                            Validate
                          </button>
                          <button
                            onClick={() => handleReject(c.id)}
                            className="btn-secondary"
                            style={{ padding: "3px 8px", fontSize: "12px", color: "#DC2626" }}
                          >
                            Reject
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Drawer / Detail View */}
      {selectedCandidate && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: "rgba(17,24,39,0.4)", display: "flex", justifyContent: "flex-end", zIndex: 1000
        }}>
          <div style={{ width: "600px", maxWidth: "100%", backgroundColor: "#FFFFFF", height: "100%", overflowY: "auto", padding: "24px", boxShadow: "-4px 0 16px rgba(0,0,0,0.05)", borderLeft: "1px solid #E5E7EB" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
              <div>
                <div style={{ fontSize: "12px", color: "#9CA3AF" }}>Candidate Details & Provenance</div>
                <h2 style={{ fontSize: "18px", fontWeight: 600, color: "#111827", margin: "4px 0 0 0", fontFamily: "monospace" }}>{selectedCandidate.canonical_identifier}</h2>
              </div>
              <button onClick={() => setSelectedCandidate(null)} className="btn-secondary" style={{ padding: "4px 8px", fontSize: "13px" }}>✕</button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "20px", fontSize: "13px", borderBottom: "1px solid #E5E7EB", paddingBottom: "16px" }}>
              <div><strong style={{ color: "#4B5563" }}>Type:</strong> {selectedCandidate.candidate_type}</div>
              <div><strong style={{ color: "#4B5563" }}>Source:</strong> {selectedCandidate.source_type}</div>
              <div><strong style={{ color: "#4B5563" }}>State:</strong> {selectedCandidate.validation_state}</div>
              <div><strong style={{ color: "#4B5563" }}>Exposure:</strong> {selectedCandidate.exposure_state}</div>
              <div><strong style={{ color: "#4B5563" }}>Confidence:</strong> {selectedCandidate.confidence}</div>
              <div><strong style={{ color: "#4B5563" }}>First Seen:</strong> {new Date(selectedCandidate.first_seen_at).toLocaleString()}</div>
            </div>

            {selectedCandidate.promoted_asset_id && (
              <div style={{ marginBottom: "20px", padding: "12px", backgroundColor: "#F0FDF4", border: "1px solid #86EFAC", borderRadius: "6px", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "13px" }}>
                <span style={{ color: "#16A34A" }}>Promoted to Asset Inventory</span>
                <Link href={`/assets?id=${selectedCandidate.promoted_asset_id}`} className="btn-secondary" style={{ padding: "2px 8px", fontSize: "12px" }}>
                  View Asset <ExternalLink size={12} />
                </Link>
              </div>
            )}

            <div style={{ fontSize: "14px", fontWeight: 600, color: "#111827", marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
              <FileText size={16} /> Evidence Records ({evidences.length})
            </div>

            {modalLoading ? (
              <div style={{ padding: "20px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading evidence records...</div>
            ) : evidences.length === 0 ? (
              <div style={{ padding: "20px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No specific evidence records retrieved.</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                {evidences.map((e) => (
                  <div key={e.id} style={{ backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", padding: "12px", borderRadius: "6px", fontSize: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px", color: "#4B5563" }}>
                      <span>Source: {e.source_type}</span>
                      <span>{new Date(e.observed_at).toLocaleString()}</span>
                    </div>
                    <pre style={{
                      backgroundColor: "#FFFFFF",
                      border: "1px solid #E5E7EB",
                      padding: "8px",
                      borderRadius: "4px",
                      fontFamily: "monospace",
                      fontSize: "12px",
                      overflowX: "auto",
                      margin: 0
                    }}>
                      {JSON.stringify({ raw_data: e.raw_data, provenance: e.provenance }, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            )}

            <div style={{ marginTop: "24px", display: "flex", gap: "12px", justifyContent: "flex-end" }}>
              {selectedCandidate.validation_state === "unvalidated" && (
                <>
                  <button onClick={() => handleValidate(selectedCandidate.id)} className="btn-primary" style={{ fontSize: "13px" }}>
                    Validate & Promote
                  </button>
                  <button onClick={() => handleReject(selectedCandidate.id)} className="btn-secondary" style={{ color: "#DC2626", fontSize: "13px" }}>
                    Reject Candidate
                  </button>
                </>
              )}
              <button onClick={() => setSelectedCandidate(null)} className="btn-secondary" style={{ fontSize: "13px" }}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

