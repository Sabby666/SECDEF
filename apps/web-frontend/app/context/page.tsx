"use client";

import React, { useEffect, useState } from "react";
import { 
  Plus, RefreshCw, Search, Shield, RotateCcw, Database 
} from "lucide-react";
import { 
  listDecisions, createDecision, revokeDecision, listMemories, 
  resolveContext, getSession 
} from "../lib/api";
import { 
  Decision, Memory, ContextResolutionResponse, UserRole 
} from "../lib/types";
import Badge from "../components/Badge";

export default function ContextPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<"decisions" | "memories" | "resolver">("decisions");
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [memories, setMemories] = useState<Memory[]>([]);
  const [role, setRole] = useState<UserRole>("ADMIN");

  // Modal states
  const [decModalOpen, setDecModalOpen] = useState(false);
  const [decSubject, setDecSubject] = useState("");
  const [decType, setDecType] = useState<any>("ACCEPT_RISK");
  const [decScope, setDecScope] = useState<any>("SPECIFIC_ASSET");
  const [decReason, setDecReason] = useState("");
  const [decSubmitting, setDecSubmitting] = useState(false);

  const [revokeModalOpen, setRevokeModalOpen] = useState(false);
  const [targetDecId, setTargetDecId] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState("");
  const [revokeSubmitting, setRevokeSubmitting] = useState(false);

  // Resolver Tool
  const [targetType, setTargetType] = useState("subdomain");
  const [targetIdent, setTargetIdent] = useState("");
  const [resolving, setResolving] = useState(false);
  const [resolutionResult, setResolutionResult] = useState<ContextResolutionResponse | null>(null);

  const loadContextData = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      setRole(session.userRole);
      const orgId = session.orgId;

      const [decRes, memRes] = await Promise.all([
        listDecisions(orgId, { limit: 50 }),
        listMemories(orgId, { limit: 50 })
      ]);

      setDecisions(decRes.items || []);
      setMemories(memRes.items || []);
    } catch (err: any) {
      setError(err.message || "Failed to load organizational context & decision memory");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadContextData();
  }, []);

  const handleCreateDecision = async (e: React.FormEvent) => {
    e.preventDefault();
    setDecSubmitting(true);
    setError(null);
    try {
      const session = getSession();
      await createDecision(session.orgId, {
        decision_type: decType,
        scope_level: decScope,
        subject_identifier: decSubject,
        new_state: { expected_exposure: "expected", risk_acceptance: true },
        reason: decReason
      });
      setDecModalOpen(false);
      setDecSubject("");
      setDecReason("");
      await loadContextData();
    } catch (err: any) {
      setError(err.message || "Failed to record human security decision");
    } finally {
      setDecSubmitting(false);
    }
  };

  const handleRevokeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetDecId || !revokeReason.trim()) return;
    setRevokeSubmitting(true);
    setError(null);
    try {
      const session = getSession();
      await revokeDecision(session.orgId, targetDecId, revokeReason);
      setRevokeModalOpen(false);
      await loadContextData();
    } catch (err: any) {
      setError(err.message || "Revocation failed");
    } finally {
      setRevokeSubmitting(false);
    }
  };

  const handleRunResolver = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetIdent.trim()) return;
    setResolving(true);
    setError(null);
    try {
      const session = getSession();
      const res = await resolveContext(session.orgId, targetType, targetIdent);
      setResolutionResult(res);
    } catch (err: any) {
      setError(err.message || "Context resolution failed");
    } finally {
      setResolving(false);
    }
  };

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Page Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Organization Context & Memory
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Audit-friendly repository for human security assertions, risk acceptances, and expected state precedence.
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px" }}>
          {role === "ADMIN" && (
            <button onClick={() => setDecModalOpen(true)} className="btn-primary" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}>
              <Plus size={14} /> Record Decision
            </button>
          )}
          <button onClick={loadContextData} className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}>
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 14px", backgroundColor: "#FEF2F2", border: "1px solid #FCA5A5", color: "#DC2626", borderRadius: "6px", fontSize: "13px" }}>
          {error}
        </div>
      )}

      {/* Workspace Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid #E5E7EB", marginBottom: "20px" }}>
        <button
          onClick={() => setActiveTab("decisions")}
          style={{
            padding: "10px 16px",
            fontSize: "13px",
            fontWeight: 500,
            color: activeTab === "decisions" ? "#2563EB" : "#4B5563",
            borderBottom: activeTab === "decisions" ? "2px solid #2563EB" : "none",
            background: "none",
            cursor: "pointer"
          }}
        >
          Security Decisions ({decisions.length})
        </button>
        <button
          onClick={() => setActiveTab("memories")}
          style={{
            padding: "10px 16px",
            fontSize: "13px",
            fontWeight: 500,
            color: activeTab === "memories" ? "#2563EB" : "#4B5563",
            borderBottom: activeTab === "memories" ? "2px solid #2563EB" : "none",
            background: "none",
            cursor: "pointer"
          }}
        >
          Organizational Memories ({memories.length})
        </button>
        <button
          onClick={() => setActiveTab("resolver")}
          style={{
            padding: "10px 16px",
            fontSize: "13px",
            fontWeight: 500,
            color: activeTab === "resolver" ? "#2563EB" : "#4B5563",
            borderBottom: activeTab === "resolver" ? "2px solid #2563EB" : "none",
            background: "none",
            cursor: "pointer"
          }}
        >
          Expected State Resolver
        </button>
      </div>

      {/* TAB 1: DECISIONS TABLE */}
      {activeTab === "decisions" && (
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
          {loading ? (
            <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading security decisions...</div>
          ) : decisions.length === 0 ? (
            <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No security decisions recorded yet.</div>
          ) : (
            <table className="asm-table">
              <thead>
                <tr>
                  <th>Decision Type</th>
                  <th>Scope</th>
                  <th>Target Identifier</th>
                  <th>Reason / Justification</th>
                  <th>Status</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {decisions.map(d => (
                  <tr key={d.id}>
                    <td>
                      <Badge variant="medium">{d.decision_type.replace(/_/g, " ")}</Badge>
                    </td>
                    <td style={{ fontSize: "12px", color: "#4B5563" }}>
                      {d.scope_level}
                    </td>
                    <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600, color: "#111827" }}>
                      {d.subject_identifier}
                    </td>
                    <td style={{ fontSize: "13px", color: "#4B5563", maxWidth: "360px" }}>
                      {d.reason}
                    </td>
                    <td>
                      <Badge variant={d.status === "ACTIVE" ? "verified" : "low"}>{d.status}</Badge>
                    </td>
                    <td style={{ textAlign: "right" }}>
                      {d.status === "ACTIVE" && role === "ADMIN" ? (
                        <button
                          onClick={() => {
                            setTargetDecId(d.id);
                            setRevokeReason("");
                            setRevokeModalOpen(true);
                          }}
                          className="btn-secondary"
                          style={{ padding: "3px 8px", fontSize: "12px", color: "#DC2626" }}
                        >
                          Revoke
                        </button>
                      ) : (
                        <span style={{ color: "#9CA3AF", fontSize: "12px", fontStyle: "italic" }}>Revoked</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* TAB 2: MEMORIES TABLE */}
      {activeTab === "memories" && (
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
          {loading ? (
            <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading organizational memories...</div>
          ) : memories.length === 0 ? (
            <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No persistent organizational memories derived yet.</div>
          ) : (
            <table className="asm-table">
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Scope Target</th>
                  <th>Level</th>
                  <th>Confidence</th>
                  <th>Source</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {memories.map(m => (
                  <tr key={m.id}>
                    <td>
                      <Badge variant="medium">{m.category.replace(/_/g, " ")}</Badge>
                    </td>
                    <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600, color: "#111827" }}>
                      {m.scope_identifier}
                    </td>
                    <td style={{ fontSize: "12px", color: "#4B5563" }}>
                      {m.scope_level}
                    </td>
                    <td style={{ fontSize: "12px", color: "#4B5563" }}>
                      {(m.confidence * 100).toFixed(0)}%
                    </td>
                    <td style={{ fontSize: "12px", color: "#4B5563" }}>
                      {m.source}
                    </td>
                    <td>
                      <Badge variant={m.status === "ACTIVE" ? "verified" : "low"}>{m.status}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* TAB 3: RESOLVER TOOL */}
      {activeTab === "resolver" && (
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "20px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600, color: "#111827", marginBottom: "12px" }}>
            Evaluate Scope Precedence & Inheritance
          </div>

          <form onSubmit={handleRunResolver} style={{ display: "flex", gap: "12px", alignItems: "flex-end", marginBottom: "20px" }}>
            <div style={{ width: "200px" }}>
              <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Target Type</label>
              <select value={targetType} onChange={(e) => setTargetType(e.target.value)} className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }}>
                <option value="subdomain">Subdomain</option>
                <option value="ip_address">IP Address</option>
                <option value="service">Service</option>
              </select>
            </div>

            <div style={{ flex: 1 }}>
              <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Target Identifier *</label>
              <input
                required
                type="text"
                value={targetIdent}
                onChange={(e) => setTargetIdent(e.target.value)}
                placeholder="e.g. api.staging.example.com"
                className="input-field"
                style={{ width: "100%", height: "36px", fontSize: "13px" }}
              />
            </div>

            <button type="submit" disabled={resolving || !targetIdent.trim()} className="btn-primary" style={{ height: "36px", fontSize: "13px" }}>
              {resolving ? "Resolving..." : "Resolve Precedence"}
            </button>
          </form>

          {resolutionResult && (
            <div style={{ padding: "16px", backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "6px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                <span style={{ fontFamily: "monospace", fontSize: "14px", fontWeight: 600, color: "#111827" }}>{resolutionResult.target_identifier}</span>
                <Badge variant={resolutionResult.expected_state === "expected" ? "verified" : "high"}>
                  {resolutionResult.expected_state}
                </Badge>
              </div>
              <div style={{ fontSize: "12px", color: "#4B5563", marginBottom: "12px" }}>
                Resolution Status: <strong>{resolutionResult.resolution_status}</strong> • Conflict Detected: <strong>{resolutionResult.conflict_detected ? "YES" : "NO"}</strong>
              </div>
              <div style={{ fontSize: "12px", fontWeight: 600, color: "#111827", marginBottom: "6px" }}>Matched Organizational Memories:</div>
              {resolutionResult.matched_memories.map((m) => (
                <div key={m.id} style={{ padding: "8px", backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "4px", fontSize: "12px", fontFamily: "monospace", color: "#4B5563", marginBottom: "4px" }}>
                  Key: {m.memory_key} • Scope: {m.scope_level} ({m.scope_identifier})
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Record Decision Modal */}
      {decModalOpen && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, backgroundColor: "rgba(17,24,39,0.4)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ backgroundColor: "#FFFFFF", borderRadius: "6px", width: "480px", maxWidth: "90%", padding: "20px", border: "1px solid #E5E7EB" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, color: "#111827", margin: "0 0 16px 0" }}>Record Human Security Decision</h3>
            <form onSubmit={handleCreateDecision} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Target Identifier *</label>
                <input required type="text" value={decSubject} onChange={(e) => setDecSubject(e.target.value)} placeholder="e.g. api.staging.example.com" className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }} />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <div>
                  <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Decision Type</label>
                  <select value={decType} onChange={(e) => setDecType(e.target.value as any)} className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }}>
                    <option value="ACCEPT_RISK">ACCEPT_RISK</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                    <option value="EXPECTED_EXPOSURE">EXPECTED_EXPOSURE</option>
                    <option value="EXPECTED_INFRASTRUCTURE">EXPECTED_INFRASTRUCTURE</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Scope Level</label>
                  <select value={decScope} onChange={(e) => setDecScope(e.target.value as any)} className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }}>
                    <option value="SPECIFIC_ASSET">SPECIFIC_ASSET</option>
                    <option value="DOMAIN">DOMAIN</option>
                    <option value="ORGANIZATION">ORGANIZATION</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Reason *</label>
                <textarea required rows={3} value={decReason} onChange={(e) => setDecReason(e.target.value)} placeholder="State operational justification..." className="input-field" style={{ width: "100%", padding: "8px", fontSize: "13px" }} />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "12px" }}>
                <button type="button" onClick={() => setDecModalOpen(false)} className="btn-secondary" style={{ fontSize: "13px" }}>Cancel</button>
                <button type="submit" disabled={decSubmitting} className="btn-primary" style={{ fontSize: "13px" }}>{decSubmitting ? "Saving..." : "Record Decision"}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revoke Decision Modal */}
      {revokeModalOpen && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, backgroundColor: "rgba(17,24,39,0.4)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ backgroundColor: "#FFFFFF", borderRadius: "6px", width: "440px", maxWidth: "90%", padding: "20px", border: "1px solid #E5E7EB" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, color: "#111827", margin: "0 0 16px 0" }}>Revoke Security Decision</h3>
            <form onSubmit={handleRevokeSubmit} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Revocation Reason *</label>
                <textarea required rows={3} value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)} placeholder="State operational reason for revocation..." className="input-field" style={{ width: "100%", padding: "8px", fontSize: "13px" }} />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "12px" }}>
                <button type="button" onClick={() => setRevokeModalOpen(false)} className="btn-secondary" style={{ fontSize: "13px" }}>Cancel</button>
                <button type="submit" disabled={revokeSubmitting || !revokeReason.trim()} className="btn-secondary" style={{ color: "#DC2626", fontSize: "13px" }}>Confirm Revocation</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

