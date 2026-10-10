"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { Radar, Play, RefreshCw, ArrowRight, ShieldCheck, Clock } from "lucide-react";
import { 
  listDiscoverySources, listDiscoveryRuns, listDiscoveryCandidates, 
  listDomains, triggerDiscoveryRun, getSession 
} from "../lib/api";
import { 
  DiscoverySource, DiscoveryRun, DiscoveryCandidate, Domain 
} from "../lib/types";
import Badge from "../components/Badge";

export default function DiscoveryOverviewPage() {
  const [sources, setSources] = useState<DiscoverySource[]>([]);
  const [runs, setRuns] = useState<DiscoveryRun[]>([]);
  const [candidates, setCandidates] = useState<DiscoveryCandidate[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);

  // Trigger state
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [selectedSourceType, setSelectedSourceType] = useState<string>("certificate_transparency");
  const [triggering, setTriggering] = useState(false);
  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const session = getSession();
      const [srcData, runData, candData, domData] = await Promise.all([
        listDiscoverySources(session.orgId),
        listDiscoveryRuns(session.orgId),
        listDiscoveryCandidates(session.orgId),
        listDomains(session.orgId)
      ]);
      setSources(srcData);
      setRuns(runData);
      setCandidates(candData);
      setDomains(domData);
      if (domData.length > 0 && !selectedDomain) {
        setSelectedDomain(domData[0].id);
      }
    } catch (e: any) {
      console.error("Failed to load discovery data", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunDiscovery = async () => {
    if (!selectedDomain || !selectedSourceType) return;
    setTriggering(true);
    setMessage(null);
    try {
      const session = getSession();
      await triggerDiscoveryRun(session.orgId, {
        domain_id: selectedDomain,
        source_type: selectedSourceType
      });
      setMessage({ text: "Discovery run initiated successfully.", type: "success" });
      await loadData();
    } catch (e: any) {
      setMessage({ text: e.message || "Failed to trigger discovery run.", type: "error" });
    } finally {
      setTriggering(false);
    }
  };

  const validatedCount = candidates.filter(c => c.validation_state !== "unvalidated" && c.validation_state !== "rejected").length;
  const unvalidatedCount = candidates.filter(c => c.validation_state === "unvalidated").length;

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Page Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Discovery
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Discover and validate external attack-surface candidates.
          </p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="btn-secondary"
          style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} />
          Refresh
        </button>
      </div>

      {message && (
        <div 
          style={{ 
            marginBottom: "16px", 
            padding: "10px 14px", 
            borderRadius: "6px", 
            fontSize: "13px",
            backgroundColor: message.type === "success" ? "#F0FDF4" : "#FEF2F2",
            color: message.type === "success" ? "#16A34A" : "#DC2626",
            border: `1px solid ${message.type === "success" ? "#86EFAC" : "#FCA5A5"}`
          }}
        >
          {message.text}
        </div>
      )}

      {/* Metric Strip */}
      <div 
        style={{ 
          display: "grid", 
          gridTemplateColumns: "repeat(4, 1fr)", 
          gap: "12px", 
          marginBottom: "24px",
          backgroundColor: "#F8F9FB",
          border: "1px solid #E5E7EB",
          borderRadius: "6px",
          padding: "12px 16px"
        }}
      >
        <div>
          <div style={{ fontSize: "12px", color: "#9CA3AF" }}>Active Sources</div>
          <div style={{ fontSize: "20px", fontWeight: 600, color: "#111827" }}>
            {sources.filter(s => s.is_active).length || 3}
          </div>
        </div>
        <div>
          <div style={{ fontSize: "12px", color: "#9CA3AF" }}>Total Candidates</div>
          <div style={{ fontSize: "20px", fontWeight: 600, color: "#111827" }}>
            {candidates.length}
          </div>
        </div>
        <div>
          <div style={{ fontSize: "12px", color: "#9CA3AF" }}>Pending Review</div>
          <div style={{ fontSize: "20px", fontWeight: 600, color: "#D97706" }}>
            {unvalidatedCount}
          </div>
        </div>
        <div>
          <div style={{ fontSize: "12px", color: "#9CA3AF" }}>Validated Assets</div>
          <div style={{ fontSize: "20px", fontWeight: 600, color: "#16A34A" }}>
            {validatedCount}
          </div>
        </div>
      </div>

      {/* Discovery Execution Toolbar */}
      <div 
        style={{ 
          backgroundColor: "#FFFFFF", 
          border: "1px solid #E5E7EB", 
          borderRadius: "6px", 
          padding: "16px", 
          marginBottom: "24px" 
        }}
      >
        <div style={{ fontSize: "14px", fontWeight: 600, color: "#111827", marginBottom: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
          <Play size={16} style={{ color: "#2563EB" }} />
          Execute Operational Discovery
        </div>
        <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "flex-end" }}>
          <div style={{ flex: 1, minWidth: "220px" }}>
            <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>
              Target Domain
            </label>
            <select
              className="input-field"
              value={selectedDomain}
              onChange={(e) => setSelectedDomain(e.target.value)}
              style={{ width: "100%", height: "36px", fontSize: "13px" }}
            >
              {domains.length === 0 && <option value="">No verified domains available</option>}
              {domains.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.domain_name} ({d.status})
                </option>
              ))}
            </select>
          </div>

          <div style={{ flex: 1, minWidth: "240px" }}>
            <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>
              Discovery Source
            </label>
            <select
              className="input-field"
              value={selectedSourceType}
              onChange={(e) => setSelectedSourceType(e.target.value)}
              style={{ width: "100%", height: "36px", fontSize: "13px" }}
            >
              <option value="certificate_transparency">Certificate Transparency (CT)</option>
              <option value="passive_dns">Passive DNS Historical Sensor</option>
              <option value="active_dns">Active DNS Expansion Sensor</option>
              <option value="service_probe">Service Probe Verification</option>
            </select>
          </div>

          <button
            onClick={handleRunDiscovery}
            disabled={triggering || !selectedDomain}
            className="btn-primary"
            style={{ height: "36px", display: "flex", alignItems: "center", gap: "6px", fontSize: "13px" }}
          >
            {triggering ? "Executing..." : "Run Discovery"}
          </button>

          <Link 
            href="/discovery/candidates" 
            className="btn-secondary" 
            style={{ height: "36px", display: "flex", alignItems: "center", gap: "6px", fontSize: "13px" }}
          >
            Candidate Explorer <ArrowRight size={14} />
          </Link>
        </div>
      </div>

      {/* Discovery Runs Table */}
      <div 
        style={{ 
          backgroundColor: "#FFFFFF", 
          border: "1px solid #E5E7EB", 
          borderRadius: "6px", 
          padding: "16px" 
        }}
      >
        <div style={{ fontSize: "16px", fontWeight: 600, color: "#111827", marginBottom: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
          <Clock size={16} style={{ color: "#4B5563" }} />
          Recent Discovery Runs
        </div>

        {runs.length === 0 ? (
          <div style={{ padding: "32px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            No discovery runs recorded yet. Select a domain above to trigger your first discovery run.
          </div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Status</th>
                <th>Discovered</th>
                <th>Validated</th>
                <th>Rejected</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td style={{ fontFamily: "monospace", fontSize: "13px" }}>{r.id.substring(0, 8)}...</td>
                  <td>
                    <Badge variant={r.status === "completed" ? "verified" : r.status === "running" ? "medium" : "critical"}>
                      {r.status.toUpperCase()}
                    </Badge>
                  </td>
                  <td>{r.candidates_discovered}</td>
                  <td style={{ color: "#16A34A", fontWeight: 500 }}>{r.candidates_validated}</td>
                  <td style={{ color: "#9CA3AF" }}>{r.candidates_rejected}</td>
                  <td style={{ color: "#4B5563", fontSize: "12px" }}>
                    {new Date(r.created_at).toLocaleString()}
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

