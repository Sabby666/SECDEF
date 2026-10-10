"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { 
  ShieldAlert, Play, RefreshCw, AlertTriangle, CheckCircle, 
  Search, ArrowRight 
} from "lucide-react";
import { listExposures, triggerExposureCorrelation, getSession } from "../lib/api";
import { ExposureCondition } from "../lib/types";
import Badge from "../components/Badge";

export default function ExposureIntelligencePage() {
  const [exposures, setExposures] = useState<ExposureCondition[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [priorityFilter, setPriorityFilter] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const session = getSession();
      const params: any = {};
      if (statusFilter !== "all") params.status = statusFilter;
      if (priorityFilter !== "all") params.priority_band = priorityFilter;
      const data = await listExposures(session.orgId, params);
      setExposures(data);
    } catch (e: any) {
      console.error("Failed to load exposure data", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [statusFilter, priorityFilter]);

  const handleTriggerCorrelation = async () => {
    setTriggering(true);
    setMessage(null);
    try {
      const session = getSession();
      const run = await triggerExposureCorrelation(session.orgId);
      setMessage({
        text: `Exposure correlation run ${run.id.slice(0, 8)} completed. Detected ${run.conditions_detected} condition(s) and ${run.paths_detected} path(s).`,
        type: "success"
      });
      await loadData();
    } catch (err: any) {
      setMessage({
        text: err.message || "Failed to trigger exposure correlation",
        type: "error"
      });
    } finally {
      setTriggering(false);
    }
  };

  const filteredExposures = exposures.filter(e => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      e.title.toLowerCase().includes(term) ||
      e.condition_type.toLowerCase().includes(term) ||
      e.explanation.toLowerCase().includes(term)
    );
  });

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Exposure Intelligence
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Deterministic correlation layer deriving exposure conditions and attack path chains.
          </p>
        </div>
        <div style={{ display: "flex", gap: "8px" }}>
          <button
            onClick={loadData}
            disabled={loading}
            className="btn-secondary"
            style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}
          >
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
          </button>
          <button
            onClick={handleTriggerCorrelation}
            disabled={triggering}
            className="btn-primary"
            style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}
          >
            <Play size={14} />
            {triggering ? "Correlating..." : "Run Correlation"}
          </button>
        </div>
      </div>

      {message && (
        <div style={{ marginBottom: "16px", padding: "10px 14px", backgroundColor: message.type === "success" ? "#F0FDF4" : "#FEF2F2", border: `1px solid ${message.type === "success" ? "#86EFAC" : "#FCA5A5"}`, color: message.type === "success" ? "#16A34A" : "#DC2626", borderRadius: "6px", fontSize: "13px" }}>
          {message.text}
        </div>
      )}

      {/* Filter Bar */}
      <div style={{ backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "12px 16px", marginBottom: "20px", display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ flex: 1, minWidth: "240px", position: "relative" }}>
          <Search size={16} style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)", color: "#9CA3AF" }} />
          <input
            type="text"
            className="input-field"
            placeholder="Search exposure conditions..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ paddingLeft: "32px", width: "100%", height: "36px", fontSize: "13px" }}
          />
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="input-field"
          style={{ height: "36px", fontSize: "13px" }}
        >
          <option value="all">All Statuses</option>
          <option value="active">Active</option>
          <option value="reopened">Reopened</option>
          <option value="resolved">Resolved</option>
        </select>

        <select
          value={priorityFilter}
          onChange={(e) => setPriorityFilter(e.target.value)}
          className="input-field"
          style={{ height: "36px", fontSize: "13px" }}
        >
          <option value="all">All Priorities</option>
          <option value="CRITICAL_EXPOSURE">Critical</option>
          <option value="HIGH_EXPOSURE">High</option>
          <option value="MEDIUM_EXPOSURE">Medium</option>
          <option value="LOW_EXPOSURE">Low</option>
        </select>
      </div>

      {/* Table */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
        {loading ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading exposure conditions...</div>
        ) : filteredExposures.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No exposure conditions found matching current filters.</div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Priority</th>
                <th>Condition Title</th>
                <th>Condition Type</th>
                <th>Status</th>
                <th>Last Seen</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredExposures.map((exp) => (
                <tr key={exp.id}>
                  <td>
                    <Badge variant={exp.priority_band === "CRITICAL_EXPOSURE" ? "critical" : exp.priority_band === "HIGH_EXPOSURE" ? "high" : "medium"}>
                      {exp.priority_band.replace("_EXPOSURE", "")}
                    </Badge>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: "#111827", fontSize: "13px" }}>{exp.title}</div>
                    <div style={{ fontSize: "12px", color: "#4B5563" }}>{exp.explanation}</div>
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>{exp.condition_type}</td>
                  <td>
                    <Badge variant={exp.status === "active" ? "critical" : exp.status === "resolved" ? "verified" : "medium"}>
                      {exp.status.toUpperCase()}
                    </Badge>
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    {new Date(exp.last_seen_at).toLocaleDateString()}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <Link
                      href={`/exposures/${exp.id}`}
                      className="btn-secondary"
                      style={{ padding: "3px 8px", fontSize: "12px", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: "4px" }}
                    >
                      Investigate <ArrowRight size={12} />
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

