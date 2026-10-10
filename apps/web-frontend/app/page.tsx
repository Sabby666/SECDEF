"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { 
  Server, Target, ShieldAlert, Zap, Globe, CheckCircle2, 
  ArrowRight, AlertTriangle, RefreshCw, Clock, Layers, Filter, Download, Play
} from "lucide-react";
import { 
  listAssets, listFindings, listRiskAssessments, listChanges, 
  listScans, listNotifications, getSession 
} from "./lib/api";
import { Asset, Finding, RiskAssessment, Change, Scan, Notification } from "./lib/types";
import { Badge } from "./components/ui/Badge";
import { ErrorAlert } from "./components/ui/ErrorAlert";

export default function OverviewPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [riskAssessments, setRiskAssessments] = useState<RiskAssessment[]>([]);
  const [changes, setChanges] = useState<Change[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);

  const [orgId, setOrgId] = useState("org-001");
  const [role, setRole] = useState("ADMIN");

  const loadDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      setOrgId(session.orgId);
      setRole(session.userRole);
      const activeOrgId = session.orgId;

      const [astRes, findRes, riskRes, chgRes, scnRes, notifRes] = await Promise.all([
        listAssets(activeOrgId),
        listFindings(activeOrgId),
        listRiskAssessments(activeOrgId),
        listChanges(activeOrgId, { limit: 10 }),
        listScans(activeOrgId),
        listNotifications(activeOrgId, { limit: 10 })
      ]);

      setAssets(astRes.items || []);
      setFindings(findRes.items || []);
      setRiskAssessments(riskRes.items || []);
      setChanges(chgRes.items || []);
      setScans(scnRes || []);
      setNotifications(notifRes.items || []);
    } catch (err: any) {
      setError(err.message || "Failed to load attack surface overview");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  const openFindings = findings.filter(f => f.status === "open" || f.status === "reopened");
  const subdomainsCount = assets.filter(a => a.asset_type === "subdomain").length;
  const publicServicesCount = assets.filter(a => a.asset_type === "service" || a.asset_type === "ip_address").length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      
      {/* 1. Page Header & Actions */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: "var(--text-primary)", letterSpacing: "-0.2px" }}>
            Attack Surface Overview
          </h1>
          <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Unified perimeter telemetry, internet-facing assets, and active exposure vectors.
          </p>
        </div>
        
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <button onClick={loadDashboardData} className="asm-btn asm-btn-secondary" style={{ padding: "5px 10px", fontSize: "12px" }}>
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
          <Link href="/discovery" className="asm-btn asm-btn-dark" style={{ padding: "5px 12px", fontSize: "12px" }}>
            <Play size={13} />
            <span>Run Discovery</span>
          </Link>
        </div>
      </div>

      {/* 2. Metadata Inline Banner Strip */}
      <div style={{
        padding: "6px 14px",
        backgroundColor: "var(--bg-surface-secondary)",
        border: "1px solid var(--border-subtle)",
        borderRadius: "5px",
        fontSize: "12px",
        color: "var(--text-secondary)",
        display: "flex",
        alignItems: "center",
        gap: "16px"
      }}>
        <div>Organization: <span className="mono" style={{ color: "var(--text-primary)", fontWeight: 600 }}>{orgId}</span></div>
        <div style={{ color: "var(--border-subtle)" }}>•</div>
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          Status: <span style={{ color: "#16A34A", fontWeight: 600, display: "flex", alignItems: "center", gap: "3px" }}><CheckCircle2 size={12} /> Active Monitoring</span>
        </div>
        <div style={{ color: "var(--border-subtle)" }}>•</div>
        <div>Role Context: <span style={{ color: "var(--text-primary)", fontWeight: 500 }}>{role}</span></div>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadDashboardData} />}

      {/* 3. Compact Metric Ribbon */}
      <div className="asm-metric-ribbon">
        <div className="asm-metric-item">
          <div className="asm-metric-label">Discovered Assets</div>
          <div className="asm-metric-value">
            {assets.length}
            <span className="asm-metric-subtext" style={{ color: "var(--text-secondary)", fontWeight: 400 }}>Total inventory</span>
          </div>
        </div>

        <div className="asm-metric-item">
          <div className="asm-metric-label">Apex & Subdomains</div>
          <div className="asm-metric-value">
            {subdomainsCount}
            <span className="asm-metric-subtext">Monitored hostnames</span>
          </div>
        </div>

        <div className="asm-metric-item">
          <div className="asm-metric-label">Public Services</div>
          <div className="asm-metric-value">
            {publicServicesCount}
            <span className="asm-metric-subtext">Open services / IPs</span>
          </div>
        </div>

        <div className="asm-metric-item">
          <div className="asm-metric-label">Open Findings</div>
          <div className="asm-metric-value">
            {openFindings.length}
            <span className="asm-metric-subtext" style={{ color: openFindings.length > 0 ? "#DC2626" : "#16A34A", fontWeight: 500 }}>
              {openFindings.length > 0 ? "Requires review" : "Clean state"}
            </span>
          </div>
        </div>
      </div>

      {/* 4. Two-Column Operational Layout */}
      <div style={{ display: "grid", gridTemplateColumns: "1.3fr 1fr", gap: "16px" }}>
        
        {/* Left Column: Attention Required */}
        <div className="asm-card">
          <div className="asm-card-header">
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <AlertTriangle style={{ width: "15px", height: "15px", color: openFindings.length > 0 ? "#DC2626" : "var(--text-tertiary)" }} />
              <span style={{ fontSize: "14px", fontWeight: 600, color: "var(--text-primary)" }}>Attention Required</span>
              {openFindings.length > 0 && (
                <span style={{ fontSize: "11px", fontWeight: 600, color: "#DC2626", backgroundColor: "#FEF2F2", padding: "1px 6px", borderRadius: "9999px", border: "1px solid #FCA5A5" }}>
                  {openFindings.length} Actionable
                </span>
              )}
            </div>
            <Link href="/findings" style={{ fontSize: "12px", color: "var(--accent)", fontWeight: 500 }}>
              View all findings →
            </Link>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {openFindings.length === 0 ? (
              <div style={{ padding: "24px 12px", textAlign: "center", color: "var(--text-tertiary)", fontSize: "13px" }}>
                ✓ No active security findings requiring attention.
              </div>
            ) : (
              openFindings.slice(0, 5).map(f => (
                <div key={f.id} style={{
                  padding: "10px 12px",
                  borderRadius: "5px",
                  border: "1px solid var(--border-subtle)",
                  backgroundColor: "var(--bg-primary)"
                }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <Badge variant="critical">{f.status.toUpperCase()}</Badge>
                      <span style={{ fontSize: "12.5px", fontWeight: 600, color: "var(--text-primary)" }}>{f.title}</span>
                    </div>
                    <Link href={`/findings/${f.id}`} className="asm-btn asm-btn-secondary" style={{ padding: "2px 8px", fontSize: "11px" }}>
                      Review
                    </Link>
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "6px" }}>
                    {f.description || "No description provided."}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column: Recent Changes Timeline Feed */}
        <div className="asm-card">
          <div className="asm-card-header">
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Clock style={{ width: "15px", height: "15px", color: "var(--accent)" }} />
              <span style={{ fontSize: "14px", fontWeight: 600, color: "var(--text-primary)" }}>Recent Changes</span>
            </div>
            <Link href="/changes" style={{ fontSize: "11px", color: "var(--accent)", fontWeight: 500 }}>
              View timeline →
            </Link>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {changes.length === 0 ? (
              <div style={{ padding: "24px 12px", textAlign: "center", color: "var(--text-tertiary)", fontSize: "13px" }}>
                No perimeter changes recorded for this organization.
              </div>
            ) : (
              changes.slice(0, 5).map(c => (
                <div key={c.id} style={{ display: "flex", gap: "10px", fontSize: "12px" }}>
                  <span style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "#2563EB", marginTop: "5px", flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{c.change_type.replace(/_/g, " ")}</span>
                      <span style={{ color: "var(--text-tertiary)", fontSize: "11px" }}>{new Date(c.detected_at).toLocaleDateString()}</span>
                    </div>
                    <p style={{ color: "var(--text-secondary)", fontSize: "11.5px", marginTop: "2px" }}>
                      Entity: <span className="mono" style={{ color: "var(--text-brand)" }}>{c.entity_identifier}</span>
                    </p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

      </div>

      {/* 5. Recent Scan Activity Table Section */}
      <div className="asm-card" style={{ padding: "0", overflow: "hidden" }}>
        <div className="asm-card-header" style={{ padding: "12px 16px", marginBottom: "0", borderBottom: "1px solid var(--border-subtle)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Layers style={{ width: "15px", height: "15px", color: "var(--accent)" }} />
            <span style={{ fontSize: "14px", fontWeight: 600, color: "var(--text-primary)" }}>Recent Scan Activity</span>
          </div>
          <Link href="/domains" className="asm-btn asm-btn-secondary" style={{ padding: "3px 8px", fontSize: "11.5px" }}>
            Manage Domains
          </Link>
        </div>

        <table className="asm-table">
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Status</th>
              <th>Created</th>
              <th>Completed</th>
              <th style={{ textAlign: "right" }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {scans.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ textAlign: "center", padding: "20px", color: "var(--text-tertiary)" }}>
                  No recent scans recorded. Start domain discovery or trigger a scan to collect perimeter telemetry.
                </td>
              </tr>
            ) : (
              scans.slice(0, 5).map(s => (
                <tr key={s.id}>
                  <td className="mono" style={{ fontWeight: 600, color: "#111827" }}>{s.id.slice(0, 8)}...</td>
                  <td><Badge variant={s.status === "completed" ? "active" : "pending"}>{s.status.toUpperCase()}</Badge></td>
                  <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>{new Date(s.created_at).toLocaleString()}</td>
                  <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>{s.completed_at ? new Date(s.completed_at).toLocaleString() : "-"}</td>
                  <td style={{ textAlign: "right" }}>
                    <Link href="/domains" style={{ fontSize: "12px", color: "var(--accent)", fontWeight: 500 }}>
                      View Domain
                    </Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

    </div>
  );
}
