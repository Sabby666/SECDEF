"use client";

import React, { useEffect, useState } from "react";
import { 
  Globe, Play, CheckCircle2, Plus, Trash2, 
  RefreshCw, FileText, ArrowRight 
} from "lucide-react";
import { 
  listDomains, createDomain, verifyDomain, deleteDomain, 
  listScans, triggerScan, getScanObservations, getSession 
} from "../lib/api";
import { Domain, Scan, Observation, UserRole } from "../lib/types";
import Badge from "../components/Badge";

export default function DomainsAndScansPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [domains, setDomains] = useState<Domain[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [role, setRole] = useState<UserRole>("ADMIN");

  // Onboarding Step state
  const [activeStep, setActiveStep] = useState<number>(1);

  // Create Domain Modal
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [newDomainName, setNewDomainName] = useState("");
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // Verification & Triggering State
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [triggeringDomainId, setTriggeringDomainId] = useState<string | null>(null);
  const [scanFeedback, setScanFeedback] = useState<string | null>(null);

  // Observations Viewer Modal
  const [obsModalOpen, setObsModalOpen] = useState(false);
  const [targetScanId, setTargetScanId] = useState<string | null>(null);
  const [observations, setObservations] = useState<Observation[]>([]);
  const [obsLoading, setObsLoading] = useState(false);

  const loadDomainsAndScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      setRole(session.userRole);
      const orgId = session.orgId;

      const [domRes, scnRes] = await Promise.all([
        listDomains(orgId),
        listScans(orgId)
      ]);

      setDomains(domRes || []);
      setScans(scnRes || []);
    } catch (err: any) {
      setError(err.message || "Failed to load domain and scan operational state");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDomainsAndScans();
  }, []);

  const handleCreateDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomainName.trim()) return;
    setCreateSubmitting(true);
    setError(null);
    try {
      const session = getSession();
      await createDomain(session.orgId, newDomainName.trim());
      setCreateModalOpen(false);
      setNewDomainName("");
      setActiveStep(2);
      await loadDomainsAndScans();
    } catch (err: any) {
      setError(err.message || "Failed to register seed domain");
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleVerifyDomain = async (domainId: string) => {
    setVerifyingId(domainId);
    setError(null);
    try {
      const session = getSession();
      await verifyDomain(session.orgId, domainId);
      setActiveStep(3);
      await loadDomainsAndScans();
    } catch (err: any) {
      setError(err.message || "Domain verification failed");
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDeleteDomain = async (domainId: string) => {
    if (!confirm("Are you sure you want to delete this domain?")) return;
    setError(null);
    try {
      const session = getSession();
      await deleteDomain(session.orgId, domainId);
      await loadDomainsAndScans();
    } catch (err: any) {
      setError(err.message || "Failed to delete domain");
    }
  };

  const handleTriggerScan = async (domainId: string) => {
    setTriggeringDomainId(domainId);
    setError(null);
    setScanFeedback(null);
    try {
      const session = getSession();
      const job = await triggerScan(session.orgId, domainId);
      setScanFeedback(`Scan job triggered successfully! Job Nonce: ${job.job_nonce}`);
      setActiveStep(4);
      await loadDomainsAndScans();
    } catch (err: any) {
      setError(err.message || "Failed to trigger domain scan");
    } finally {
      setTriggeringDomainId(null);
    }
  };

  const handleViewObservations = async (scanId: string) => {
    setTargetScanId(scanId);
    setObsModalOpen(true);
    setObsLoading(true);
    try {
      const session = getSession();
      const obsList = await getScanObservations(session.orgId, scanId);
      setObservations(obsList || []);
    } catch (err: any) {
      setError(err.message || "Failed to load scan observations");
    } finally {
      setObsLoading(false);
    }
  };

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Domain Onboarding & Monitoring
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Register seed domains, verify ownership DNS TXT tokens, and configure discovery schedules.
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px" }}>
          {role === "ADMIN" && (
            <button onClick={() => setCreateModalOpen(true)} className="btn-primary" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}>
              <Plus size={14} /> Add Target Domain
            </button>
          )}
          <button onClick={loadDomainsAndScans} className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}>
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {/* Guided 5-Step Onboarding Progress Bar */}
      <div style={{ backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "16px", marginBottom: "24px" }}>
        <div style={{ fontSize: "12px", color: "#9CA3AF", marginBottom: "12px", fontWeight: 600 }}>
          GUIDED SETUP WORKFLOW
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          {[
            { step: 1, label: "1 Enter Domain" },
            { step: 2, label: "2 Verify Ownership" },
            { step: 3, label: "3 Configure Monitoring" },
            { step: 4, label: "4 Discovery" },
            { step: 5, label: "5 Review" }
          ].map((s) => (
            <div
              key={s.step}
              onClick={() => setActiveStep(s.step)}
              style={{
                fontSize: "13px",
                fontWeight: activeStep === s.step ? 600 : 400,
                color: activeStep === s.step ? "#2563EB" : "#4B5563",
                cursor: "pointer",
                padding: "4px 8px",
                borderRadius: "4px",
                backgroundColor: activeStep === s.step ? "#EFF6FF" : "transparent"
              }}
            >
              {s.label}
            </div>
          ))}
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 14px", backgroundColor: "#FEF2F2", border: "1px solid #FCA5A5", color: "#DC2626", borderRadius: "6px", fontSize: "13px" }}>
          {error}
        </div>
      )}

      {scanFeedback && (
        <div style={{ marginBottom: "16px", padding: "10px 14px", backgroundColor: "#F0FDF4", border: "1px solid #86EFAC", color: "#16A34A", borderRadius: "6px", fontSize: "13px" }}>
          {scanFeedback}
        </div>
      )}

      {/* Domain Monitoring Table */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden", marginBottom: "24px" }}>
        <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
          Monitored Target Domains ({domains.length})
        </div>

        {loading ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading domains...</div>
        ) : domains.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            No seed domains registered yet. Click "Add Target Domain" to begin setup.
          </div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Domain Name</th>
                <th>Verification Token</th>
                <th>Schedule</th>
                <th>Ownership Status</th>
                <th>Registered At</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {domains.map((d) => (
                <tr key={d.id}>
                  <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600, color: "#111827" }}>
                    {d.domain_name}
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>
                    {d.verification_token}
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    Continuous (24h)
                  </td>
                  <td>
                    <Badge variant={d.status === "verified" ? "verified" : "high"}>
                      {d.status.toUpperCase()}
                    </Badge>
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    {new Date(d.created_at).toLocaleDateString()}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "flex", gap: "6px", justifyContent: "flex-end" }}>
                      {d.status !== "verified" && role === "ADMIN" && (
                        <button
                          onClick={() => handleVerifyDomain(d.id)}
                          disabled={verifyingId === d.id}
                          className="btn-secondary"
                          style={{ padding: "3px 8px", fontSize: "12px" }}
                        >
                          {verifyingId === d.id ? "Verifying..." : "Verify TXT"}
                        </button>
                      )}

                      {d.status === "verified" && role === "ADMIN" && (
                        <button
                          onClick={() => handleTriggerScan(d.id)}
                          disabled={triggeringDomainId === d.id}
                          className="btn-primary"
                          style={{ padding: "3px 8px", fontSize: "12px" }}
                        >
                          {triggeringDomainId === d.id ? "Queuing..." : "Run Scan"}
                        </button>
                      )}

                      {role === "ADMIN" && (
                        <button
                          onClick={() => handleDeleteDomain(d.id)}
                          className="btn-secondary"
                          style={{ padding: "3px 8px", fontSize: "12px", color: "#DC2626" }}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Recent Scan Pipeline Table */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
        <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
          Scan Worker Executions ({scans.length})
        </div>

        {scans.length === 0 ? (
          <div style={{ padding: "32px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            No scan executions recorded yet.
          </div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Job Nonce</th>
                <th>Scan Status</th>
                <th>Timing</th>
                <th style={{ textAlign: "right" }}>Observations</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#111827" }}>
                    {s.job_nonce}
                  </td>
                  <td>
                    <Badge variant={s.status === "completed" ? "verified" : s.status === "running" ? "medium" : "high"}>
                      {s.status.toUpperCase()}
                    </Badge>
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    {s.started_at ? new Date(s.started_at).toLocaleTimeString() : "Pending"}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <button
                      onClick={() => handleViewObservations(s.id)}
                      className="btn-secondary"
                      style={{ padding: "3px 8px", fontSize: "12px" }}
                    >
                      Inspect Raw
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Add Domain Modal */}
      {createModalOpen && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, backgroundColor: "rgba(17,24,39,0.4)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ backgroundColor: "#FFFFFF", borderRadius: "6px", width: "440px", maxWidth: "90%", padding: "20px", border: "1px solid #E5E7EB" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, color: "#111827", margin: "0 0 16px 0" }}>Register Target Domain</h3>
            <form onSubmit={handleCreateDomain} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Domain Name *</label>
                <input
                  required
                  type="text"
                  value={newDomainName}
                  onChange={(e) => setNewDomainName(e.target.value)}
                  placeholder="e.g. example.com"
                  className="input-field"
                  style={{ width: "100%", height: "36px", fontSize: "13px" }}
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "12px" }}>
                <button type="button" onClick={() => setCreateModalOpen(false)} className="btn-secondary" style={{ fontSize: "13px" }}>Cancel</button>
                <button type="submit" disabled={createSubmitting || !newDomainName.trim()} className="btn-primary" style={{ fontSize: "13px" }}>
                  {createSubmitting ? "Registering..." : "Register Domain"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Observations Modal */}
      {obsModalOpen && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, backgroundColor: "rgba(17,24,39,0.4)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ backgroundColor: "#FFFFFF", borderRadius: "6px", width: "640px", maxWidth: "90%", maxHeight: "80vh", overflowY: "auto", padding: "20px", border: "1px solid #E5E7EB" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h3 style={{ fontSize: "16px", fontWeight: 600, color: "#111827", margin: 0 }}>Scan Job Observations ({observations.length})</h3>
              <button onClick={() => setObsModalOpen(false)} className="btn-secondary" style={{ padding: "4px 8px", fontSize: "12px" }}>✕</button>
            </div>

            {obsLoading ? (
              <div style={{ padding: "24px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading observations...</div>
            ) : observations.length === 0 ? (
              <div style={{ padding: "24px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No raw observations produced.</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {observations.map((obs) => (
                  <div key={obs.id} style={{ backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "4px", padding: "10px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px", fontSize: "12px" }}>
                      <Badge variant="medium">{obs.observation_type}</Badge>
                      <span style={{ fontFamily: "monospace", color: "#111827" }}>{obs.target}</span>
                    </div>
                    <pre style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "4px", padding: "8px", fontSize: "11px", fontFamily: "monospace", overflowX: "auto", margin: 0 }}>
                      {JSON.stringify(obs.raw_data, null, 2)}
                    </pre>
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

