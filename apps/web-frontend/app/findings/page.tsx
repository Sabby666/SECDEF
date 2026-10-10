"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Target, Filter, ArrowRight, CheckCircle2, RefreshCw, ShieldCheck } from "lucide-react";
import { listFindings, acknowledgeFinding, verifyFinding, getSession } from "../lib/api";
import { Finding, UserRole } from "../lib/types";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { Table, Column } from "../components/ui/Table";
import { ErrorAlert } from "../components/ui/ErrorAlert";
import { Modal } from "../components/ui/Modal";
import { RBACGate } from "../components/ui/RBACGate";

export default function FindingsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [role, setRole] = useState<UserRole>("ADMIN");

  const [statusFilter, setStatusFilter] = useState<string>("");

  // Acknowledge Modal State
  const [ackModalOpen, setAckModalOpen] = useState(false);
  const [targetFindingId, setTargetFindingId] = useState<string | null>(null);
  const [ackReason, setAckReason] = useState("");
  const [ackProcessing, setAckProcessing] = useState(false);

  // Verification Processing State
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationFeedback, setVerificationFeedback] = useState<string | null>(null);

  const loadFindingsData = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      setRole(session.userRole);
      const res = await listFindings(session.orgId, {
        status: statusFilter || undefined,
        limit: 50
      });
      setFindings(res.items || []);
    } catch (err: any) {
      setError(err.message || "Failed to load security findings");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindingsData();
  }, [statusFilter]);

  const handleOpenAcknowledge = (findingId: string) => {
    setTargetFindingId(findingId);
    setAckReason("");
    setAckModalOpen(true);
  };

  const handleAcknowledgeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetFindingId || !ackReason.trim()) return;
    setAckProcessing(true);
    setError(null);
    try {
      const session = getSession();
      await acknowledgeFinding(session.orgId, targetFindingId, ackReason);
      setAckModalOpen(false);
      await loadFindingsData();
    } catch (err: any) {
      setError(err.message || "Acknowledge operation failed");
    } finally {
      setAckProcessing(false);
    }
  };

  const handleTriggerVerification = async (findingId: string) => {
    setVerifyingId(findingId);
    setError(null);
    setVerificationFeedback(null);
    try {
      const session = getSession();
      const result = await verifyFinding(session.orgId, findingId);
      setVerificationFeedback(`Verification completed with result status: ${result.status}`);
      await loadFindingsData();
    } catch (err: any) {
      setError(err.message || "Verification trigger failed");
    } finally {
      setVerifyingId(null);
    }
  };

  const columns: Column<Finding>[] = [
    {
      key: "status",
      header: "Status",
      render: (f) => <Badge variant={f.status} />
    },
    {
      key: "title",
      header: "Finding Title",
      render: (f) => (
        <div>
          <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{f.title}</span>
          <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }} className="truncate max-w-md">{f.description}</div>
        </div>
      )
    },
    {
      key: "acknowledged_by",
      header: "Acknowledgement",
      render: (f) => (
        <div className="mono" style={{ fontSize: "11.5px" }}>
          {f.acknowledged_at ? (
            <span style={{ color: "var(--accent)" }}>
              Ack by {f.acknowledged_by || "Member"} ({new Date(f.acknowledged_at).toLocaleDateString()})
            </span>
          ) : (
            <span style={{ color: "var(--text-tertiary)", fontStyle: "italic" }}>Not Acknowledged</span>
          )}
        </div>
      )
    },
    {
      key: "created_at",
      header: "Created",
      render: (f) => <span style={{ fontSize: "12px", color: "var(--text-tertiary)" }}>{new Date(f.created_at).toLocaleDateString()}</span>
    },
    {
      key: "actions",
      header: "Operations & Verification",
      render: (f) => (
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {f.status === "open" && (
            <RBACGate requiredRole="MEMBER" currentRole={role}>
              <button
                onClick={() => handleOpenAcknowledge(f.id)}
                className="asm-btn asm-btn-secondary"
                style={{ padding: "3px 8px", fontSize: "11.5px" }}
              >
                Acknowledge
              </button>
            </RBACGate>
          )}

          <RBACGate requiredRole="MEMBER" currentRole={role}>
            <button
              onClick={() => handleTriggerVerification(f.id)}
              disabled={verifyingId === f.id}
              className="asm-btn asm-btn-primary"
              style={{ padding: "3px 8px", fontSize: "11.5px" }}
            >
              <ShieldCheck style={{ width: "12px", height: "12px" }} />
              <span>{verifyingId === f.id ? "Verifying..." : "Verify Scan"}</span>
            </button>
          </RBACGate>

          <Link href={`/findings/${f.id}`} style={{ fontSize: "12px", color: "var(--accent)", fontWeight: 500, display: "flex", alignItems: "center", gap: "4px" }}>
            <span>Evidence</span>
            <ArrowRight style={{ width: "13px", height: "13px" }} />
          </Link>
        </div>
      )
    }
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: "var(--text-primary)" }}>
            Security Findings & Remediation Verification
          </h1>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Finding lifecycle: OPEN → ACKNOWLEDGED → IN_PROGRESS → RESOLVED / REOPENED.
          </p>
        </div>
        <button onClick={loadFindingsData} className="asm-btn asm-btn-secondary">
          <RefreshCw style={{ width: "14px", height: "14px" }} />
          <span>Refresh</span>
        </button>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadFindingsData} />}

      {verificationFeedback && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-800 rounded text-emerald-300 text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{verificationFeedback}</span>
        </div>
      )}

      {/* Filter Bar */}
      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Filter style={{ width: "14px", height: "14px", color: "var(--text-tertiary)" }} />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="asm-input"
              style={{ width: "200px" }}
            >
              <option value="">All Finding Statuses</option>
              <option value="open">OPEN</option>
              <option value="acknowledged">ACKNOWLEDGED</option>
              <option value="in_progress">IN_PROGRESS</option>
              <option value="resolved">RESOLVED (Verified)</option>
              <option value="reopened">REOPENED (Regression)</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Findings Table */}
      <Card title={`Active Findings Queue (${findings.length})`}>
        <Table
          columns={columns}
          data={findings}
          keyExtractor={(f) => f.id}
          loading={loading}
          emptyMessage="No findings match the selected status filter."
        />
      </Card>

      {/* Acknowledge Modal */}
      <Modal
        isOpen={ackModalOpen}
        onClose={() => setAckModalOpen(false)}
        title="Acknowledge Security Finding"
      >
        <form onSubmit={handleAcknowledgeSubmit} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <div className="text-xs text-slate-300">
            <span className="font-semibold text-amber-400">Important Invariant:</span> Acknowledging a finding records human operational review but <span className="font-bold underline">does NOT technical resolve</span> the finding. Automated resolution requires fresh scan proof.
          </div>

          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Reason for Acknowledgement *</label>
            <textarea
              required
              rows={3}
              value={ackReason}
              onChange={(e) => setAckReason(e.target.value)}
              placeholder="e.g. Under investigation by Infra team. Ticket #1042 opened."
              className="asm-input"
            />
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
            <button
              type="button"
              onClick={() => setAckModalOpen(false)}
              className="asm-btn asm-btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={ackProcessing || !ackReason.trim()}
              className="asm-btn asm-btn-primary"
            >
              {ackProcessing ? "Submitting..." : "Confirm Acknowledgement"}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
