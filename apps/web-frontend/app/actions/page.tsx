"use client";

import React, { useState, useEffect } from "react";
import { CheckCircle2, AlertCircle, Clock, RotateCcw, Shield, Play, RefreshCw } from "lucide-react";
import { getSession, listActions, approveAction } from "../lib/api";
import Badge from "../components/Badge";

interface ActionExecution {
  id: string;
  action_type: string;
  target_type: string;
  target_identifier: string;
  risk_class: string;
  execution_state: string;
  authorization_state: string;
  approval_requirement: string;
  requested_by: string;
  verification_state: string;
  rollback_state: string;
  idempotency_key: string;
  created_at: string;
}

export default function ActionsPage() {
  const [executions, setExecutions] = useState<ActionExecution[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const session = getSession();

  const fetchActions = async () => {
    setLoading(true);
    try {
      const data = await listActions(session.orgId);
      setExecutions(data.items || []);
    } catch (err) {
      console.error("Failed to fetch actions", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchActions();
  }, []);

  const handleApprove = async (actionId: string, decision: "APPROVED" | "REJECTED") => {
    try {
      await approveAction(session.orgId, actionId, decision);
      await fetchActions();
    } catch (err) {
      console.error("Failed to approve/reject action", err);
    }
  };

  const handleExecute = async (actionId: string) => {
    try {
      const res = await fetch(`/api/v1/organizations/${session.orgId}/actions/${actionId}/execute`, {
        method: "POST",
        headers: {
          "x-user-id": session.userId,
          "x-org-id": session.orgId
        }
      });
      if (res.ok) {
        fetchActions();
      }
    } catch (err) {
      console.error("Failed to execute action", err);
    }
  };

  const handleRollback = async (actionId: string) => {
    try {
      const res = await fetch(`/api/v1/organizations/${session.orgId}/actions/${actionId}/rollback`, {
        method: "POST",
        headers: {
          "x-user-id": session.userId,
          "x-org-id": session.orgId
        }
      });
      if (res.ok) {
        fetchActions();
      }
    } catch (err) {
      console.error("Failed to rollback action", err);
    }
  };

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Actions & Approvals
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Human-in-the-loop action orchestration, authorization controls, and deterministic rollbacks.
          </p>
        </div>
        <button 
          onClick={fetchActions} 
          className="btn-secondary" 
          style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
        </button>
      </div>

      {/* Main Executions & Approvals Table */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
        <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
          Pending Approvals & Action Executions ({executions.length})
        </div>

        {loading ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            Loading action executions...
          </div>
        ) : executions.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            No action executions recorded yet. Actions triggered by discovery or remediation will appear here for authorization.
          </div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Action</th>
                <th>Target Identifier</th>
                <th>Requested By</th>
                <th>Risk Class</th>
                <th>Authorization</th>
                <th>Status</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {executions.map((e) => (
                <tr key={e.id}>
                  <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600, color: "#111827" }}>
                    {e.action_type}
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>
                    {e.target_identifier || e.target_type}
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    {e.requested_by}
                  </td>
                  <td>
                    <Badge variant={e.risk_class === "CLASS_C" ? "critical" : e.risk_class === "CLASS_B" ? "high" : "low"}>
                      {e.risk_class}
                    </Badge>
                  </td>
                  <td>
                    <Badge variant={e.authorization_state === "AUTHORIZED" ? "verified" : e.authorization_state === "PENDING" ? "high" : "medium"}>
                      {e.authorization_state}
                    </Badge>
                  </td>
                  <td>
                    <Badge variant={e.execution_state === "SUCCEEDED" || e.execution_state === "VERIFIED" ? "verified" : e.execution_state === "PENDING_APPROVAL" ? "high" : "medium"}>
                      {e.execution_state}
                    </Badge>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "flex", gap: "6px", justifyContent: "flex-end" }}>
                      {e.execution_state === "PENDING_APPROVAL" && (session.userRole === "ADMIN" || session.userRole === "MEMBER") && (
                        <>
                          <button
                            onClick={() => handleApprove(e.id, "APPROVED")}
                            className="btn-primary"
                            style={{ padding: "3px 8px", fontSize: "12px" }}
                          >
                            Approve
                          </button>
                          <button
                            onClick={() => handleApprove(e.id, "REJECTED")}
                            className="btn-secondary"
                            style={{ padding: "3px 8px", fontSize: "12px", color: "#DC2626" }}
                          >
                            Reject
                          </button>
                        </>
                      )}

                      {e.execution_state === "APPROVED" && (
                        <button
                          onClick={() => handleExecute(e.id)}
                          className="btn-primary"
                          style={{ padding: "3px 8px", fontSize: "12px" }}
                        >
                          Execute Now
                        </button>
                      )}

                      {e.execution_state === "SUCCEEDED" && session.userRole === "ADMIN" && e.rollback_state !== "ROLLED_BACK" && (
                        <button
                          onClick={() => handleRollback(e.id)}
                          className="btn-secondary"
                          style={{ padding: "3px 8px", fontSize: "12px", color: "#DC2626" }}
                        >
                          Rollback
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
    </div>
  );
}

