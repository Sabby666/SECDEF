"use client";

import React, { useState, useEffect } from "react";
import { Cpu, ShieldCheck, CheckCircle, AlertTriangle, Plus, RefreshCw } from "lucide-react";
import { getSession } from "../lib/api";
import Badge from "../components/Badge";

interface AutomationPolicy {
  id: string;
  name: string;
  description: string;
  is_enabled: boolean;
  allow_auto_approval: boolean;
  max_risk_class: string;
  allowed_action_types: string[];
  created_at: string;
}

export default function AutomationPage() {
  const [policies, setPolicies] = useState<AutomationPolicy[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [newPolicyName, setNewPolicyName] = useState<string>("");
  const [selectedActions, setSelectedActions] = useState<string[]>([
    "VERIFY_HTTP_ENDPOINT",
    "ACKNOWLEDGE_FINDING"
  ]);

  const session = getSession();

  const fetchPolicies = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/organizations/${session.orgId}/automation/policies`, {
        headers: {
          "x-user-id": session.userId,
          "x-org-id": session.orgId
        }
      });
      if (res.ok) {
        const data = await res.json();
        setPolicies(data.items || []);
      }
    } catch (err) {
      console.error("Failed to fetch automation policies", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPolicyName) return;

    try {
      const res = await fetch(`/api/v1/organizations/${session.orgId}/automation/policies`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-user-id": session.userId,
          "x-org-id": session.orgId
        },
        body: JSON.stringify({
          name: newPolicyName,
          description: "Tenant-scoped automated security policy",
          is_enabled: true,
          allow_auto_approval: false,
          max_risk_class: "CLASS_B_LOW_RISK_REVERSIBLE",
          allowed_action_types: selectedActions
        })
      });
      if (res.ok) {
        setNewPolicyName("");
        fetchPolicies();
      }
    } catch (err) {
      console.error("Failed to create policy", err);
    }
  };

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Automation Policies
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Tenant-scoped security orchestration rules, risk bounds, and automated authorization policies.
          </p>
        </div>
        <button 
          onClick={fetchPolicies} 
          className="btn-secondary"
          style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
        </button>
      </div>

      {session.userRole === "ADMIN" && (
        <div style={{
          backgroundColor: "#FFFFFF",
          border: "1px solid #E5E7EB",
          borderRadius: "6px",
          padding: "20px",
          marginBottom: "24px"
        }}>
          <div style={{ fontSize: "16px", fontWeight: 600, color: "#111827", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
            <Plus size={16} style={{ color: "#2563EB" }} /> Create Automation Policy
          </div>
          <form onSubmit={handleCreatePolicy} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            <input
              type="text"
              placeholder="Policy Name (e.g., Low-Risk Verification Policy)"
              value={newPolicyName}
              onChange={(e) => setNewPolicyName(e.target.value)}
              className="input-field"
              style={{ height: "36px", fontSize: "13px" }}
            />
            <div style={{ fontSize: "12px", color: "#4B5563" }}>
              Allowed Action Types: <strong>VERIFY_HTTP_ENDPOINT, ACKNOWLEDGE_FINDING, CREATE_REMEDIATION_TASK, MARK_EXPECTED_STATE</strong>
            </div>
            <button
              type="submit"
              className="btn-primary"
              style={{ alignSelf: "flex-start", height: "36px", fontSize: "13px" }}
            >
              Create Policy
            </button>
          </form>
        </div>
      )}

      <div style={{
        backgroundColor: "#FFFFFF",
        border: "1px solid #E5E7EB",
        borderRadius: "6px",
        overflow: "hidden"
      }}>
        <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
          Active Tenant Policies ({policies.length})
        </div>

        {loading ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading policies...</div>
        ) : policies.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>
            No explicit policies configured. Default fail-closed policy requires explicit human approval for all state-changing actions.
          </div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Policy Name</th>
                <th>Max Risk Class</th>
                <th>Auto Approval</th>
                <th>Allowed Actions</th>
                <th style={{ textAlign: "right" }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id}>
                  <td style={{ fontWeight: 600, color: "#111827" }}>{p.name}</td>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>{p.max_risk_class}</td>
                  <td>
                    <Badge variant={p.allow_auto_approval ? "verified" : "low"}>
                      {p.allow_auto_approval ? "ALLOWED" : "DISABLED"}
                    </Badge>
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>{p.allowed_action_types.join(", ")}</td>
                  <td style={{ textAlign: "right" }}>
                    <Badge variant={p.is_enabled ? "verified" : "low"}>
                      {p.is_enabled ? "ENABLED" : "DISABLED"}
                    </Badge>
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

