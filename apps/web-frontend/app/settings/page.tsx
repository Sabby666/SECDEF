"use client";

import React, { useState, useEffect } from "react";
import { Shield, Key, Users, Building, Lock, Globe, CheckCircle2, AlertCircle, Trash2 } from "lucide-react";
import { 
  getSession, 
  getOrgSettings, 
  updateOrgSettings, 
  listOrgMembers, 
  listOrgApiKeys, 
  createOrgApiKey, 
  revokeOrgApiKey 
} from "../lib/api";
import Badge from "../components/Badge";

export default function SettingsPage() {
  const session = getSession();
  const [activeTab, setActiveTab] = useState<"org" | "members" | "apikeys" | "egress" | "security">("org");
  const [loading, setLoading] = useState(false);
  const [feedbackMessage, setFeedbackMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Live state from backend
  const [orgData, setOrgData] = useState<{ org_id: string; name: string; slug: string; status: string } | null>(null);
  const [orgNameInput, setOrgNameInput] = useState("");
  const [members, setMembers] = useState<any[]>([]);
  const [apiKeys, setApiKeys] = useState<any[]>([]);

  // API Key Form State
  const [newKeyName, setNewKeyName] = useState("");
  const [createdToken, setCreatedToken] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const org = await getOrgSettings(session.orgId);
      setOrgData(org);
      setOrgNameInput(org.name);

      const memList = await listOrgMembers(session.orgId);
      setMembers(memList);

      const keys = await listOrgApiKeys(session.orgId);
      setApiKeys(keys);
    } catch (err: any) {
      setFeedbackMessage({ type: "error", text: err.message || "Failed to load organization settings" });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSaveOrg = async () => {
    setLoading(true);
    setFeedbackMessage(null);
    try {
      const updated = await updateOrgSettings(session.orgId, { name: orgNameInput, status: orgData?.status || "active" });
      setOrgData(updated);
      setFeedbackMessage({ type: "success", text: `Organization details successfully persisted to database (Audit Event Emitted)` });
    } catch (err: any) {
      setFeedbackMessage({ type: "error", text: err.message || "Failed to update organization settings" });
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateKey = async () => {
    if (!newKeyName.trim()) {
      setFeedbackMessage({ type: "error", text: "Please provide a key name" });
      return;
    }
    setLoading(true);
    setFeedbackMessage(null);
    try {
      const key = await createOrgApiKey(session.orgId, newKeyName.trim());
      setCreatedToken(key.token);
      setNewKeyName("");
      setFeedbackMessage({ type: "success", text: `API Key '${key.key_name}' generated and recorded to immutable audit log.` });
      const keys = await listOrgApiKeys(session.orgId);
      setApiKeys(keys);
    } catch (err: any) {
      setFeedbackMessage({ type: "error", text: err.message || "Failed to generate API key" });
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    setLoading(true);
    setFeedbackMessage(null);
    try {
      await revokeOrgApiKey(session.orgId, keyId);
      setFeedbackMessage({ type: "success", text: `API Key revoked and status persisted.` });
      const keys = await listOrgApiKeys(session.orgId);
      setApiKeys(keys);
    } catch (err: any) {
      setFeedbackMessage({ type: "error", text: err.message || "Failed to revoke API key" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Settings & Administration
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Manage organization configuration, access controls, API keys, and scan egress guards.
          </p>
        </div>
        <Badge variant={session.userRole === "ADMIN" || session.userRole === "OWNER" ? "critical" : "low"}>
          {session.userRole} PRIVILEGE LEVEL
        </Badge>
      </div>

      {feedbackMessage && (
        <div style={{
          marginBottom: "16px",
          padding: "10px 14px",
          backgroundColor: feedbackMessage.type === "success" ? "#F0FDF4" : "#FEF2F2",
          border: `1px solid ${feedbackMessage.type === "success" ? "#86EFAC" : "#FECACA"}`,
          color: feedbackMessage.type === "success" ? "#16A34A" : "#DC2626",
          borderRadius: "6px",
          fontSize: "13px",
          display: "flex",
          alignItems: "center",
          gap: "8px"
        }}>
          {feedbackMessage.type === "success" ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
          {feedbackMessage.text}
        </div>
      )}

      {/* Settings Navigation Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid #E5E7EB", marginBottom: "20px" }}>
        {[
          { id: "org", label: "Organization", icon: Building },
          { id: "members", label: "Members & Roles", icon: Users },
          { id: "apikeys", label: "API Keys", icon: Key },
          { id: "egress", label: "Scan Egress Guard", icon: Globe },
          { id: "security", label: "Security & RBAC", icon: Lock }
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id as any);
                setFeedbackMessage(null);
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                padding: "10px 16px",
                fontSize: "13px",
                fontWeight: isActive ? 600 : 400,
                color: isActive ? "#2563EB" : "#4B5563",
                borderBottom: isActive ? "2px solid #2563EB" : "none",
                background: "none",
                cursor: "pointer"
              }}
            >
              <Icon size={16} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: ORGANIZATION */}
      {activeTab === "org" && (
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "20px", maxWidth: "680px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600, color: "#111827", marginBottom: "16px" }}>
            Organization Details
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <div>
              <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Organization Identifier</label>
              <input type="text" disabled value={session.orgId} className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px", fontFamily: "monospace", backgroundColor: "#F8F9FB" }} />
            </div>
            <div>
              <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Organization Name</label>
              <input 
                type="text" 
                value={orgNameInput} 
                onChange={(e) => setOrgNameInput(e.target.value)} 
                className="input-field" 
                style={{ width: "100%", height: "36px", fontSize: "13px" }} 
              />
            </div>
            <div>
              <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Environment Scoping</label>
              <select className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }}>
                <option value="Production">Production & Staging Scoped</option>
                <option value="All">All Environments</option>
              </select>
            </div>
            <button 
              onClick={handleSaveOrg} 
              disabled={loading}
              className="btn-primary" 
              style={{ alignSelf: "flex-start", height: "36px", fontSize: "13px", marginTop: "8px" }}
            >
              {loading ? "Persisting to Backend..." : "Save Organization Changes"}
            </button>
          </div>
        </div>
      )}

      {/* TAB 2: MEMBERS & ROLES */}
      {activeTab === "members" && (
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
          <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
            Server-Authoritative Members & RBAC Roles ({members.length} Users)
          </div>
          <table className="asm-table">
            <thead>
              <tr>
                <th>User Identifier</th>
                <th>Full Name</th>
                <th>Email</th>
                <th>Server Role</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.user_id}>
                  <td style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 600, color: "#111827" }}>{m.user_id}</td>
                  <td style={{ fontSize: "13px", color: "#111827" }}>{m.full_name}</td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>{m.email}</td>
                  <td>
                    <Badge variant={m.role === "OWNER" || m.role === "ADMIN" ? "critical" : m.role === "MEMBER" ? "high" : "low"}>
                      {m.role}
                    </Badge>
                  </td>
                  <td><Badge variant="verified">{m.status.toUpperCase()}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 3: API KEYS */}
      {activeTab === "apikeys" && (
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
          <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
            Active Organization API Keys
          </div>
          
          <div style={{ padding: "16px", backgroundColor: "#F9FAFB", borderBottom: "1px solid #E5E7EB", display: "flex", gap: "10px", alignItems: "center" }}>
            <input 
              type="text" 
              placeholder="New API Key Name (e.g., CI/CD Pipeline Key)" 
              value={newKeyName} 
              onChange={(e) => setNewKeyName(e.target.value)} 
              style={{ flex: 1, height: "36px", padding: "0 10px", borderRadius: "4px", border: "1px solid #D1D5DB", fontSize: "13px" }}
            />
            <button 
              onClick={handleGenerateKey} 
              disabled={loading}
              className="btn-primary" 
              style={{ fontSize: "13px", height: "36px", whiteSpace: "nowrap" }}
            >
              + Generate New API Key
            </button>
          </div>

          {createdToken && (
            <div style={{ margin: "16px", padding: "12px", backgroundColor: "#FEF3C7", border: "1px solid #F59E0B", borderRadius: "4px", fontSize: "13px" }}>
              <strong>Generated Secret Token (copy now, will not be shown again):</strong>
              <div style={{ fontFamily: "monospace", marginTop: "4px", color: "#92400E", wordBreak: "break-all" }}>
                {createdToken}
              </div>
            </div>
          )}

          <table className="asm-table">
            <thead>
              <tr>
                <th>Key Identifier</th>
                <th>Key Name</th>
                <th>Prefix</th>
                <th>Scope</th>
                <th>Created</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {apiKeys.map((k) => (
                <tr key={k.id}>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>{k.id}</td>
                  <td style={{ fontWeight: 600, color: "#111827" }}>{k.key_name}</td>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>{k.key_prefix}</td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>{k.scope}</td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>{k.created_at.slice(0, 10)}</td>
                  <td>
                    <Badge variant={k.status === "ACTIVE" ? "verified" : "low"}>{k.status}</Badge>
                  </td>
                  <td>
                    {k.status === "ACTIVE" && (
                      <button 
                        onClick={() => handleRevokeKey(k.id)}
                        disabled={loading}
                        style={{ background: "none", border: "none", color: "#DC2626", cursor: "pointer", fontSize: "12px", display: "flex", alignItems: "center", gap: "4px" }}
                      >
                        <Trash2 size={13} /> Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 4: SCAN EGRESS GUARD */}
      {activeTab === "egress" && (
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "20px", maxWidth: "680px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600, color: "#111827", marginBottom: "8px" }}>
            Scan Egress Guard & SSRF Protection
          </div>
          <p style={{ fontSize: "13px", color: "#4B5563", marginBottom: "16px" }}>
            Strict outbound network rules enforced by scanner workers during active domain probes.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "13px" }}>
            <div style={{ padding: "12px", backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "4px" }}>
              <strong>Block Private Subnets (RFC 1918):</strong> Enabled (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            </div>
            <div style={{ padding: "12px", backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "4px" }}>
              <strong>Block Loopback & Link-Local:</strong> Enabled (127.0.0.0/8, 169.254.0.0/16)
            </div>
            <div style={{ padding: "12px", backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "4px" }}>
              <strong>Cloud Metadata Protection:</strong> Enabled (169.254.169.254 blocked)
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: SECURITY & RBAC */}
      {activeTab === "security" && (
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", padding: "20px", maxWidth: "680px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600, color: "#111827", marginBottom: "8px" }}>
            Security Controls & Authorization Boundaries
          </div>
          <p style={{ fontSize: "13px", color: "#4B5563", marginBottom: "16px" }}>
            Enforced enterprise authorization rules and tenant boundary isolation.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "13px" }}>
            <div style={{ padding: "12px", backgroundColor: "#F0FDF4", border: "1px solid #86EFAC", borderRadius: "4px", color: "#16A34A" }}>
              ✓ Multi-Tenant Isolation: Enforced via `x-org-id` DB filter gating
            </div>
            <div style={{ padding: "12px", backgroundColor: "#F0FDF4", border: "1px solid #86EFAC", borderRadius: "4px", color: "#16A34A" }}>
              ✓ Server-Authoritative RBAC: Role derived from server database, client state rejected
            </div>
            <div style={{ padding: "12px", backgroundColor: "#F0FDF4", border: "1px solid #86EFAC", borderRadius: "4px", color: "#16A34A" }}>
              ✓ Action Class Authorization: Class C (Irreversible) requires explicit ADMIN approval
            </div>
            <div style={{ padding: "12px", backgroundColor: "#F0FDF4", border: "1px solid #86EFAC", borderRadius: "4px", color: "#16A34A" }}>
              ✓ Audit Log Immutability: Real-time event recording into audit_events table
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
