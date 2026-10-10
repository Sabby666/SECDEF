"use client";

import React, { useEffect, useState } from "react";
import { 
  Bell, Globe, Shield, Plus, Send, RefreshCw, CheckCircle2, 
  AlertTriangle 
} from "lucide-react";
import { 
  listNotifications, listNotificationDestinations, createNotificationDestination,
  testWebhookDestination, listNotificationPolicies, createNotificationPolicy, getSession 
} from "../lib/api";
import { 
  Notification, NotificationDestination, NotificationPolicy, UserRole 
} from "../lib/types";
import Badge from "../components/Badge";

export default function NotificationsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [destinations, setDestinations] = useState<NotificationDestination[]>([]);
  const [policies, setPolicies] = useState<NotificationPolicy[]>([]);
  const [role, setRole] = useState<UserRole>("ADMIN");

  // Modal states
  const [destModalOpen, setDestModalOpen] = useState(false);
  const [destName, setDestName] = useState("");
  const [destChannel, setDestChannel] = useState("webhook");
  const [destUrl, setDestUrl] = useState("");
  const [destSecret, setDestSecret] = useState("");
  const [destSubmitting, setDestSubmitting] = useState(false);

  const [testModalOpen, setTestModalOpen] = useState(false);
  const [testUrl, setTestUrl] = useState("");
  const [testSecret, setTestSecret] = useState("");
  const [testSubmitting, setTestSubmitting] = useState(false);
  const [testFeedback, setTestFeedback] = useState<string | null>(null);

  const [policyModalOpen, setPolicyModalOpen] = useState(false);
  const [policyName, setPolicyName] = useState("");
  const [policyMinBand, setPolicyMinBand] = useState("HIGH");
  const [policyCooldown, setPolicyCooldown] = useState(60);
  const [policySubmitting, setPolicySubmitting] = useState(false);

  const loadNotificationsData = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      setRole(session.userRole);
      const orgId = session.orgId;

      const [notifRes, destRes, polRes] = await Promise.all([
        listNotifications(orgId, { limit: 50 }),
        listNotificationDestinations(orgId),
        listNotificationPolicies(orgId)
      ]);

      setNotifications(notifRes.items || []);
      setDestinations(destRes || []);
      setPolicies(polRes || []);
    } catch (err: any) {
      setError(err.message || "Failed to load notification operational state");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadNotificationsData();
  }, []);

  const handleCreateDestination = async (e: React.FormEvent) => {
    e.preventDefault();
    setDestSubmitting(true);
    setError(null);
    try {
      const session = getSession();
      await createNotificationDestination(session.orgId, {
        channel: destChannel,
        name: destName,
        config: { url: destUrl, signing_secret: destSecret || undefined }
      });
      setDestModalOpen(false);
      setDestName("");
      setDestUrl("");
      setDestSecret("");
      await loadNotificationsData();
    } catch (err: any) {
      setError(err.message || "Failed to create destination");
    } finally {
      setDestSubmitting(false);
    }
  };

  const handleTestWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    setTestSubmitting(true);
    setError(null);
    setTestFeedback(null);
    try {
      const session = getSession();
      const res = await testWebhookDestination(session.orgId, {
        url: testUrl,
        signing_secret: testSecret || undefined
      });
      setTestFeedback(`Webhook test SUCCESS! Response Code: ${res.response_code}`);
    } catch (err: any) {
      setError(err.message || "Webhook test failed");
    } finally {
      setTestSubmitting(false);
    }
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setPolicySubmitting(true);
    setError(null);
    try {
      const session = getSession();
      const activeDestIds = destinations.map(d => d.id);
      await createNotificationPolicy(session.orgId, {
        name: policyName,
        min_risk_band: policyMinBand,
        trigger_types: ["high_risk_new_asset", "risky_condition_resolved", "risk_reopened"],
        destination_ids: activeDestIds,
        cooldown_minutes: policyCooldown
      });
      setPolicyModalOpen(false);
      setPolicyName("");
      await loadNotificationsData();
    } catch (err: any) {
      setError(err.message || "Failed to create policy");
    } finally {
      setPolicySubmitting(false);
    }
  };

  return (
    <div style={{ padding: "24px", maxWidth: "1280px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 600, color: "#111827", margin: 0 }}>
            Notifications & Integrations
          </h1>
          <p style={{ fontSize: "14px", color: "#4B5563", marginTop: "4px", margin: 0 }}>
            Configure webhook egress, HMAC signing keys, and event notification policies.
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px" }}>
          {role === "ADMIN" && (
            <>
              <button onClick={() => setTestModalOpen(true)} className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}>
                <Send size={14} /> Test Webhook
              </button>
              <button onClick={() => setDestModalOpen(true)} className="btn-primary" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}>
                <Plus size={14} /> Destination
              </button>
              <button onClick={() => setPolicyModalOpen(true)} className="btn-primary" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}>
                <Plus size={14} /> Policy
              </button>
            </>
          )}
          <button onClick={loadNotificationsData} className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", height: "36px" }}>
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 14px", backgroundColor: "#FEF2F2", border: "1px solid #FCA5A5", color: "#DC2626", borderRadius: "6px", fontSize: "13px" }}>
          {error}
        </div>
      )}

      {/* Table 1: Dispatched Notifications */}
      <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden", marginBottom: "24px" }}>
        <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
          Dispatched Notification Events ({notifications.length})
        </div>

        {loading ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>Loading notifications...</div>
        ) : notifications.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No security notification events generated yet.</div>
        ) : (
          <table className="asm-table">
            <thead>
              <tr>
                <th>Trigger Type</th>
                <th>Title & Summary</th>
                <th>Event Identity Hash</th>
                <th>Dispatched At</th>
              </tr>
            </thead>
            <tbody>
              {notifications.map((n) => (
                <tr key={n.id}>
                  <td>
                    <Badge variant="medium">{n.trigger_type.replace(/_/g, " ")}</Badge>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: "#111827", fontSize: "13px" }}>{n.title}</div>
                    <div style={{ fontSize: "12px", color: "#4B5563" }}>{n.summary}</div>
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>
                    {n.event_identity.substring(0, 16)}...
                  </td>
                  <td style={{ fontSize: "12px", color: "#4B5563" }}>
                    {new Date(n.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Grid: Webhook Destinations & Notification Policies */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
        {/* Destinations */}
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
          <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
            Webhook Destinations ({destinations.length})
          </div>

          {destinations.length === 0 ? (
            <div style={{ padding: "32px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No destinations configured yet.</div>
          ) : (
            <table className="asm-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Channel</th>
                  <th>Config URL</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {destinations.map((d) => (
                  <tr key={d.id}>
                    <td style={{ fontWeight: 500, color: "#111827" }}>{d.name}</td>
                    <td><Badge variant="medium">{d.channel}</Badge></td>
                    <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#4B5563" }}>{d.config?.url || "Internal"}</td>
                    <td><Badge variant={d.is_active ? "verified" : "low"}>{d.is_active ? "ACTIVE" : "DISABLED"}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Policies */}
        <div style={{ backgroundColor: "#FFFFFF", border: "1px solid #E5E7EB", borderRadius: "6px", overflow: "hidden" }}>
          <div style={{ padding: "16px", borderBottom: "1px solid #E5E7EB", fontSize: "16px", fontWeight: 600, color: "#111827" }}>
            Notification Policies ({policies.length})
          </div>

          {policies.length === 0 ? (
            <div style={{ padding: "32px", textAlign: "center", color: "#9CA3AF", fontSize: "13px" }}>No notification policies configured yet.</div>
          ) : (
            <table className="asm-table">
              <thead>
                <tr>
                  <th>Policy Name</th>
                  <th>Min Risk</th>
                  <th>Cooldown</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id}>
                    <td style={{ fontWeight: 500, color: "#111827" }}>{p.name}</td>
                    <td><Badge variant={p.min_risk_band === "CRITICAL" ? "critical" : "high"}>{p.min_risk_band}</Badge></td>
                    <td style={{ fontSize: "12px", color: "#4B5563" }}>{p.cooldown_minutes}m</td>
                    <td><Badge variant={p.is_active ? "verified" : "low"}>{p.is_active ? "ACTIVE" : "DISABLED"}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Modal: Create Destination */}
      {destModalOpen && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, backgroundColor: "rgba(17,24,39,0.4)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ backgroundColor: "#FFFFFF", borderRadius: "6px", width: "440px", maxWidth: "90%", padding: "20px", border: "1px solid #E5E7EB" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, color: "#111827", margin: "0 0 16px 0" }}>Create Webhook Destination</h3>
            <form onSubmit={handleCreateDestination} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Destination Name *</label>
                <input required type="text" value={destName} onChange={(e) => setDestName(e.target.value)} placeholder="e.g. Production Webhook" className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }} />
              </div>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Webhook URL *</label>
                <input required type="url" value={destUrl} onChange={(e) => setDestUrl(e.target.value)} placeholder="https://api.example.com/webhooks/asm" className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }} />
              </div>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>HMAC Secret (Optional)</label>
                <input type="password" value={destSecret} onChange={(e) => setDestSecret(e.target.value)} placeholder="SHA256 signing secret" className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "12px" }}>
                <button type="button" onClick={() => setDestModalOpen(false)} className="btn-secondary" style={{ fontSize: "13px" }}>Cancel</button>
                <button type="submit" disabled={destSubmitting} className="btn-primary" style={{ fontSize: "13px" }}>{destSubmitting ? "Creating..." : "Save Destination"}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Webhook Test */}
      {testModalOpen && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, backgroundColor: "rgba(17,24,39,0.4)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ backgroundColor: "#FFFFFF", borderRadius: "6px", width: "440px", maxWidth: "90%", padding: "20px", border: "1px solid #E5E7EB" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, color: "#111827", margin: "0 0 16px 0" }}>Test Webhook Egress Guard</h3>
            {testFeedback && (
              <div style={{ marginBottom: "12px", padding: "10px", backgroundColor: "#F0FDF4", border: "1px solid #86EFAC", color: "#16A34A", borderRadius: "4px", fontSize: "12px" }}>
                {testFeedback}
              </div>
            )}
            <form onSubmit={handleTestWebhook} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Test Webhook URL *</label>
                <input required type="url" value={testUrl} onChange={(e) => setTestUrl(e.target.value)} placeholder="https://public.example.com/webhook" className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }} />
              </div>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Signing Secret (Optional)</label>
                <input type="password" value={testSecret} onChange={(e) => setTestSecret(e.target.value)} placeholder="Secret" className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "12px" }}>
                <button type="button" onClick={() => setTestModalOpen(false)} className="btn-secondary" style={{ fontSize: "13px" }}>Close</button>
                <button type="submit" disabled={testSubmitting} className="btn-primary" style={{ fontSize: "13px" }}>{testSubmitting ? "Testing..." : "Send Test Webhook"}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Create Policy */}
      {policyModalOpen && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, backgroundColor: "rgba(17,24,39,0.4)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ backgroundColor: "#FFFFFF", borderRadius: "6px", width: "440px", maxWidth: "90%", padding: "20px", border: "1px solid #E5E7EB" }}>
            <h3 style={{ fontSize: "16px", fontWeight: 600, color: "#111827", margin: "0 0 16px 0" }}>Create Notification Policy</h3>
            <form onSubmit={handleCreatePolicy} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Policy Name *</label>
                <input required type="text" value={policyName} onChange={(e) => setPolicyName(e.target.value)} placeholder="e.g. High Risk Alerts Policy" className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }} />
              </div>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Min Risk Threshold</label>
                <select value={policyMinBand} onChange={(e) => setPolicyMinBand(e.target.value)} className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }}>
                  <option value="CRITICAL">CRITICAL Only</option>
                  <option value="HIGH">HIGH or higher</option>
                  <option value="MEDIUM">MEDIUM or higher</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: "12px", color: "#4B5563", display: "block", marginBottom: "4px" }}>Cooldown Window (Minutes)</label>
                <input type="number" value={policyCooldown} onChange={(e) => setPolicyCooldown(parseInt(e.target.value) || 60)} className="input-field" style={{ width: "100%", height: "36px", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "12px" }}>
                <button type="button" onClick={() => setPolicyModalOpen(false)} className="btn-secondary" style={{ fontSize: "13px" }}>Cancel</button>
                <button type="submit" disabled={policySubmitting} className="btn-primary" style={{ fontSize: "13px" }}>{policySubmitting ? "Creating..." : "Save Policy"}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

