"use client";

import React, { useState, useEffect } from "react";
import { Bot, Send, ShieldAlert, Cpu, Sparkles, AlertCircle, FileText, CheckCircle, Database } from "lucide-react";
import { getSession, queryAssistant, listConversations } from "../lib/api";
import Badge from "../components/Badge";

export default function AssistantPage() {
  const [session, setSessionState] = useState(getSession());
  const [conversations, setConversations] = useState<any[]>([]);
  const [selectedConvId, setSelectedConvId] = useState<string | null>(null);
  const [queryInput, setQueryInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [messages, setMessages] = useState<any[]>([]);

  useEffect(() => {
    const s = getSession();
    setSessionState(s);
    loadConversations(s.orgId);
  }, []);

  const loadConversations = async (orgId: string) => {
    try {
      const res = await listConversations(orgId);
      setConversations(res.items || []);
    } catch (e: any) {
      console.error("Failed to load conversations:", e);
    }
  };

  const handleSend = async () => {
    if (!queryInput.trim()) return;
    setLoading(true);
    setError(null);
    const userQuery = queryInput;
    setQueryInput("");

    // User message
    const tempUserMsg = {
      id: "temp-" + Date.now(),
      sender_type: "user",
      content: userQuery,
      created_at: new Date().toISOString()
    };
    setMessages((prev) => [...prev, tempUserMsg]);

    try {
      const res = await queryAssistant(session.orgId, {
        query: userQuery,
        conversation_id: selectedConvId || undefined
      });

      if (!selectedConvId && res.conversation_id) {
        setSelectedConvId(res.conversation_id);
        loadConversations(session.orgId);
      }

      const assistantMsg = {
        id: res.message_id,
        sender_type: "assistant",
        content: res.response.answer,
        structured_data: res.response,
        created_at: new Date().toISOString()
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      setError(err.message || "AI query request failed.");
    } finally {
      setLoading(false);
    }
  };

  // Collect referenced facts/objects across messages for right panel
  const lastAssistantMsg = [...messages].reverse().find(m => m.sender_type === "assistant");
  const referencedFacts = lastAssistantMsg?.structured_data?.facts || [];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 80px)", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 24px", borderBottom: "1px solid #E5E7EB", backgroundColor: "#FFFFFF" }}>
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 600, color: "#111827", margin: 0 }}>
            AI Investigation Assistant
          </h1>
          <p style={{ fontSize: "12px", color: "#4B5563", marginTop: "2px", margin: 0 }}>
            Subordinate AI assistance layer grounded in authoritative ASM scan data.
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontSize: "12px", padding: "4px 8px", backgroundColor: "#F3F4F6", border: "1px solid #D1D5DB", color: "#4B5563", borderRadius: "4px" }}>
            SUBORDINATE TO ASM AUTHORITY
          </span>
        </div>
      </div>

      {/* 3-panel workspace */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden", backgroundColor: "#F8F9FB" }}>
        {/* PANEL 1: LEFT 240px Investigation Sessions */}
        <div style={{ width: "240px", borderRight: "1px solid #E5E7EB", backgroundColor: "#FFFFFF", padding: "16px", display: "flex", flexDirection: "column" }}>
          <div style={{ fontSize: "13px", fontWeight: 600, color: "#111827", marginBottom: "12px" }}>
            Investigation History
          </div>
          <button
            onClick={() => { setSelectedConvId(null); setMessages([]); }}
            className="btn-primary"
            style={{ width: "100%", height: "34px", fontSize: "12px", marginBottom: "16px" }}
          >
            + New Investigation
          </button>
          <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "6px" }}>
            {conversations.length === 0 ? (
              <div style={{ fontSize: "12px", color: "#9CA3AF", textAlign: "center", padding: "16px" }}>
                No past sessions
              </div>
            ) : (
              conversations.map((c) => (
                <button
                  key={c.id}
                  onClick={() => { setSelectedConvId(c.id); }}
                  style={{
                    textAlign: "left",
                    padding: "8px 10px",
                    borderRadius: "6px",
                    border: "1px solid " + (selectedConvId === c.id ? "#2563EB" : "#E5E7EB"),
                    backgroundColor: selectedConvId === c.id ? "#EFF6FF" : "#FFFFFF",
                    color: "#111827",
                    fontSize: "12px",
                    cursor: "pointer"
                  }}
                >
                  <div style={{ fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {c.title || "Investigation Session"}
                  </div>
                  <div style={{ fontSize: "11px", color: "#9CA3AF", marginTop: "2px" }}>
                    {new Date(c.updated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* PANEL 2: CENTER Conversation Thread & Input */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", backgroundColor: "#FFFFFF" }}>
          {/* Messages Feed */}
          <div style={{ flex: 1, padding: "20px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "16px" }}>
            {messages.length === 0 ? (
              <div style={{ textAlign: "center", margin: "auto", maxWidth: "440px" }}>
                <Bot size={40} style={{ color: "#9CA3AF", margin: "0 auto 12px" }} />
                <div style={{ fontSize: "16px", fontWeight: 600, color: "#111827" }}>
                  Ask an AI-Assisted Security Query
                </div>
                <div style={{ fontSize: "13px", color: "#4B5563", marginTop: "6px" }}>
                  Query asset relationships, exposure reasoning, or threat correlation. AI output is strictly labeled and subordinate to verified ASM evidence.
                </div>
              </div>
            ) : (
              messages.map((m, idx) => (
                <div
                  key={m.id || idx}
                  style={{
                    alignSelf: m.sender_type === "user" ? "flex-end" : "flex-start",
                    maxWidth: m.sender_type === "user" ? "75%" : "90%",
                    backgroundColor: m.sender_type === "user" ? "#2563EB" : "#F8F9FB",
                    color: m.sender_type === "user" ? "#FFFFFF" : "#111827",
                    padding: "14px 16px",
                    borderRadius: "6px",
                    border: `1px solid ${m.sender_type === "user" ? "#2563EB" : "#E5E7EB"}`
                  }}
                >
                  <div style={{ fontSize: "11px", fontWeight: 600, color: m.sender_type === "user" ? "#DBEAFE" : "#4B5563", marginBottom: "6px" }}>
                    {m.sender_type === "user" ? "OPERATOR QUERY" : "AI INVESTIGATION LAYER"}
                  </div>

                  <div style={{ fontSize: "14px", lineHeight: "20px", whiteSpace: "pre-wrap" }}>
                    {m.content}
                  </div>

                  {/* Structured Content Breakdown */}
                  {m.structured_data && (
                    <div style={{ marginTop: "16px", paddingTop: "12px", borderTop: "1px solid #E5E7EB", display: "flex", flexDirection: "column", gap: "10px" }}>
                      {/* FACTS / EVIDENCE */}
                      {m.structured_data.facts && m.structured_data.facts.length > 0 && (
                        <div>
                          <div style={{ fontSize: "11px", fontWeight: 700, color: "#16A34A", marginBottom: "4px" }}>
                            ASM EVIDENCE (AUTHORITATIVE)
                          </div>
                          {m.structured_data.facts.map((f: string, fi: number) => (
                            <div key={fi} style={{ fontSize: "12px", fontFamily: "monospace", color: "#111827", backgroundColor: "#F0FDF4", border: "1px solid #86EFAC", padding: "4px 8px", borderRadius: "4px", marginBottom: "4px" }}>
                              {f}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* INFERENCES / AI INTERPRETATION */}
                      {m.structured_data.inferences && m.structured_data.inferences.length > 0 && (
                        <div>
                          <div style={{ fontSize: "11px", fontWeight: 700, color: "#2563EB", marginBottom: "4px" }}>
                            AI INTERPRETATION
                          </div>
                          {m.structured_data.inferences.map((inf: string, ii: number) => (
                            <div key={ii} style={{ fontSize: "13px", color: "#4B5563", marginBottom: "2px" }}>
                              • {inf}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* RECOMMENDATIONS */}
                      {m.structured_data.recommendations && m.structured_data.recommendations.length > 0 && (
                        <div>
                          <div style={{ fontSize: "11px", fontWeight: 700, color: "#D97706", marginBottom: "4px" }}>
                            RECOMMENDATION
                          </div>
                          {m.structured_data.recommendations.map((r: string, ri: number) => (
                            <div key={ri} style={{ fontSize: "13px", color: "#4B5563", marginBottom: "2px" }}>
                              ✓ {r}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
            {loading && (
              <div style={{ alignSelf: "flex-start", padding: "10px 14px", backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "6px", fontSize: "13px", color: "#4B5563" }}>
                Querying assistant context...
              </div>
            )}
            {error && (
              <div style={{ padding: "10px 14px", backgroundColor: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: "6px", color: "#DC2626", fontSize: "13px" }}>
                Error: {error}
              </div>
            )}
          </div>

          {/* Input Bar */}
          <div style={{ padding: "16px", borderTop: "1px solid #E5E7EB", backgroundColor: "#FFFFFF", display: "flex", gap: "12px" }}>
            <input
              type="text"
              className="input-field"
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleSend(); }}
              placeholder="Ask an investigative question about assets, findings, or exposure..."
              style={{ flex: 1, height: "38px", fontSize: "13px" }}
            />
            <button
              onClick={handleSend}
              disabled={loading || !queryInput.trim()}
              className="btn-primary"
              style={{ height: "38px", display: "flex", alignItems: "center", gap: "6px", fontSize: "13px" }}
            >
              <Send size={14} /> Send Query
            </button>
          </div>
        </div>

        {/* PANEL 3: RIGHT 280px Referenced ASM Objects */}
        <div style={{ width: "280px", borderLeft: "1px solid #E5E7EB", backgroundColor: "#FFFFFF", padding: "16px", overflowY: "auto" }}>
          <div style={{ fontSize: "13px", fontWeight: 600, color: "#111827", marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
            <Database size={14} style={{ color: "#4B5563" }} /> Referenced ASM Objects
          </div>

          {referencedFacts.length === 0 ? (
            <div style={{ fontSize: "12px", color: "#9CA3AF" }}>
              No authoritative objects referenced in current conversation turn.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              <div style={{ fontSize: "11px", fontWeight: 600, color: "#16A34A" }}>
                VERIFIED ASM EVIDENCE
              </div>
              {referencedFacts.map((fact: string, i: number) => (
                <div key={i} style={{ padding: "8px", backgroundColor: "#F8F9FB", border: "1px solid #E5E7EB", borderRadius: "4px", fontSize: "12px", fontFamily: "monospace", color: "#111827", wordBreak: "break-all" }}>
                  {fact}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

