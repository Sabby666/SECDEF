"use client";

import React, { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { Bot, ArrowLeft, Cpu, Sparkles } from "lucide-react";
import Link from "next/link";
import { getSession, getConversationThread } from "../../lib/api";

export default function ConversationThreadPage() {
  const params = useParams();
  const convId = params?.id as string;
  const [session, setSessionState] = useState(getSession());
  const [thread, setThread] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const s = getSession();
    setSessionState(s);
    if (convId) {
      fetchThread(s.orgId, convId);
    }
  }, [convId]);

  const fetchThread = async (orgId: string, id: string) => {
    try {
      setLoading(true);
      const res = await getConversationThread(orgId, id);
      setThread(res);
    } catch (e: any) {
      setError(e.message || "Failed to load conversation thread.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "24px", maxWidth: "1000px", margin: "0 auto" }}>
      <Link href="/assistant" style={{ display: "inline-flex", alignItems: "center", gap: "6px", color: "var(--text-tertiary)", fontSize: "13px", marginBottom: "16px" }}>
        <ArrowLeft size={16} /> Back to Assistant
      </Link>

      {loading ? (
        <div>Loading conversation thread...</div>
      ) : error ? (
        <div style={{ color: "var(--danger)" }}>Error: {error}</div>
      ) : thread ? (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
            <h1 style={{ fontSize: "20px", fontWeight: 700, margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
              <Bot size={22} className="text-indigo-400" />
              {thread.conversation.title}
            </h1>
            <span style={{ fontSize: "12px", color: "var(--text-tertiary)", fontFamily: "var(--font-mono)" }}>
              ID: {thread.conversation.id}
            </span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            {thread.messages.map((m: any) => (
              <div
                key={m.id}
                style={{
                  alignSelf: m.sender_type === "user" ? "flex-end" : "flex-start",
                  maxWidth: m.sender_type === "user" ? "70%" : "90%",
                  backgroundColor: m.sender_type === "user" ? "var(--accent)" : "var(--bg-secondary)",
                  padding: "16px",
                  borderRadius: "8px",
                  border: "1px solid var(--border-primary)"
                }}
              >
                <div style={{ fontSize: "11px", color: "var(--text-tertiary)", marginBottom: "6px" }}>
                  {m.sender_type === "user" ? "OPERATOR QUERY" : "AI ASSISTANCE LAYER"} • {new Date(m.created_at).toLocaleTimeString()}
                </div>
                <div style={{ fontSize: "14px", whiteSpace: "pre-wrap" }}>{m.content}</div>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
