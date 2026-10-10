"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  LayoutDashboard, Server, ShieldAlert, GitFork, 
  CheckCircle2, Bell, Globe, Search, Shield, Zap,
  ChevronDown, Layers, Activity, Cpu, Settings, Calendar, Info, RefreshCw
} from "lucide-react";
import { getSession, setSession, ROLE_USER_MAP, fetchServerSession } from "./lib/api";
import { UserRole } from "./lib/types";
import "./globals.css";

interface NavGroup {
  group: string;
  items: { href: string; label: string; icon: any; count?: string | number }[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    group: "OVERVIEW",
    items: [
      { href: "/", label: "Overview", icon: LayoutDashboard }
    ]
  },
  {
    group: "ATTACK SURFACE",
    items: [
      { href: "/domains", label: "Domains & Scans", icon: Globe, count: "4" },
      { href: "/assets", label: "Asset Inventory", icon: Server, count: "84" },
      { href: "/graph", label: "Topology Graph", icon: GitFork, count: "5" }
    ]
  },
  {
    group: "DISCOVERY & INGESTION",
    items: [
      { href: "/discovery", label: "Discovery Runs", icon: Activity },
      { href: "/discovery/candidates", label: "Discovery Candidates", icon: CheckCircle2 }
    ]
  },
  {
    group: "EXPOSURE & FINDINGS",
    items: [
      { href: "/findings", label: "Security Findings", icon: ShieldAlert, count: "7" },
      { href: "/exposures", label: "Exposure Engine", icon: Zap },
      { href: "/changes", label: "Perimeter Changes", icon: Activity },
      { href: "/risk", label: "Risk Analysis", icon: Shield }
    ]
  },
  {
    group: "THREAT INTELLIGENCE",
    items: [
      { href: "/intelligence", label: "Threat Feeds", icon: Cpu },
      { href: "/correlations", label: "Cert Correlations", icon: Layers },
      { href: "/assistant", label: "AI Security Assistant", icon: Cpu }
    ]
  },
  {
    group: "REMEDIATION & GOVERNANCE",
    items: [
      { href: "/actions", label: "Remediation Actions", icon: CheckCircle2 },
      { href: "/automation", label: "Automation Policies", icon: Zap },
      { href: "/verification", label: "Continuous Verification", icon: CheckCircle2 },
      { href: "/notifications", label: "Notifications & Alerts", icon: Bell }
    ]
  },
  {
    group: "ADMINISTRATION",
    items: [
      { href: "/context", label: "Audit Logs & Context", icon: Layers },
      { href: "/settings", label: "Settings & Access Control", icon: Settings }
    ]
  }
];

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const [role, setRole] = useState<UserRole>("ADMIN");
  const [orgId, setOrgId] = useState<string>("org-001");
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    async function initSession() {
      try {
        const serverSession = await fetchServerSession();
        setRole(serverSession.role);
        setOrgId(serverSession.org_id);
      } catch (e) {
        const local = getSession();
        setRole(local.userRole);
        setOrgId(local.orgId);
      }
    }
    initSession();
  }, []);

  const handleRoleChange = (newRole: UserRole) => {
    const user = ROLE_USER_MAP[newRole];
    setSession({
      orgId,
      userId: user.userId,
      userRole: newRole
    });
    window.location.reload();
  };

  return (
    <html lang="en">
      <head>
        <title>ASM Console — Attack Surface Monitor</title>
        <meta name="description" content="Attack Surface Monitor & Exposure Management Workspace" />
      </head>
      <body>
        <div style={{ display: "flex", flexDirection: "column", minHeight: "100vh", backgroundColor: "var(--bg-app)" }}>
          
          {/* Top Control Header Bar (Stitch Reference Specification) */}
          <header style={{
            height: "46px",
            borderBottom: "1px solid var(--border-subtle)",
            backgroundColor: "var(--bg-primary)",
            padding: "0 16px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            zIndex: 10
          }}>
            {/* Left: ASM Logo + Identity + Search */}
            <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
              <Link href="/" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Shield size={18} style={{ color: "#2563EB" }} />
                <span style={{ fontWeight: 700, fontSize: "15px", color: "#111827", letterSpacing: "-0.2px" }}>
                  ASM Console
                </span>
              </Link>

              {/* Global Search Bar */}
              <div style={{ position: "relative", width: "280px" }}>
                <Search style={{ position: "absolute", left: "9px", top: "7px", width: "13px", height: "13px", color: "var(--text-tertiary)" }} />
                <input
                  type="text"
                  placeholder="Search assets, findings, domains... ⌘K"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "4px 8px 4px 28px",
                    fontSize: "12px",
                    borderRadius: "5px",
                    border: "1px solid var(--border-subtle)",
                    backgroundColor: "var(--bg-surface-secondary)",
                    color: "var(--text-primary)",
                    outline: "none"
                  }}
                />
              </div>
            </div>

            {/* Right: Tenant, Role, Quick Action, Avatar */}
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              {/* Tenant Dropdown */}
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: "4px",
                fontSize: "12px",
                fontWeight: 500,
                color: "var(--text-primary)",
                backgroundColor: "var(--bg-surface-secondary)",
                padding: "3px 8px",
                borderRadius: "4px",
                border: "1px solid var(--border-subtle)"
              }}>
                <span className="mono">{orgId}</span>
                <ChevronDown size={12} style={{ color: "var(--text-tertiary)" }} />
              </div>

              {/* Role Switcher Pill */}
              <div style={{ display: "flex", gap: "2px", backgroundColor: "var(--bg-surface-secondary)", padding: "2px", borderRadius: "4px", border: "1px solid var(--border-subtle)" }}>
                {(["VIEWER", "MEMBER", "ADMIN", "OWNER"] as UserRole[]).map((r) => (
                  <button
                    key={r}
                    onClick={() => handleRoleChange(r)}
                    style={{
                      padding: "2px 6px",
                      borderRadius: "3px",
                      fontSize: "10.5px",
                      fontWeight: role === r ? 600 : 400,
                      backgroundColor: role === r ? "var(--bg-primary)" : "transparent",
                      color: role === r ? "var(--accent)" : "var(--text-secondary)",
                      border: role === r ? "1px solid var(--border-subtle)" : "none",
                      cursor: "pointer"
                    }}
                  >
                    {r}
                  </button>
                ))}
              </div>

              {/* Quick Scan Primary Action */}
              <button className="asm-btn asm-btn-dark" style={{ padding: "4px 10px", fontSize: "12px" }}>
                <Zap size={13} />
                <span>Quick Scan</span>
              </button>

              {/* Utilities */}
              <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--text-secondary)", paddingLeft: "4px" }}>
                <Bell size={15} style={{ cursor: "pointer" }} />
                <Calendar size={15} style={{ cursor: "pointer" }} />
                <Info size={15} style={{ cursor: "pointer" }} />
                
                {/* User Avatar */}
                <div style={{
                  width: "24px",
                  height: "24px",
                  borderRadius: "50%",
                  backgroundColor: "#0F172A",
                  color: "#FFFFFF",
                  fontSize: "11px",
                  fontWeight: 600,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  marginLeft: "4px"
                }}>
                  AL
                </div>
              </div>
            </div>
          </header>

          {/* Body Container: Sidebar + Workspace */}
          <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
            {/* App Sidebar Navigation (Quiet Compact Dock) */}
            <aside style={{
              width: "210px",
              backgroundColor: "var(--bg-surface-secondary)",
              borderRight: "1px solid var(--border-subtle)",
              padding: "12px 10px",
              display: "flex",
              flexDirection: "column",
              gap: "12px",
              flexShrink: 0
            }}>
              {/* Sidebar Header Block */}
              <div style={{
                padding: "8px",
                backgroundColor: "var(--bg-primary)",
                borderRadius: "5px",
                border: "1px solid var(--border-subtle)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between"
              }}>
                <div>
                  <div style={{ fontSize: "11.5px", fontWeight: 700, color: "var(--text-primary)" }}>ASM Ops</div>
                  <div style={{ fontSize: "10px", color: "var(--text-tertiary)" }}>Engine v4.12</div>
                </div>
                <button className="asm-btn asm-btn-secondary" style={{ padding: "2px 6px", fontSize: "10.5px" }}>
                  Trigger Ingestion
                </button>
              </div>

              {/* Navigation Groups */}
              <nav style={{ display: "flex", flexDirection: "column", gap: "12px", flex: 1, overflowY: "auto" }}>
                {NAV_GROUPS.map((group) => (
                  <div key={group.group}>
                    <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.5px", padding: "0 6px 3px 6px" }}>
                      {group.group}
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "1px" }}>
                      {group.items.map((item, idx) => {
                        const Icon = item.icon;
                        const isActive = pathname === item.href && group.group === "OVERVIEW";
                        return (
                          <Link
                            key={`${item.label}-${idx}`}
                            href={item.href}
                            style={{
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "space-between",
                              padding: "5px 7px",
                              borderRadius: "4px",
                              fontSize: "12px",
                              fontWeight: isActive ? 600 : 400,
                              backgroundColor: isActive ? "var(--bg-primary)" : "transparent",
                              color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
                              borderLeft: isActive ? "3px solid var(--accent)" : "3px solid transparent",
                              borderTop: isActive ? "1px solid var(--border-subtle)" : "none",
                              borderRight: isActive ? "1px solid var(--border-subtle)" : "none",
                              borderBottom: isActive ? "1px solid var(--border-subtle)" : "none"
                            }}
                          >
                            <div style={{ display: "flex", alignItems: "center", gap: "7px" }}>
                              <Icon style={{ width: "14px", height: "14px", color: isActive ? "var(--accent)" : "var(--text-tertiary)" }} />
                              <span>{item.label}</span>
                            </div>
                            {item.count && (
                              <span style={{ fontSize: "10.5px", color: "var(--text-tertiary)", fontFamily: "monospace" }}>
                                {item.count}
                              </span>
                            )}
                          </Link>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </nav>

              {/* Sidebar Footer Status */}
              <div style={{ paddingTop: "8px", borderTop: "1px solid var(--border-subtle)", fontSize: "10.5px", color: "var(--text-tertiary)", display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "#16A34A" }} />
                <span>v4.12.0 • Engine Online</span>
              </div>
            </aside>

            {/* Main Workspace Area */}
            <main style={{ flex: 1, padding: "20px 24px", overflowY: "auto", backgroundColor: "var(--bg-app)" }}>
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}
