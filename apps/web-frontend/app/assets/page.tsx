"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Server, Filter, Search, ArrowRight, RefreshCw, Download } from "lucide-react";
import { listAssets, getSession } from "../lib/api";
import { Asset } from "../lib/types";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { Table, Column } from "../components/ui/Table";
import { ErrorAlert } from "../components/ui/ErrorAlert";

export default function AssetInventoryPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);

  // Filters
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [envFilter, setEnvFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const loadAssetsData = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      const res = await listAssets(session.orgId, {
        asset_type: typeFilter || undefined,
        environment: envFilter || undefined,
        status: statusFilter || undefined
      });
      setAssets(res.items || []);
    } catch (err: any) {
      setError(err.message || "Failed to load asset inventory");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssetsData();
  }, [typeFilter, envFilter, statusFilter]);

  const filteredAssets = assets.filter((a) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      a.identifier.toLowerCase().includes(q) ||
      a.asset_type.toLowerCase().includes(q) ||
      (a.owner_team && a.owner_team.toLowerCase().includes(q))
    );
  });

  const handleExportCSV = () => {
    if (!filteredAssets.length) return;
    const headers = ["Identifier", "Asset Type", "Environment", "Criticality", "Owner Team", "Status", "Last Observed"];
    const rows = filteredAssets.map((a) => [
      `"${a.identifier.replace(/"/g, '""')}"`,
      `"${a.asset_type}"`,
      `"${a.environment}"`,
      `"${a.criticality}"`,
      `"${(a.owner_team || "Unassigned").replace(/"/g, '""')}"`,
      `"${a.status}"`,
      `"${new Date(a.last_seen_at).toISOString()}"`
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `asm_assets_export_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const columns: Column<Asset>[] = [
    {
      key: "asset_type",
      header: "Asset Type",
      render: (a) => <Badge variant={a.asset_type} label={a.asset_type.replace(/_/g, " ")} />
    },
    {
      key: "identifier",
      header: "Identifier",
      render: (a) => <span className="mono" style={{ fontWeight: 600, color: "var(--text-primary)" }}>{a.identifier}</span>
    },
    {
      key: "environment",
      header: "Environment",
      render: (a) => <Badge variant={a.environment} />
    },
    {
      key: "criticality",
      header: "Criticality",
      render: (a) => <Badge variant={a.criticality} />
    },
    {
      key: "owner_team",
      header: "Owner Team",
      render: (a) => (
        <span className="mono" style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
          {a.owner_team || "Unassigned"}
        </span>
      )
    },
    {
      key: "last_seen_at",
      header: "Last Observed",
      render: (a) => <span style={{ fontSize: "12px", color: "var(--text-tertiary)" }}>{new Date(a.last_seen_at).toLocaleDateString()}</span>
    },
    {
      key: "status",
      header: "Status",
      render: (a) => <Badge variant={a.status} />
    },
    {
      key: "action",
      header: "Details",
      render: (a) => (
        <Link href={`/assets/${a.id}`} style={{ fontSize: "12px", color: "var(--accent)", fontWeight: 500, display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Inspect</span>
          <ArrowRight style={{ width: "13px", height: "13px" }} />
        </Link>
      )
    }
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: "var(--text-primary)" }}>
            Operational Asset Inventory
          </h1>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Complete inventory of exposed subdomains, IP addresses, running services, and SSL certificates.
          </p>
        </div>
        <div style={{ display: "flex", gap: "8px" }}>
          <button onClick={handleExportCSV} className="asm-btn asm-btn-secondary" id="btn-export-assets-csv">
            <Download style={{ width: "14px", height: "14px" }} />
            <span>Export CSV</span>
          </button>
          <button onClick={loadAssetsData} className="asm-btn asm-btn-secondary">
            <RefreshCw style={{ width: "14px", height: "14px" }} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadAssetsData} />}

      {/* Filter Bar */}
      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: "220px", display: "flex", alignItems: "center", gap: "8px", backgroundColor: "var(--bg-primary)", padding: "4px 10px", borderRadius: "6px", border: "1px solid var(--border-primary)" }}>
            <Search style={{ width: "14px", height: "14px", color: "var(--text-tertiary)" }} />
            <input
              type="text"
              placeholder="Search by hostname, IP, identifier, or owner..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="asm-input"
              style={{ border: "none", padding: "4px 0" }}
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Filter style={{ width: "14px", height: "14px", color: "var(--text-tertiary)" }} />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="asm-input"
              style={{ width: "150px" }}
            >
              <option value="">All Asset Types</option>
              <option value="subdomain">Subdomain</option>
              <option value="ip_address">IP Address</option>
              <option value="service">Service Endpoint</option>
              <option value="certificate">SSL Certificate</option>
            </select>

            <select
              value={envFilter}
              onChange={(e) => setEnvFilter(e.target.value)}
              className="asm-input"
              style={{ width: "150px" }}
            >
              <option value="">All Environments</option>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="unknown">Unknown</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="asm-input"
              style={{ width: "130px" }}
            >
              <option value="">All Statuses</option>
              <option value="active">Active</option>
              <option value="removed">Removed</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Asset Table */}
      <Card title={`Discovered Assets (${filteredAssets.length})`}>
        <Table
          columns={columns}
          data={filteredAssets}
          keyExtractor={(a) => a.id}
          loading={loading}
          emptyMessage="No assets match the selected filter criteria."
        />
      </Card>
    </div>
  );
}
