"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Zap, Filter, ArrowRight, RefreshCw, GitCompare } from "lucide-react";
import { listChanges, listComparisons, getSession } from "../lib/api";
import { Change, ComparisonRun } from "../lib/types";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { Table, Column } from "../components/ui/Table";
import { ErrorAlert } from "../components/ui/ErrorAlert";

export default function ChangesTimelinePage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [changes, setChanges] = useState<Change[]>([]);
  const [comparisons, setComparisons] = useState<ComparisonRun[]>([]);

  const [changeTypeFilter, setChangeTypeFilter] = useState<string>("");
  const [entityTypeFilter, setEntityTypeFilter] = useState<string>("");

  const loadChangesData = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      const orgId = session.orgId;

      const [chgRes, compRes] = await Promise.all([
        listChanges(orgId, {
          change_type: changeTypeFilter || undefined,
          entity_type: entityTypeFilter || undefined,
          limit: 50
        }),
        listComparisons(orgId, { limit: 10 })
      ]);

      setChanges(chgRes.items || []);
      setComparisons(compRes.items || []);
    } catch (err: any) {
      setError(err.message || "Failed to load change intelligence timeline");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadChangesData();
  }, [changeTypeFilter, entityTypeFilter]);

  const changeColumns: Column<Change>[] = [
    {
      key: "change_type",
      header: "Change Type",
      render: (c) => <Badge variant={c.change_type} label={c.change_type.replace(/_/g, " ")} />
    },
    {
      key: "entity_identifier",
      header: "Target Identifier",
      render: (c) => (
        <div>
          <span className="mono" style={{ fontWeight: 600, color: "var(--text-primary)" }}>{c.entity_identifier}</span>
          <div className="mono" style={{ fontSize: "11px", color: "var(--text-tertiary)", marginTop: "2px" }}>Entity: {c.entity_type}</div>
        </div>
      )
    },
    {
      key: "comparison_run_id",
      header: "Scan Comparison Run",
      render: (c) => <span className="mono" style={{ fontSize: "12px", color: "var(--text-secondary)" }}>{c.comparison_run_id}</span>
    },
    {
      key: "detected_at",
      header: "Detected At",
      render: (c) => <span style={{ fontSize: "12px", color: "var(--text-tertiary)" }}>{new Date(c.detected_at).toLocaleString()}</span>
    },
    {
      key: "action",
      header: "Diff & Evidence",
      render: (c) => (
        <Link href={`/changes/${c.id}`} style={{ fontSize: "12px", color: "var(--accent)", fontWeight: 500, display: "flex", alignItems: "center", gap: "4px" }}>
          <span>View State Diff</span>
          <ArrowRight style={{ width: "13px", height: "13px" }} />
        </Link>
      )
    }
  ];

  const compColumns: Column<ComparisonRun>[] = [
    {
      key: "status",
      header: "Status",
      render: (c) => <Badge variant={c.status} />
    },
    {
      key: "current_scan_completeness",
      header: "Scan Completeness",
      render: (c) => <Badge variant={c.current_scan_completeness} />
    },
    {
      key: "changes_detected",
      header: "Changes Detected",
      render: (c) => <span className="mono" style={{ fontWeight: 700, color: "var(--text-primary)" }}>{c.changes_detected}</span>
    },
    {
      key: "created_at",
      header: "Run Timestamp",
      render: (c) => <span style={{ fontSize: "12px", color: "var(--text-tertiary)" }}>{new Date(c.created_at).toLocaleString()}</span>
    }
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: "var(--text-primary)" }}>
            Change Intelligence Timeline
          </h1>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Real-time delta detection: ASSET_ADDED, ASSET_REMOVED, PROPERTY_CHANGED, RELATIONSHIP_ADDED/REMOVED.
          </p>
        </div>
        <button onClick={loadChangesData} className="asm-btn asm-btn-secondary">
          <RefreshCw style={{ width: "14px", height: "14px" }} />
          <span>Refresh</span>
        </button>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadChangesData} />}

      {/* Filter Bar */}
      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Filter style={{ width: "14px", height: "14px", color: "var(--text-tertiary)" }} />
            <select
              value={changeTypeFilter}
              onChange={(e) => setChangeTypeFilter(e.target.value)}
              className="asm-input"
              style={{ width: "220px" }}
            >
              <option value="">All Change Types</option>
              <option value="ASSET_ADDED">ASSET_ADDED</option>
              <option value="ASSET_REMOVED">ASSET_REMOVED</option>
              <option value="ASSET_PROPERTY_CHANGED">ASSET_PROPERTY_CHANGED</option>
              <option value="RELATIONSHIP_ADDED">RELATIONSHIP_ADDED</option>
              <option value="RELATIONSHIP_REMOVED">RELATIONSHIP_REMOVED</option>
            </select>

            <select
              value={entityTypeFilter}
              onChange={(e) => setEntityTypeFilter(e.target.value)}
              className="asm-input"
              style={{ width: "160px" }}
            >
              <option value="">All Entity Types</option>
              <option value="asset">Asset</option>
              <option value="relationship">Relationship</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Changes Table */}
      <Card title={`Detected Changes (${changes.length})`}>
        <Table
          columns={changeColumns}
          data={changes}
          keyExtractor={(c) => c.id}
          loading={loading}
          emptyMessage="No detected changes recorded for this organization."
        />
      </Card>

      {/* Scan-over-Scan Comparison Runs */}
      <Card
        title={
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <GitCompare style={{ width: "16px", height: "16px", color: "var(--accent)" }} />
            <span>Comparison Run Execution Logs ({comparisons.length})</span>
          </div>
        }
        subtitle="Historical scan delta evaluations with completeness gates"
      >
        <Table
          columns={compColumns}
          data={comparisons}
          keyExtractor={(c) => c.id}
          loading={loading}
          emptyMessage="No comparison run records found."
        />
      </Card>
    </div>
  );
}
