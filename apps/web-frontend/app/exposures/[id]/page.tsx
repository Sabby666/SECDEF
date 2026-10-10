"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { 
  ShieldAlert, ArrowLeft, Layers, GitCommit, FileText, CheckCircle, 
  AlertTriangle, Clock, Database, ExternalLink, Activity
} from "lucide-react";
import { getExposure, getExposureEvidence, getExposurePaths, getSession } from "../../lib/api";
import { ExposureCondition, ExposureEvidence, ExposurePath } from "../../lib/types";

export default function ExposureDetailPage() {
  const params = useParams();
  const exposureId = params?.id as string;

  const [exposure, setExposure] = useState<ExposureCondition | null>(null);
  const [evidence, setEvidence] = useState<ExposureEvidence[]>([]);
  const [paths, setPaths] = useState<ExposurePath[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!exposureId) return;
    const loadDetail = async () => {
      setLoading(true);
      setError(null);
      try {
        const session = getSession();
        const [expData, evData, pathData] = await Promise.all([
          getExposure(session.orgId, exposureId),
          getExposureEvidence(session.orgId, exposureId),
          getExposurePaths(session.orgId, exposureId)
        ]);
        setExposure(expData);
        setEvidence(evData);
        setPaths(pathData);
      } catch (e: any) {
        console.error("Failed to load exposure detail", e);
        setError(e.message || "Failed to load exposure details");
      } finally {
        setLoading(false);
      }
    };
    loadDetail();
  }, [exposureId]);

  if (loading) {
    return <div className="p-8 text-center text-xs text-neutral-400">Loading exposure investigation detail...</div>;
  }

  if (error || !exposure) {
    return (
      <div className="space-y-4">
        <Link href="/exposures" className="inline-flex items-center gap-1.5 text-xs text-neutral-400 hover:text-white">
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Exposures
        </Link>
        <div className="p-6 bg-neutral-950 border border-red-900 rounded text-red-300 text-xs">
          {error || "Exposure condition not found"}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-800 pb-5">
        <Link href="/exposures" className="inline-flex items-center gap-1.5 text-xs text-neutral-400 hover:text-white mb-3">
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Exposures
        </Link>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-1 text-xs font-bold rounded bg-red-950 text-red-400 border border-red-800">
                {exposure.priority_band.replace("_", " ")}
              </span>
              <span className="px-2.5 py-1 text-xs font-semibold rounded bg-neutral-900 text-neutral-300 border border-neutral-700">
                {exposure.status.toUpperCase()}
              </span>
              <span className="text-xs font-mono text-neutral-500">{exposure.condition_type}</span>
            </div>
            <h1 className="text-xl font-bold text-white mt-2">{exposure.title}</h1>
          </div>
        </div>
      </div>

      {/* Primary Details & Explanation */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-neutral-950 p-5 rounded border border-neutral-800 space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <FileText className="h-4 w-4 text-neutral-400" />
              Deterministic Correlation Explanation
            </h2>
            <p className="text-xs text-neutral-300 leading-relaxed bg-neutral-900/70 p-3.5 rounded border border-neutral-800/80 font-mono">
              {exposure.explanation}
            </p>
            <div>
              <h3 className="text-xs font-semibold text-neutral-400 mb-1">Description</h3>
              <p className="text-xs text-neutral-300">{exposure.description}</p>
            </div>
          </div>

          {/* Exposure Paths */}
          <div className="bg-neutral-950 p-5 rounded border border-neutral-800 space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Layers className="h-4 w-4 text-neutral-400" />
              Derived Exposure Paths ({paths.length})
            </h2>
            {paths.length === 0 ? (
              <p className="text-xs text-neutral-500">No multi-hop exposure paths derived for this condition.</p>
            ) : (
              <div className="space-y-3">
                {paths.map((path, idx) => (
                  <div key={path.id} className="p-3.5 bg-neutral-900/50 rounded border border-neutral-800 space-y-2">
                    <div className="flex items-center justify-between text-xs font-semibold text-neutral-300">
                      <span>Path #{idx + 1} (Hops: {path.path_length})</span>
                      <span className="text-[10px] text-neutral-500 font-mono">{path.id.slice(0, 8)}</span>
                    </div>
                    <p className="text-xs text-neutral-400">{path.explanation}</p>
                    {/* Node chain rendering */}
                    <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-neutral-800/60">
                      {path.nodes_snapshot.map((node, nodeIdx) => (
                        <React.Fragment key={node.id}>
                          <span className="px-2 py-1 bg-neutral-950 text-neutral-300 rounded text-[11px] border border-neutral-800 font-mono">
                            {node.asset_type}: {node.identifier}
                          </span>
                          {nodeIdx < path.nodes_snapshot.length - 1 && (
                            <span className="text-neutral-600 text-xs">→</span>
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Provenance Sidebar */}
        <div className="space-y-6">
          <div className="bg-neutral-950 p-5 rounded border border-neutral-800 space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Database className="h-4 w-4 text-neutral-400" />
              Authoritative Provenance
            </h2>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-neutral-900">
                <span className="text-neutral-500">Rule Version</span>
                <span className="font-mono text-neutral-300">{exposure.rule_version}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-900">
                <span className="text-neutral-500">Primary Asset</span>
                <span className="font-mono text-neutral-300">{exposure.primary_asset_id.slice(0, 8)}...</span>
              </div>
              {exposure.risk_assessment_id && (
                <div className="flex justify-between py-1 border-b border-neutral-900">
                  <span className="text-neutral-500">Risk Assessment</span>
                  <Link href={`/risk/${exposure.risk_assessment_id}`} className="font-mono text-blue-400 hover:underline">
                    {exposure.risk_assessment_id.slice(0, 8)}...
                  </Link>
                </div>
              )}
              {exposure.finding_id && (
                <div className="flex justify-between py-1 border-b border-neutral-900">
                  <span className="text-neutral-500">Finding</span>
                  <Link href={`/findings/${exposure.finding_id}`} className="font-mono text-blue-400 hover:underline">
                    {exposure.finding_id.slice(0, 8)}...
                  </Link>
                </div>
              )}
              {exposure.change_id && (
                <div className="flex justify-between py-1 border-b border-neutral-900">
                  <span className="text-neutral-500">Change Event</span>
                  <Link href={`/changes/${exposure.change_id}`} className="font-mono text-blue-400 hover:underline">
                    {exposure.change_id.slice(0, 8)}...
                  </Link>
                </div>
              )}
              <div className="flex justify-between py-1 border-b border-neutral-900">
                <span className="text-neutral-500">First Seen</span>
                <span className="text-neutral-400">{new Date(exposure.first_seen_at).toLocaleDateString()}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-neutral-500">Last Seen</span>
                <span className="text-neutral-400">{new Date(exposure.last_seen_at).toLocaleDateString()}</span>
              </div>
            </div>

            {/* Formatted Provenance JSON */}
            <div className="pt-2">
              <span className="text-[11px] font-semibold text-neutral-400 block mb-1.5">Raw Provenance Object</span>
              <pre className="p-3 bg-neutral-900 rounded border border-neutral-800 text-[10px] text-neutral-300 overflow-x-auto">
                {JSON.stringify(exposure.provenance, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
