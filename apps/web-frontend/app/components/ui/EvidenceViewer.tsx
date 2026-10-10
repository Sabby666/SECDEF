import React, { useState } from "react";
import { ChevronDown, ChevronRight, Copy, Check } from "lucide-react";

export interface EvidenceViewerProps {
  data: Record<string, any> | null | undefined;
  title?: string;
  defaultExpanded?: boolean;
}

export const EvidenceViewer: React.FC<EvidenceViewerProps> = ({
  data,
  title = "Evidence Details",
  defaultExpanded = true
}) => {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [copied, setCopied] = useState(false);

  if (!data || Object.keys(data).length === 0) {
    return (
      <div className="text-xs font-mono text-slate-500 italic py-1">
        No evidence payload attached.
      </div>
    );
  }

  const jsonString = JSON.stringify(data, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="border border-slate-800 rounded bg-slate-950/80 overflow-hidden my-2">
      <div
        onClick={() => setExpanded(!expanded)}
        className="px-3 py-2 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between cursor-pointer select-none text-xs font-mono text-slate-300 hover:bg-slate-800/60"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          <span className="font-semibold">{title}</span>
          <span className="text-[10px] text-slate-500 font-sans">({Object.keys(data).length} keys)</span>
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            handleCopy();
          }}
          className="text-slate-400 hover:text-slate-200 p-1 rounded hover:bg-slate-700/50 flex items-center gap-1 text-[11px]"
          title="Copy JSON payload"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          <span>{copied ? "Copied" : "Copy"}</span>
        </button>
      </div>
      {expanded && (
        <pre className="p-3 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap break-all max-h-80 selection:bg-slate-700">
          {jsonString}
        </pre>
      )}
    </div>
  );
};
