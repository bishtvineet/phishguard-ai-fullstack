import React, { useState } from "react";
import { AnalysisResponse } from "../../types/analysis";
import { RiskGauge } from "../ui/RiskGauge";
import { FindingCard } from "./FindingCard";
import { CheckCircle2, Copy, Download, ArrowLeft, Shield, AlertTriangle } from "lucide-react";

interface ResultsViewProps {
  response: AnalysisResponse;
  onReset: () => void;
}

export const ResultsView: React.FC<ResultsViewProps> = ({ response, onReset }) => {
  const [copied, setCopied] = useState(false);
  const [filterAnalyzer, setFilterAnalyzer] = useState<string>("all");

  const filteredFindings = response.findings.filter((f) => {
    if (filterAnalyzer === "all") return true;
    return f.analyzer === filterAnalyzer;
  });

  const handleCopy = () => {
    const jsonStr = JSON.stringify(response, null, 2);
    navigator.clipboard.writeText(jsonStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(response, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `phishguard-report-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Top Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-cyber-700/60">
        <button
          onClick={onReset}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-sm font-medium text-slate-300 hover:text-white bg-cyber-850 hover:bg-cyber-800 border border-cyber-700 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Analyze Another Email
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-cyber-850 hover:bg-cyber-800 border border-cyber-700 transition-colors"
          >
            {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? "Copied JSON" : "Copy Report"}
          </button>
          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 hover:bg-cyan-900/40 border border-cyan-500/30 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download JSON
          </button>
        </div>
      </div>

      {/* Main Score & Summary Header */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">
        <div className="lg:col-span-1">
          <RiskGauge score={response.risk_score} category={response.risk_category} />
        </div>

        <div className="lg:col-span-2 flex flex-col justify-between p-6 rounded-2xl border border-cyber-700/70 bg-cyber-900/50">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-bold text-white tracking-tight">Executive Assessment Summary</h2>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed bg-cyber-950/60 p-4 rounded-xl border border-cyber-800 font-mono">
              {response.summary}
            </p>
          </div>

          <div className="mt-4 pt-4 border-t border-cyber-800/80 flex flex-wrap items-center justify-between text-xs text-slate-400">
            <span>Total Indicators Flagged: <strong className="text-white font-mono">{response.findings.length}</strong></span>
            <span>Recommended Actions: <strong className="text-white font-mono">{response.recommendations.length}</strong></span>
            <span className="text-cyan-400 font-medium">Evaluation: Offline Heuristic & Lexical ML</span>
          </div>
        </div>
      </div>

      {/* Actionable Security Recommendations */}
      {response.recommendations.length > 0 && (
        <div className="p-6 rounded-2xl border border-blue-500/20 bg-blue-950/20 space-y-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-blue-400" />
            <h3 className="font-bold text-white text-sm">Actionable Security Recommendations</h3>
          </div>
          <ul className="space-y-2">
            {response.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2.5 text-sm text-slate-300">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-2 flex-shrink-0" />
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Findings Breakdown */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            Detailed Diagnostic Findings
            <span className="px-2 py-0.5 rounded text-xs font-mono bg-cyber-800 text-slate-300 border border-cyber-700">
              {filteredFindings.length}
            </span>
          </h3>

          {/* Filter Pills */}
          <div className="flex items-center gap-1.5 bg-cyber-950 p-1 rounded-lg border border-cyber-800 text-xs">
            {["all", "sender", "content", "url", "ml_url"].map((cat) => (
              <button
                key={cat}
                onClick={() => setFilterAnalyzer(cat)}
                className={`px-2.5 py-1 rounded font-mono uppercase text-[11px] transition-all ${
                  filterAnalyzer === cat
                    ? "bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {cat === "all" ? "All Findings" : cat}
              </button>
            ))}
          </div>
        </div>

        {filteredFindings.length === 0 ? (
          <div className="p-8 rounded-xl border border-cyber-800 bg-cyber-900/30 text-center">
            <p className="text-sm text-slate-400">No findings recorded under the selected filter.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3">
            {filteredFindings.map((finding, idx) => (
              <FindingCard key={idx} finding={finding} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
