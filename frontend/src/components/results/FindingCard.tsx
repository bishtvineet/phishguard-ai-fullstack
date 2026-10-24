import React from "react";
import { Finding } from "../../types/analysis";
import { AlertCircle, AlertTriangle, Info, ShieldAlert, Cpu, Globe, Mail, FileText } from "lucide-react";

interface FindingCardProps {
  finding: Finding;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding }) => {
  const isMl = finding.analyzer === "ml_url";

  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case "high":
        return {
          border: "border-rose-500/30 hover:border-rose-500/50",
          badge: "bg-rose-500/10 text-rose-400 border-rose-500/30",
          icon: <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0" />,
        };
      case "medium":
        return {
          border: "border-amber-500/30 hover:border-amber-500/50",
          badge: "bg-amber-500/10 text-amber-400 border-amber-500/30",
          icon: <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />,
        };
      case "low":
        return {
          border: "border-cyan-500/30 hover:border-cyan-500/50",
          badge: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
          icon: <AlertCircle className="w-4 h-4 text-cyan-400 flex-shrink-0" />,
        };
      default:
        return {
          border: "border-slate-700/60 hover:border-slate-600",
          badge: "bg-slate-800 text-slate-400 border-slate-700",
          icon: <Info className="w-4 h-4 text-slate-400 flex-shrink-0" />,
        };
    }
  };

  const getAnalyzerIcon = (analyzer: string) => {
    switch (analyzer) {
      case "sender":
        return <Mail className="w-3.5 h-3.5 text-blue-400" />;
      case "content":
        return <FileText className="w-3.5 h-3.5 text-purple-400" />;
      case "url":
        return <Globe className="w-3.5 h-3.5 text-emerald-400" />;
      case "ml_url":
        return <Cpu className="w-3.5 h-3.5 text-cyan-400" />;
      default:
        return null;
    }
  };

  const style = getSeverityStyle(finding.severity);

  // Helper to format descriptions containing long URLs by shortening the URL inside quotes
  const formatDescription = (desc: string) => {
    return desc.replace(/'(https?:\/\/[^']+)'/g, (_match, url: string) => {
      if (url.length > 60) {
        return `'${url.substring(0, 50)}...${url.substring(url.length - 10)}'`;
      }
      return `'${url}'`;
    });
  };

  return (
    <div className="p-4 rounded-xl bg-cyber-900/70 border overflow-hidden max-w-full transition-all duration-200">
      <div className="flex items-start justify-between gap-3 mb-2 flex-wrap sm:flex-nowrap">
        <div className="flex items-center gap-2 min-w-0">
          {style.icon}
          <span className="font-mono text-xs font-semibold text-white tracking-wide truncate">
            {finding.indicator}
          </span>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${style.badge}`}>
            {finding.severity}
          </span>
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-cyber-800 text-slate-300 border border-cyber-700">
            {getAnalyzerIcon(finding.analyzer)}
            {isMl ? "ML Lexical" : finding.analyzer}
          </span>
        </div>
      </div>

      <p className="text-sm text-slate-300 leading-relaxed pl-6 break-words [overflow-wrap:anywhere]">
        {formatDescription(finding.description)}
      </p>

      {finding.target && (
        <div className="mt-2.5 pl-6 flex items-center gap-1.5 min-w-0">
          <span className="text-[11px] font-mono text-slate-500 uppercase flex-shrink-0">Target:</span>
          <code className="text-xs font-mono px-2 py-0.5 rounded bg-cyber-950 text-cyan-300 border border-cyber-700/50 truncate max-w-md">
            {finding.target}
          </code>
        </div>
      )}
    </div>
  );
};
