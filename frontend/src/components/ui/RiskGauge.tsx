import React from "react";
import { RiskCategory } from "../../types/analysis";

interface RiskGaugeProps {
  score: number | null;
  category: RiskCategory;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, category }) => {
  const isInconclusive = category === "Inconclusive" || score === null;

  // Color scheme based on verified category thresholds
  const getColor = () => {
    if (isInconclusive) return { text: "text-slate-400", stroke: "#64748b", bg: "bg-slate-800/40" };
    if (category === "High Risk") return { text: "text-rose-400", stroke: "#f43f5e", bg: "bg-rose-950/30" };
    if (category === "Suspicious") return { text: "text-amber-400", stroke: "#f59e0b", bg: "bg-amber-950/30" };
    return { text: "text-cyan-400", stroke: "#06b6d4", bg: "bg-cyan-950/30" };
  };

  const colors = getColor();
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const validScore = score !== null ? Math.max(0, Math.min(100, score)) : 0;
  const strokeDashoffset = isInconclusive ? circumference : circumference - (validScore / 100) * circumference;

  return (
    <div className={`relative flex flex-col items-center justify-center p-6 rounded-2xl border border-cyber-700/70 ${colors.bg}`}>
      <div className="relative w-40 h-40 flex items-center justify-center">
        <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 160 160">
          {/* Background Track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            className="stroke-cyber-800"
            strokeWidth="12"
            fill="transparent"
          />
          {/* Gauge Progress */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke={colors.stroke}
            strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Display */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          {isInconclusive ? (
            <>
              <span className="text-xl font-mono font-bold text-slate-400">N/A</span>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500">Inconclusive</span>
            </>
          ) : (
            <>
              <span className={`text-4xl font-extrabold font-mono tracking-tight ${colors.text}`}>
                {score}
              </span>
              <span className="text-xs font-medium text-slate-400 uppercase tracking-widest mt-0.5">
                / 100
              </span>
            </>
          )}
        </div>
      </div>

      {/* Category Pill */}
      <div className="mt-4 flex flex-col items-center">
        <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${
          category === "High Risk"
            ? "bg-rose-500/10 text-rose-400 border-rose-500/30"
            : category === "Suspicious"
            ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
            : category === "Low Risk"
            ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
            : "bg-slate-800 text-slate-400 border-slate-700"
        }`}>
          {category}
        </span>
        <span className="text-[11px] text-slate-400 mt-1 font-mono">
          {category === "High Risk"
            ? "Score 60–100 (Immediate Caution)"
            : category === "Suspicious"
            ? "Score 25–59 (Multiple Anomalies)"
            : category === "Low Risk"
            ? "Score 0–24 (No Major Heuristics)"
            : "Telemetry Insufficient"}
        </span>
      </div>
    </div>
  );
};
