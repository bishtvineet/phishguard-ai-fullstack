import React from "react";
import { Cpu, AlertTriangle, Layers } from "lucide-react";

export const AboutView: React.FC = () => {
  return (
    <div className="space-y-8 py-4 animate-fadeIn max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">System Architecture & ML Specifications</h1>
        <p className="text-sm text-slate-300 mt-2">
          Technical specifications, scoring containment proofs, and dataset limitations for academic and technical evaluation.
        </p>
      </div>

      <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
        <div className="flex items-center gap-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          <h2 className="font-bold text-white text-base">Centralized Risk Scoring Engine</h2>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">
          The scoring system aggregates indicators across Sender, Content, Deterministic URL, and Machine Learning modules using calibrated base weights and strict mathematical containment:
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 rounded-xl bg-cyber-950 border border-cyber-800 text-center">
            <span className="text-rose-400 font-bold text-sm block">35 PTS</span>
            <span className="text-slate-400">HIGH Severity</span>
          </div>
          <div className="p-3 rounded-xl bg-cyber-950 border border-cyber-800 text-center">
            <span className="text-amber-400 font-bold text-sm block">18 PTS</span>
            <span className="text-slate-400">MEDIUM Severity</span>
          </div>
          <div className="p-3 rounded-xl bg-cyber-950 border border-cyber-800 text-center">
            <span className="text-cyan-400 font-bold text-sm block">7 PTS</span>
            <span className="text-slate-400">LOW Severity</span>
          </div>
          <div className="p-3 rounded-xl bg-cyber-950 border border-cyber-800 text-center">
            <span className="text-slate-400 font-bold text-sm block">0 PTS</span>
            <span className="text-slate-400">INFO Severity</span>
          </div>
        </div>
      </div>

      <div className="p-6 rounded-2xl border border-cyan-500/20 bg-cyan-950/20 space-y-4">
        <div className="flex items-center gap-2">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <h2 className="font-bold text-white text-base">Machine Learning URL Classifier</h2>
        </div>
        <div className="space-y-3 text-sm text-slate-300">
          <p>
            <strong>Model Type:</strong> Offline <code className="font-mono text-cyan-300">RandomForestClassifier</code> (100 estimators, max depth 12) trained on 14 lexical features extracted strictly from URL string geometry.
          </p>
          <p>
            <strong>Decision Threshold:</strong> Calibrated at <code className="font-mono text-cyan-300">0.22317</code> to satisfy a target validation false-positive rate (FPR &le; 1.50%).
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono pt-2">
            <div className="p-2.5 rounded-lg bg-cyber-950 border border-cyber-800">
              <span className="text-slate-400 block">Val FPR</span>
              <span className="text-cyan-400 font-bold text-sm">1.48%</span>
            </div>
            <div className="p-2.5 rounded-lg bg-cyber-950 border border-cyber-800">
              <span className="text-slate-400 block">Val Precision</span>
              <span className="text-cyan-400 font-bold text-sm">98.16%</span>
            </div>
            <div className="p-2.5 rounded-lg bg-cyber-950 border border-cyber-800">
              <span className="text-slate-400 block">Val Recall</span>
              <span className="text-cyan-400 font-bold text-sm">99.22%</span>
            </div>
            <div className="p-2.5 rounded-lg bg-cyber-950 border border-cyber-800">
              <span className="text-slate-400 block">Val F1-Score</span>
              <span className="text-cyan-400 font-bold text-sm">98.68%</span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-6 rounded-2xl border border-amber-500/20 bg-amber-950/20 space-y-4">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          <h2 className="font-bold text-white text-base">Architectural Containment & Known Dataset Biases</h2>
        </div>
        <div className="space-y-3 text-sm text-slate-300 leading-relaxed">
          <p>
            <strong>Mathematical Containment:</strong> The ML finding <code className="font-mono text-cyan-300">ML_URL_SUSPICIOUS_LEXICAL_ANOMALY</code> is emitted strictly at MEDIUM severity (18 base points). Even with the maximum repeat bonus (+6 pts across distinct domains), its total contribution is capped at <strong>24 points</strong>. Because the Suspicious category threshold begins at <strong>25 points</strong>, ML findings alone can <em>never</em> elevate an email into Suspicious or High Risk without corroborating deterministic evidence.
          </p>
          <p>
            <strong>UCI PhiUSIIL Dataset Distribution Bias:</strong> Across all 134,850 legitimate URLs in the raw UCI dataset, zero records contain query parameters (<code className="font-mono">?</code>) and zero exceed 60 characters. Consequently, tree-based models learn an association between path complexity and phishing, producing false positives on search queries such as <code className="font-mono text-amber-300">https://www.google.com/search?q=cybersecurity</code> (probability: 0.9937). The containment invariant guarantees that such isolated false alarms remain bounded in Low Risk.
          </p>
        </div>
      </div>
    </div>
  );
};
