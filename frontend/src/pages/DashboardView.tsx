import React from "react";
import { Cpu, Search, Lock, ArrowRight, Zap } from "lucide-react";

interface DashboardViewProps {
  onStartAnalysis: () => void;
  onExploreArchitecture: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ onStartAnalysis, onExploreArchitecture }) => {
  return (
    <div className="space-y-12 py-4">
      <div className="relative overflow-hidden rounded-3xl border border-cyber-700/60 bg-gradient-to-b from-cyber-850 via-cyber-900 to-cyber-950 p-8 sm:p-12">
        <div className="relative z-10 max-w-3xl space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Zap className="w-3.5 h-3.5" />
            <span>Hybrid Detection: Rule-Based Heuristics + Lexical Machine Learning</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
            AI-Powered Phishing Detection & Awareness
          </h1>

          <p className="text-base sm:text-lg text-slate-300 leading-relaxed font-normal">
            Analyze suspicious email headers, social engineering text patterns, and deceptive URL structures using a local-first, explainable decision support architecture.
          </p>

          <div className="flex flex-wrap items-center gap-4 pt-2">
            <button
              onClick={onStartAnalysis}
              className="px-6 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 shadow-lg shadow-cyan-500/25 transition-all flex items-center gap-2"
            >
              <span>Analyze an Email</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={onExploreArchitecture}
              className="px-5 py-3 rounded-xl font-medium text-slate-300 hover:text-white bg-cyber-800 hover:bg-cyber-700 border border-cyber-700 transition-colors"
            >
              Explore Model Architecture
            </button>
          </div>
        </div>

        <div className="absolute -right-20 -top-20 w-96 h-96 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />
        <div className="absolute right-40 -bottom-20 w-80 h-80 rounded-full bg-blue-600/10 blur-3xl pointer-events-none" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-3">
          <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Lock className="w-5 h-5" />
          </div>
          <h3 className="font-bold text-white text-base">Sender & Domain Authentication</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Detects typosquatting, Levenshtein brand lookalikes, nested brand subdomains, and evaluates SPF, DKIM, and DMARC alignment.
          </p>
        </div>

        <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <Search className="w-5 h-5" />
          </div>
          <h3 className="font-bold text-white text-base">Behavioral Content Heuristics</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Strips zero-width obfuscation and flags urgency coercion, credential solicitation, financial lures, and false authority impersonation.
          </p>
        </div>

        <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Cpu className="w-5 h-5" />
          </div>
          <h3 className="font-bold text-white text-base">Offline Lexical ML URL Model</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Extracts 14 lexical features from raw URLs and scores them against a Random Forest model calibrated to a 1.48% validation FPR.
          </p>
        </div>
      </div>

      <div className="p-8 rounded-2xl border border-cyber-700/60 bg-cyber-900/30 space-y-6">
        <h2 className="text-xl font-bold text-white tracking-tight">How PhishGuard Analyzes Incoming Messages</h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-800 space-y-1.5">
            <span className="font-mono text-cyan-400 text-xs font-bold">STEP 01</span>
            <h4 className="font-semibold text-white text-sm">Envelope & Content Input</h4>
            <p className="text-xs text-slate-400">Ingest headers, email body text, and optional authentication signals.</p>
          </div>
          <div className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-800 space-y-1.5">
            <span className="font-mono text-cyan-400 text-xs font-bold">STEP 02</span>
            <h4 className="font-semibold text-white text-sm">Heuristic & Feature Parsing</h4>
            <p className="text-xs text-slate-400">Extract URLs via Public Suffix List and decompose text with NFKD Unicode.</p>
          </div>
          <div className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-800 space-y-1.5">
            <span className="font-mono text-cyan-400 text-xs font-bold">STEP 03</span>
            <h4 className="font-semibold text-white text-sm">Dual-Track Inference</h4>
            <p className="text-xs text-slate-400">Execute deterministic rule engines alongside the offline Random Forest model.</p>
          </div>
          <div className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-800 space-y-1.5">
            <span className="font-mono text-cyan-400 text-xs font-bold">STEP 04</span>
            <h4 className="font-semibold text-white text-sm">Synthesized Risk Verdict</h4>
            <p className="text-xs text-slate-400">Compute score (0–100), assign category, and generate explainable guidance.</p>
          </div>
        </div>
      </div>
    </div>
  );
};
