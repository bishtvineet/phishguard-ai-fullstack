import React from "react";
import { ShieldCheck, Brain, Server } from "lucide-react";
import { SystemHealth } from "../../types/analysis";

interface NavbarProps {
  activeTab: "dashboard" | "analyze" | "about";
  onSelectTab: (tab: "dashboard" | "analyze" | "about") => void;
  health: SystemHealth;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onSelectTab, health }) => {
  return (
    <header className="sticky top-0 z-50 border-b border-cyber-700/60 bg-cyber-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div 
            className="flex items-center gap-3 cursor-pointer group"
            onClick={() => {
              window.history.pushState({}, "", "/");
              onSelectTab("dashboard");
            }}
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 group-hover:shadow-cyan-500/40 transition-all">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-tight text-white text-lg">PhishGuard</span>
                <span className="text-xs uppercase tracking-wider font-extrabold px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">AI</span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium">Detection & Awareness System</p>
            </div>
          </div>

          <nav className="hidden md:flex items-center gap-1">
            <button
              onClick={() => {
                window.history.pushState({}, "", "/");
                onSelectTab("dashboard");
              }}
              className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === "dashboard"
                  ? "bg-cyber-800 text-cyan-400 border border-cyan-500/30 shadow-sm"
                  : "text-slate-300 hover:text-white hover:bg-cyber-850"
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => {
                window.history.pushState({}, "", "/");
                onSelectTab("analyze");
              }}
              className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === "analyze"
                  ? "bg-cyber-800 text-cyan-400 border border-cyan-500/30 shadow-sm"
                  : "text-slate-300 hover:text-white hover:bg-cyber-850"
              }`}
            >
              Analyze Email
            </button>
            <button
              onClick={() => {
                window.history.pushState({}, "", "/");
                onSelectTab("about");
              }}
              className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === "about"
                  ? "bg-cyber-800 text-cyan-400 border border-cyan-500/30 shadow-sm"
                  : "text-slate-300 hover:text-white hover:bg-cyber-850"
              }`}
            >
              Model Specs
            </button>
          </nav>

          <div className="flex items-center gap-2.5">
            <div 
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border ${
                health.apiOnline
                  ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-400"
                  : "bg-rose-950/40 border-rose-500/30 text-rose-400"
              }`}
              title={health.apiOnline ? "FastAPI Backend is operational" : "Backend unreachable at 127.0.0.1:8000"}
            >
              <Server className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">API</span>
              <span className={`w-1.5 h-1.5 rounded-full ${health.apiOnline ? "bg-emerald-400 animate-pulse" : "bg-rose-400"}`} />
            </div>

            <div 
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border ${
                health.mlOnline
                  ? "bg-cyan-950/40 border-cyan-500/30 text-cyan-400"
                  : "bg-slate-900 border-slate-700 text-slate-400"
              }`}
              title={
                health.mlOnline
                  ? `ML URL Random Forest active (Threshold: ${health.mlThreshold ?? 0.2232})`
                  : `ML URL model inactive (${health.mlStatus})`
              }
            >
              <Brain className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">ML URL</span>
              <span className={`w-1.5 h-1.5 rounded-full ${health.mlOnline ? "bg-cyan-400" : "bg-slate-500"}`} />
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};