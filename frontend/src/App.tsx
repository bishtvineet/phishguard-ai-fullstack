import React, { useState, useEffect } from "react";
import { Navbar } from "./components/layout/Navbar";
import { DashboardView } from "./pages/DashboardView";
import { AboutView } from "./pages/AboutView";
import { DocsView } from "./pages/DocsView";
import { AnalyzerForm } from "./components/analysis/AnalyzerForm";
import { ResultsView } from "./components/results/ResultsView";
import { analyzeEmail, checkHealth, checkMlHealth } from "./services/api";
import { AnalysisRequest, AnalysisResponse, SystemHealth } from "./types/analysis";

export const App: React.FC = () => {
  // Check if initial URL is /sys_guide
  const isSecretRoute = window.location.pathname.toLowerCase().startsWith("/sys_guide");

  const [activeTab, setActiveTab] = useState<"dashboard" | "analyze" | "about" | "secret_guide">(
    isSecretRoute ? "secret_guide" : "dashboard"
  );
  const [analysisResult, setAnalysisResult] = useState<AnalysisResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [health, setHealth] = useState<SystemHealth>({
    apiOnline: false,
    mlOnline: false,
    mlStatus: "unknown",
    mlThreshold: null,
  });

  // Listen to browser forward/back buttons
  useEffect(() => {
    const handlePopState = () => {
      if (window.location.pathname.toLowerCase().startsWith("/sys_guide")) {
        setActiveTab("secret_guide");
      } else {
        setActiveTab("dashboard");
      }
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const pollHealth = async () => {
    try {
      const [apiRes, mlRes] = await Promise.allSettled([checkHealth(), checkMlHealth()]);

      const apiOk =
        apiRes.status === "fulfilled" &&
        ["ok", "healthy", "ready", "online"].includes(String(apiRes.value?.status).toLowerCase());

      let mlOk = false;
      let mlStatus = "offline";
      let mlThreshold: number | null = null;

      if (mlRes.status === "fulfilled") {
        const val = mlRes.value;
        mlOk = Boolean(val.available) || ["active", "ready", "ok", "healthy"].includes(String(val.status).toLowerCase());
        mlStatus = val.status || "active";
        mlThreshold = typeof val.threshold === "number" ? Number(val.threshold.toFixed(4)) : null;
      }

      setHealth({
        apiOnline: apiOk,
        mlOnline: mlOk,
        mlStatus,
        mlThreshold,
      });
    } catch {
      setHealth({
        apiOnline: false,
        mlOnline: false,
        mlStatus: "unreachable",
        mlThreshold: null,
      });
    }
  };

  useEffect(() => {
    pollHealth();
    const interval = setInterval(pollHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleAnalyze = async (request: AnalysisRequest) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await analyzeEmail(request);
      setAnalysisResult(res);
      setHealth((prev) => ({ ...prev, apiOnline: true }));
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setError(
          typeof err.response.data.detail === "string"
            ? err.response.data.detail
            : JSON.stringify(err.response.data.detail)
        );
      } else {
        setError(err.message || "Failed to analyze email. Verify that backend is running.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetAnalysis = () => {
    setAnalysisResult(null);
  };

  return (
    <div className="min-h-screen bg-cyber-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      <Navbar 
        activeTab={activeTab === "secret_guide" ? "dashboard" : activeTab} 
        onSelectTab={(tab) => setActiveTab(tab)} 
        health={health} 
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Hidden Book-Guide Route */}
        {activeTab === "secret_guide" && <DocsView />}

        {activeTab === "dashboard" && (
          <DashboardView
            onStartAnalysis={() => setActiveTab("analyze")}
            onExploreArchitecture={() => setActiveTab("about")}
          />
        )}

        {activeTab === "about" && <AboutView />}

        {activeTab === "analyze" && (
          <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
            {analysisResult ? (
              <ResultsView response={analysisResult} onReset={handleResetAnalysis} />
            ) : (
              <div className="space-y-6">
                <div>
                  <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                    Analyze Suspicious Email
                  </h1>
                  <p className="text-sm text-slate-300 mt-1">
                    Paste raw email text or populate individual headers and links for offline inference.
                  </p>
                </div>

                <AnalyzerForm onSubmit={handleAnalyze} isLoading={isLoading} error={error} />
              </div>
            )}
          </div>
        )}
      </main>

      <footer className="border-t border-cyber-800 bg-cyber-950/60 py-6 text-center text-xs text-slate-400 font-mono">
        <p>PhishGuard AI — Offline Explainable Phishing Detection Architecture</p>
      </footer>
    </div>
  );
};

export default App;