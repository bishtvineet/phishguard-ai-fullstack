import React, { useState } from "react";
import { 
  BookOpen, 
  Server, 
  Code2, 
  GitFork, 
  Laptop, 
  Terminal, 
  ShieldCheck, 
  BrainCircuit, 
  Layers,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  HelpCircle
} from "lucide-react";

export const DocsView: React.FC = () => {
  const [chapter, setChapter] = useState<"theory" | "transfer" | "backend" | "frontend" | "workflows">("theory");

  return (
    <div className="space-y-8 py-4 animate-fadeIn max-w-5xl mx-auto text-slate-200">
      {/* Header */}
      <div className="border-b border-cyber-800 pb-5">
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            System Design & Engineering Specification
          </span>
          <span className="text-xs text-slate-500 font-mono">Academic & Production Reference</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight mt-1 flex items-center gap-2">
          <BookOpen className="w-7 h-7 text-cyan-400" />
          PhishGuard AI: Architecture & Operations Book
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          The definitive guide detailing AI taxonomy, lexical NLP mechanics, framework decisions, and the zero-assumption laptop onboarding runbook.
        </p>

        {/* Chapter Navigation Tabs */}
        <div className="flex items-center gap-2 p-1.5 rounded-xl bg-cyber-900 border border-cyber-800 mt-4 flex-wrap">
          <button
            onClick={() => setChapter("theory")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              chapter === "theory"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            Chapter 1: AI, NLP & Design Philosophy
          </button>

          <button
            onClick={() => setChapter("transfer")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              chapter === "transfer"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Laptop className="w-3.5 h-3.5" />
            Chapter 2: New Laptop Setup & Runbook
          </button>

          <button
            onClick={() => setChapter("backend")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              chapter === "backend"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            Chapter 3: Backend & ML Engines
          </button>

          <button
            onClick={() => setChapter("frontend")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              chapter === "frontend"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            Chapter 4: Frontend & API Flows
          </button>

          <button
            onClick={() => setChapter("workflows")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              chapter === "workflows"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <GitFork className="w-3.5 h-3.5" />
            Chapter 5: Math Proofs & Viva Defense
          </button>
        </div>
      </div>

      {/* CHAPTER 1: AI, NLP & SYSTEM DESIGN PHILOSOPHY */}
      {chapter === "theory" && (
        <div className="space-y-6">
          {/* Section 1.1: Where is AI? */}
          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-cyan-400" />
              1.1 Where is the "AI" in this project? (Demystifying AI vs ML)
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              In computer science, <strong>Artificial Intelligence (AI)</strong> is the broad overarching discipline of building software systems that perceive, reason, and make decisions mimicking human experts. <strong>Machine Learning (ML)</strong> is a specialized sub-branch of AI focused on learning statistical patterns from data.
            </p>

            <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
              <pre>{`┌────────────────────────────────────────────────────────────────────────┐
│                      ARTIFICIAL INTELLIGENCE (AI)                      │
│                                                                        │
│  ┌─────────────────────────────────┐  ┌─────────────────────────────┐  │
│  │   Symbolic AI / Expert Systems  │  │    Machine Learning (ML)    │  │
│  │                                 │  │                             │  │
│  │  • Heuristic Rule Aggregation   │  │  • Random Forest Classifier │  │
│  │  • Damerau-Levenshtein Metrics  │  │  • 14 Geometric Features    │  │
│  │  • Public Suffix List Isolation │  │  • Calibrated Threshold     │  │
│  │  • Lexical NLP Normalization    │  │  • Probabilistic Evasion    │  │
│  └─────────────────────────────────┘  └─────────────────────────────┘  │
│                                                                        │
│               ▼                                      ▼                 │
│         [Deterministic Reasoning]              [Statistical Inference] │
│                                                                        │
│                                   │                                    │
│                                   ▼                                    │
│       ┌────────────────────────────────────────────────────────┐       │
│       │           Hybrid Explainable Decision Engine           │       │
│       │           (Mathematical Containment & Risk Score)      │       │
│       └────────────────────────────────────────────────────────┘       │
└────────────────────────────────────────────────────────────────────────┘`}</pre>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-2">
              <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800 space-y-1">
                <span className="font-bold text-cyan-400 block font-mono">1. Statistical Machine Learning AI</span>
                <p className="text-slate-400 leading-relaxed">
                  Instead of hand-coding thousands of static URL string checks, our Random Forest model learned multidimensional non-linear boundaries across 14 structural features (token depth, digit ratio, path entropy), running probability inference in &lt;10ms.
                </p>
              </div>
              <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800 space-y-1">
                <span className="font-bold text-emerald-400 block font-mono">2. Symbolic & Cognitive AI</span>
                <p className="text-slate-400 leading-relaxed">
                  Mimics the decision-making of a human Security Operations Center (SOC) analyst. Evaluates domain proximity metrics (Levenshtein edit operations), identity envelope signatures (SPF/DKIM), and social-engineering pressure levers.
                </p>
              </div>
            </div>
          </div>

          {/* Section 1.2: Is there NLP? */}
          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <BrainCircuit className="w-5 h-5 text-cyan-400" />
              1.2 Are We Using NLP (Natural Language Processing)?
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              <strong>Yes. We use Classical, Lexical, and Semantic Intent NLP.</strong> NLP is the computational manipulation of natural human text—it is not limited to massive Generative LLMs or BERT models.
            </p>

            <div className="space-y-3 text-xs">
              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="font-mono font-bold text-cyan-400 text-sm block mb-1">
                  A. Adversarial Text Normalization (Unicode NFKD Decomposition)
                </span>
                <p className="text-slate-300 leading-relaxed">
                  Attackers deliberately insert invisible zero-width spaces (<code className="text-cyan-300 font-mono">\u200B</code>) or swap Latin letters with identical Cyrillic homoglyphs (e.g. Cyrillic 'а' <code className="text-cyan-300 font-mono">\u0430</code> instead of Latin 'a' <code className="text-cyan-300 font-mono">\u0061</code>) so keyword filters fail.
                </p>
                <p className="text-slate-400 mt-1">
                  <strong>The NLP Pipeline:</strong> The backend runs <code className="text-cyan-300 font-mono">unicodedata.normalize('NFKD', text)</code>, flattening homoglyphs into canonical base forms and stripping control codepoints before analysis.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="font-mono font-bold text-cyan-400 text-sm block mb-1">
                  B. Semantic Social Engineering Intent Extraction
                </span>
                <p className="text-slate-300 leading-relaxed">
                  Phishing text relies on psychological coercion. Our semantic NLP engine categorizes language into three core cognitive triggers:
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mt-2 font-mono text-[11px]">
                  <div className="p-2 rounded bg-cyber-900 border border-cyber-800 text-slate-300">
                    • Temporal Pressure: "within 24 hours", "immediate suspension"
                  </div>
                  <div className="p-2 rounded bg-cyber-900 border border-cyber-800 text-slate-300">
                    • Credential Coercion: "verify identity", "reset password now"
                  </div>
                  <div className="p-2 rounded bg-cyber-900 border border-cyber-800 text-slate-300">
                    • Threat Framing: "account locked", "legal action initiated"
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="font-mono font-bold text-amber-400 text-sm block mb-1">
                  Why Classical Rule-Based NLP instead of Large Language Models (LLMs)?
                </span>
                <p className="text-slate-300 leading-relaxed">
                  1. <strong>Deterministic Latency:</strong> NFKD normalization and intent regex execute in &lt;1 millisecond on CPU. LLMs take 800ms to 4000ms.
                  <br />
                  2. <strong>Zero Hallucination:</strong> An examiner or security auditor can inspect the exact matched phrase. LLMs suffer from probabilistic non-determinism.
                  <br />
                  3. <strong>Data Privacy:</strong> No customer email text is transmitted over the internet to OpenAI, Anthropic, or external cloud endpoints.
                </p>
              </div>
            </div>
          </div>

          {/* Section 1.3: How System Design Was Formulated */}
          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" />
              1.3 How the System Architecture Was Formulated
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              The architecture was designed backwards from two real-world enterprise constraints:
            </p>
            <div className="space-y-3 text-xs">
              <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
                <strong className="text-white block mb-1">Constraint 1: The False Positive Trap</strong>
                <p className="text-slate-400 leading-relaxed">
                  If an AI model misclassifies a genuine CEO memo or legal contract as "Phishing", the business stops. Therefore, we invented the <strong>Mathematical Containment Invariant</strong>: the statistical ML model score is capped at 24 points (18 base + 6 repeat). Because "Suspicious" starts at 25 points, the ML model can <em>never</em> sound a false alarm on its own without corroborating heuristic evidence.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
                <strong className="text-white block mb-1">Constraint 2: The Naive User Experience</strong>
                <p className="text-slate-400 leading-relaxed">
                  End users do not know how to view raw SMTP email source headers or extract link targets behind buttons. Therefore, we built the <strong>Smart Clipboard Ingestion Engine</strong> directly into the React client. When the user pastes formatted email text, the client interceptor queries the DOM for hidden <code className="text-cyan-300 font-mono">&lt;a href="..."&gt;</code> tags and separates envelope headers automatically.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CHAPTER 2: NEW LAPTOP SETUP RUNBOOK */}
      {chapter === "transfer" && (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Terminal className="w-5 h-5 text-cyan-400" />
              Phase 0: Run Terminal Diagnostics on New Laptop
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Open your PowerShell or Terminal first. Run these 4 commands to immediately discover what is already installed and what is missing:
            </p>

            <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 font-mono text-xs text-slate-300 space-y-2">
              <p className="text-cyan-400"># Check Python installation</p>
              <p>python --version    <span className="text-slate-500"># Need: Python 3.10, 3.11, or 3.12</span></p>
              <p className="text-cyan-400 pt-1"># Check Node and npm installation</p>
              <p>node -v             <span className="text-slate-500"># Need: v18.x or v20.x+</span></p>
              <p>npm -v              <span className="text-slate-500"># Need: v9.x or v10.x+</span></p>
              <p className="text-cyan-400 pt-1"># Check Docker Engine</p>
              <p>docker --version    <span className="text-slate-500"># Need: Docker 24.x+</span></p>
              <p>docker compose version</p>
            </div>
          </div>

          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Laptop className="w-5 h-5 text-cyan-400" />
              Phase 1: Install Missing Prerequisites
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-2">
                <span className="font-bold text-emerald-400 block font-mono">1. Python 3.11</span>
                <p className="text-slate-400 leading-relaxed">
                  Download from python.org.
                  <br />
                  <strong className="text-amber-300">Crucial:</strong> Check the box that says <em>"Add python.exe to PATH"</em> during installation.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-2">
                <span className="font-bold text-emerald-400 block font-mono">2. Node.js LTS (20.x)</span>
                <p className="text-slate-400 leading-relaxed">
                  Download the LTS installer from nodejs.org. Run the installer with default settings to get Node and npm.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-2">
                <span className="font-bold text-emerald-400 block font-mono">3. Docker Desktop</span>
                <p className="text-slate-400 leading-relaxed">
                  Download from docker.com. Install and start Docker Desktop. Make sure the whale icon in the taskbar turns solid green (engine running).
                </p>
              </div>
            </div>
          </div>

          <div className="p-6 rounded-2xl border border-amber-500/40 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              Phase 2: Check If Pre-Trained Model Exists
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              In your cloned folder, check if the binary weights file was transferred or ignored:
            </p>
            <div className="p-3 rounded-xl bg-cyber-950 border border-cyber-800 font-mono text-xs">
              <p>Test-Path "backend/app/models/url_rf_model.joblib"</p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs pt-1">
              <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-emerald-300">
                <strong>If True (File Exists):</strong>
                <p className="text-slate-300 mt-1 font-sans">
                  You can skip training completely. Jump straight to <strong>Phase 4 (Run with Docker)</strong>.
                </p>
              </div>
              <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30 text-amber-300">
                <strong>If False (File Missing):</strong>
                <p className="text-slate-300 mt-1 font-sans">
                  You must execute <strong>Phase 3</strong> first to create the Python environment and train the model.
                </p>
              </div>
            </div>
          </div>

          <div className="p-6 rounded-2xl border border-cyan-500/40 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <BrainCircuit className="w-5 h-5 text-cyan-400" />
              Phase 3: Python Virtual Environment & Training (If Model Missing)
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Run these exact sequential commands in PowerShell to create the environment and train the Random Forest artifact:
            </p>

            <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 font-mono text-xs text-slate-200 space-y-2">
              <p className="text-cyan-400"># 1. Navigate into backend</p>
              <p>cd phishing-detector/backend</p>
              <p className="text-cyan-400 pt-1"># 2. Create isolated Python virtual environment</p>
              <p>python -m venv .venv</p>
              <p className="text-cyan-400 pt-1"># 3. Activate the virtual environment</p>
              <p>.\.venv\Scripts\Activate.ps1    <span className="text-slate-500"># Windows</span></p>
              <p className="text-slate-500"># (On Linux or Mac, use: source .venv/bin/activate)</p>
              <p className="text-cyan-400 pt-1"># 4. Install backend dependencies & Scikit-learn</p>
              <p>pip install --upgrade pip</p>
              <p>pip install -r requirements.txt</p>
              <p className="text-cyan-400 pt-1"># 5. Run the offline ML training pipeline</p>
              <p>python -m app.ml.train_url_model</p>
              <p className="text-emerald-400 pt-1"># Output generated: backend/app/models/url_rf_model.joblib</p>
              <p className="text-cyan-400 pt-1"># 6. Verify training with automated tests</p>
              <p>pytest tests/test_ml_detector.py -v</p>
            </div>
          </div>

          <div className="p-6 rounded-2xl border border-emerald-500/40 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              Phase 4: Launch the System (Choose Path A or Path B)
            </h2>

            <div className="space-y-4 text-xs font-mono">
              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-2">
                <span className="text-emerald-400 font-bold font-sans text-sm block">
                  Path A: One-Command Docker Launch (Recommended)
                </span>
                <p className="text-slate-400 font-sans">
                  Builds and networks both the FastAPI backend and Nginx React frontend:
                </p>
                <div className="bg-cyber-900 p-3 rounded-lg text-slate-200">
                  <p>cd phishing-detector</p>
                  <p>docker compose up --build -d</p>
                </div>
                <p className="text-slate-300 font-sans pt-1">
                  • Frontend: <code className="text-cyan-300">http://localhost:3000</code>
                  <br />
                  • Backend Docs: <code className="text-cyan-300">http://localhost:8000/docs</code>
                </p>
              </div>

              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-2">
                <span className="text-cyan-400 font-bold font-sans text-sm block">
                  Path B: Running Without Docker (Local Development)
                </span>
                <p className="text-slate-400 font-sans">
                  Terminal 1 (Backend):
                </p>
                <div className="bg-cyber-900 p-2.5 rounded-lg text-slate-200">
                  <p>cd phishing-detector/backend</p>
                  <p>.\.venv\Scripts\Activate.ps1</p>
                  <p>uvicorn app.main:app --reload --host 127.0.0.1 --port 8000</p>
                </div>
                <p className="text-slate-400 font-sans pt-1">
                  Terminal 2 (Frontend):
                </p>
                <div className="bg-cyber-900 p-2.5 rounded-lg text-slate-200">
                  <p>cd phishing-detector/frontend</p>
                  <p>npm install</p>
                  <p>npm run dev</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CHAPTER 3: BACKEND & ML ENGINES */}
      {chapter === "backend" && (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Server className="w-5 h-5 text-cyan-400" />
              3.1 Backend Core Libraries & Selection Rationale
            </h2>
            <div className="space-y-3 pt-2 text-xs">
              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="font-mono font-bold text-cyan-400 text-sm">fastapi & uvicorn</span>
                <p className="text-slate-300 mt-1 leading-relaxed">
                  High-speed asynchronous routing based on Starlette and Pydantic v2. Auto-generates OpenAPI docs at <code className="text-cyan-300 font-mono">/docs</code>.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="font-mono font-bold text-cyan-400 text-sm">scikit-learn & numpy</span>
                <p className="text-slate-300 mt-1 leading-relaxed">
                  Evaluates 14 geometric lexical features using an ensemble of 100 decision trees in under 10ms on CPU memory without GPU requirements.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="font-mono font-bold text-cyan-400 text-sm">tldextract</span>
                <p className="text-slate-300 mt-1 leading-relaxed">
                  Uses the official Mozilla Public Suffix List to separate the registered apex domain from deceptive multi-level subdomains.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="font-mono font-bold text-cyan-400 text-sm">pydantic (v2)</span>
                <p className="text-slate-300 mt-1 leading-relaxed">
                  Strict schema enforcement, validating bounds and stripping invalid payloads before passing data to detection engines.
                </p>
              </div>
            </div>
          </div>

          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <BrainCircuit className="w-5 h-5 text-cyan-400" />
              3.2 The 14 Geometric Features
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">1. url_length:</strong> Total character count.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">2. num_dots:</strong> Subdomain depth indicator.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">3. num_hyphens:</strong> Brand impersonation separator.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">4. num_underscores:</strong> Obfuscation marker.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">5. num_slashes:</strong> Resource directory depth.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">6. num_questionmarks:</strong> Query string presence.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">7. num_equal_signs:</strong> Parameter count.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">8. num_at_symbols:</strong> Browser auth evasion trick.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">9. num_digits:</strong> Absolute digit count.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">10. digit_ratio:</strong> Ratio of digits to total length.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">11. path_length:</strong> Length of path after domain.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">12. path_token_count:</strong> Segments split by delimiters.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">13. has_ip_address:</strong> Flag for direct IP hosts.
              </div>
              <div className="p-2.5 rounded bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-400">14. suspicious_tld:</strong> High-abuse registrar flag.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CHAPTER 4: FRONTEND & API */}
      {chapter === "frontend" && (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Code2 className="w-5 h-5 text-cyan-400" />
              4.1 Frontend Architecture & Component Hierarchy
            </h2>
            <div className="space-y-3 text-xs">
              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="font-mono font-bold text-cyan-400 text-sm">React 18 + Vite 6 + TypeScript (Strict Mode)</span>
                <p className="text-slate-300 mt-1 leading-relaxed">
                  Vite provides instant Hot Module Replacement during development and compiles into an optimized static bundle using Rollup. Strict TypeScript enforces interface types matching backend Pydantic models.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="font-mono font-bold text-cyan-400 text-sm">Smart Ingestion (AnalyzerForm.tsx)</span>
                <p className="text-slate-300 mt-1 leading-relaxed">
                  Intercepts clipboard events with an in-memory <code className="text-cyan-300 font-mono">DOMParser</code> to scan for hidden hyperlinks inside <code className="text-cyan-300 font-mono">&lt;a href="..."&gt;</code> tags behind clickable text like <em>"Verify Account"</em>.
                </p>
              </div>
            </div>
          </div>

          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" />
              4.2 API Route Specifications
            </h2>
            <div className="space-y-3 text-xs font-mono">
              <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="text-emerald-400 font-bold">POST /api/v1/analyze</span>
                <p className="text-slate-400 mt-1 font-sans">
                  Accepts email envelope, body, and extracted links. Returns score and finding cards.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="text-cyan-400 font-bold">GET /health</span>
                <p className="text-slate-400 mt-1 font-sans">
                  Returns <code className="text-cyan-300">{`{"status":"ok"}`}</code>.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
                <span className="text-purple-400 font-bold">GET /api/v1/health/ml</span>
                <p className="text-slate-400 mt-1 font-sans">
                  Returns model readiness and threshold (<code className="text-cyan-300">0.2232</code>).
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CHAPTER 5: MATH PROOFS & VIVA DEFENSE */}
      {chapter === "workflows" && (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              5.1 The Mathematical Containment Proof
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Why an ML model false alarm cannot classify an email as Suspicious on its own:
            </p>
            <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 font-mono text-xs text-slate-300 space-y-2">
              <p>• Low Risk: [0 - 24] points</p>
              <p>• Suspicious: [25 - 59] points</p>
              <p>• High Risk: [60 - 100] points</p>
              <p className="text-cyan-400 pt-2 font-bold">Formula:</p>
              <p>Max ML Score = 18 base pts + 6 repeat pts = 24 points</p>
              <p className="text-emerald-400 font-bold">Invariant: 24 &lt; 25</p>
              <p className="text-slate-400 text-[11px]">
                The ML model alone cannot push a score to 25. An email requires corroborating heuristic findings (SPF failure, typosquatted sender) to cross into Suspicious.
              </p>
            </div>
          </div>

          <div className="p-6 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <HelpCircle className="w-5 h-5 text-cyan-400" />
              5.2 Core Viva Defense Questions
            </h2>
            <div className="space-y-3 text-xs">
              <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-300 block mb-1">Q: Why did you not use Google Safe Browsing or VirusTotal APIs?</strong>
                <p className="text-slate-400 leading-relaxed">
                  1. <em>Zero Data Leakage:</em> Calling cloud APIs sends proprietary email URLs to 3rd parties.
                  <br />
                  2. <em>Zero-Day Attacks:</em> Phishing links last under 4–8 hours. Blocklists only flag after victims are compromised. Lexical ML catches zero-days on arrival.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
                <strong className="text-cyan-300 block mb-1">Q: Why shouldn't the ML model auto-retrain on live user inputs?</strong>
                <p className="text-slate-400 leading-relaxed">
                  Auto-retraining creates vulnerability to <strong>Data Poisoning Attacks</strong> where an adversary deliberately submits malicious samples labeled as benign to degrade model accuracy. Retraining requires human-in-the-loop review.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};