# PhishGuard AI: Master Architecture, Engineering & Viva Defense Guide

This document is the definitive technical reference for the PhishGuard AI project. It details the complete technology stack, architectural decisions, mathematical containment proofs, ML training mechanics, and technical Q&A designed for project examiners, interviewers, and senior engineers.

---

## 1. High-Level Architecture & Component Stack

```text
                                [ User / Examiner Browser ]
                                             │
                                             │ HTTP (Port 3000)
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               FRONTEND CONTAINER (Nginx)                               │
│  - Engine: React 18, TypeScript 5.6 (Strict Mode), Vite 6, Tailwind CSS 3.4           │
│  - Smart Ingestion: In-memory DOMParser (captures text/plain AND text/html clipboard)   │
│  - Visualization: Dynamic SVG Radial Gauge (0-100), Responsive CSS Finding Cards       │
│  - Nginx Alpine: Static asset delivery & reverse proxy (/api/ -> backend:8000/api/)   │
└────────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │
                                             │ Internal Docker Network (HTTP Port 8000)
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              BACKEND CONTAINER (FastAPI)                               │
│  - Runtime: Python 3.11-slim, Uvicorn ASGI Server, Pydantic v2 validation              │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              FOUR DETECTION ENGINES                              │  │
│  │                                                                                  │  │
│  │ 1. Sender & Domain Analyzer (Deterministic Heuristic)                            │  │
│  │    • Public Suffix List (tldextract) domain isolation                            │  │
│  │    • Levenshtein Distance (Damerau-Levenshtein metric) for typosquatting         │  │
│  │    • Subdomain brand spoofing & SPF/DKIM/DMARC cryptographic alignment checks    │  │
│  │                                                                                  │  │
│  │ 2. Content & Behavioral Analyzer (NLP Heuristic)                                 │  │
│  │    • Unicode normalization (NFKD) stripping zero-width spaces & homoglyphs       │  │
│  │    • Regex heuristics for urgency, deadline threats, credential harvesting       │  │
│  │                                                                                  │  │
│  │ 3. Deterministic URL Analyzer (Structural Heuristic)                             │  │
│  │    • Anchor text vs. destination href mismatch detection                        │  │
│  │    • IP-literal hosts, multi-TLD chains, and obfuscated hex/octal encodings      │  │
│  │                                                                                  │  │
│  │ 4. Machine Learning Lexical Classifier (Offline Scikit-Learn Random Forest)      │  │
│  │    • url_rf_model.joblib (14 geometric features extracted strictly offline)      │  │
│  │    • Calibrated Threshold: 0.2232 (False Positive Rate <= 1.48% on clean data)  │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
│                                             │                                          │
│                                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                        CENTRALIZED RISK AGGREGATOR                               │  │
│  │  • Base Weights: HIGH = 35 pts | MEDIUM = 18 pts | LOW = 7 pts | INFO = 0 pts    │  │
│  │  • Mathematical Containment Bound: ML URL Model capped at 24 pts max (Low Risk) │  │
│  │  • Scoring Categories: Low Risk (0-24) | Suspicious (25-59) | High Risk (60-100) │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘