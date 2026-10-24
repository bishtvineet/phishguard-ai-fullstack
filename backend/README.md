# Phishing Detection Backend

A local-first FastAPI backend that analyzes submitted email information and returns structured phishing risk assessments with explainable findings and actionable security recommendations. It integrates deterministic heuristic analyzers with an offline lexical machine-learning model for URLs.

> **Educational Project Disclaimer:** This software is developed as an educational decision-support and awareness project for a BCA final-year curriculum. It does not provide absolute guarantees of security or authenticity. A risk score of 0 or a "Low Risk" categorization signifies only that the configured heuristic rules and lexical model did not detect known anomalous patterns in the supplied text; it does not certify that an email or destination URL is legitimate.

---

## Contents

- [System Architecture](#system-architecture)
- [Request Lifecycle](#request-lifecycle)
- [API Endpoints & Contracts](#api-endpoints--contracts)
- [Detection Engines](#detection-engines)
- [Risk Scoring & Containment Invariants](#risk-scoring--containment-invariants)
- [Machine Learning Pipeline](#machine-learning-pipeline)
- [Project Layout](#project-layout)
- [Environment Setup](#environment-setup)
- [Running the Application](#running-the-application)
- [Test Suite & Verification](#test-suite--verification)
- [Known Limitations & Empirical Biases](#known-limitations--empirical-biases)
- [Troubleshooting](#troubleshooting)

---

## System Architecture

```text
HTTP Client (Web UI / Automated Tests)
  │
  ▼
FastAPI Application (Port 8000)
  │
  ├─► LimitPayloadSizeMiddleware (250 KB / 256,000 raw bytes transport ceiling)
  │
  └─► Router: POST /api/v1/analyze
        │
        ▼
      AnalysisService (Pipeline Orchestrator)
        │
        ├──► SenderAnalyzer (Punycode, lookalikes, brand subdomains, auth alignment)
        ├──► ContentAnalyzer (Zero-width chars, NFKD normalization, urgency, credential lures)
        ├──► URL Extraction & Normalization (HTML/plain-text parser, bundled PSL snapshot)
        │     │
        │     ├──► URLAnalyzer (Deterministic rules: IP literals, lookalikes, userinfo)
        │     └──► MLURLAnalyzer (Offline Random Forest model; advisory signal)
        │
        ▼
      RiskAssessor (Centralized Scoring Engine)
        │  ├── Deduplication & target normalization
        │  ├── Base severity weighting + repeat bonuses (capped)
        │  ├── Compound synergy evaluation
        │  └── Score clamping (0–100) & qualitative category mapping
        │
        ▼
      AnalysisResponse (Score, Category, Narrative Summary, Findings, Guidance)
```

The system cleanly separates routing, orchestration, feature extraction, scoring, and ML training into isolated modules. The API operates offline during request analysis: it evaluates structural text patterns and URL syntax without issuing outbound HTTP requests, querying live DNS servers, or executing browser DOMs.

---

## Request Lifecycle

1. **Transport Payload Guard:** `LimitPayloadSizeMiddleware` inspects both the `Content-Length` header and the raw incoming byte stream. If the payload exceeds **250 KB (256,000 bytes)**, the connection is halted with HTTP `413 Payload Too Large`.
2. **Field Schema Validation:** Pydantic parses `AnalysisRequest` against structural typing rules. It rejects malformed sender email syntax, body strings exceeding **100,000 characters**, and individual URLs exceeding **2,048 characters**, returning HTTP `422 Unprocessable Entity` on violation.
3. **Sender & Content Inspection:**
   - `SenderAnalyzer` normalizes domains using an offline Public Suffix List snapshot (`tldextract.TLDExtract(cache_dir=None)`), computes Levenshtein distances against configured trusted brands, and evaluates caller-supplied SPF, DKIM, and DMARC parameters.
   - `ContentAnalyzer` scans for and purges invisible zero-width evasion characters (`\u200b`, `\u200c`, `\u200d`, `\ufeff`, `\u00ad`), strips HTML markup with unclosed tag suppression, normalizes Unicode via NFKD decomposition, and matches regex heuristics.
4. **Unified URL Extraction:** `extract_urls()` scans HTML `<a>` tags and plain-text URLs in a single unified pass. It normalizes schemes, strips default ports (80/443) and trailing root slashes, deduplicates candidates, and caps analysis to the first 50 unique URLs.
5. **Dual URL Evaluation:**
   - **Deterministic:** `URLAnalyzer` inspects authority integrity (embedded credentials, public IP literals, non-standard ports), path depth, double percent-encoding, and open redirect parameters.
   - **Machine Learning:** `MLURLAnalyzer` verifies that the serialized model artifact is valid. If active, it extracts 14 lexical features from each normalized URL and evaluates phishing probabilities against the calibrated threshold ($0.2232$). If absent or invalid, it returns zero findings without service failure.
6. **Risk Assessment:** `RiskAssessor` groups findings by indicator, applies severity weights, calculates target repeat bonuses, tests single-fire compound synergies, clamps the score to $[0, 100]$, and assigns the qualitative category.
7. **Actionable Delivery:** `AnalysisService` maps active findings to specific mitigation guidance and serializes the final `AnalysisResponse`.

---

## API Endpoints & Contracts

### 1. Phishing Analysis Endpoint
- **Route:** `POST /api/v1/analyze`
- **Description:** Analyzes email headers, body content, extracted URLs, and authentication telemetry.

#### Request Example
```json
{
  "sender_email": "security-alert@paypa1.com",
  "reply_to": "attacker-inbox@suspicious-domain.com",
  "subject": "Urgent: Account Suspension Notice",
  "body": "Dear Customer, please verify your credentials within 24 hours: https://paypal.com.attacker-portal.net/login",
  "additional_urls": [
    "https://paypal.com.attacker-portal.net/login"
  ],
  "authentication": {
    "spf": "fail",
    "dkim": "none",
    "dmarc": "fail"
  }
}
```

#### Actual Verified Response
```json
{
  "risk_score": 100,
  "risk_category": "High Risk",
  "summary": "Analysis completed with 8 indicator(s) resulting in a risk score of 100/100 (High Risk).",
  "findings": [
    {
      "analyzer": "sender",
      "indicator": "LOOKALIKE_TRUSTED_DOMAIN",
      "description": "Sender domain label 'paypa1' closely resembles trusted brand 'paypal.com' via character substitution or edit distance.",
      "severity": "high",
      "target": null
    },
    {
      "analyzer": "sender",
      "indicator": "REPLY_TO_DOMAIN_MISMATCH",
      "description": "Reply-To address points to an unrelated domain ('suspicious-domain.com') instead of the sender domain ('paypa1.com').",
      "severity": "medium",
      "target": null
    },
    {
      "analyzer": "sender",
      "indicator": "DMARC_POLICY_FAILED",
      "description": "Email explicitly failed reported DMARC policy validation, indicating failure of domain alignment across SPF or DKIM mechanisms.",
      "severity": "high",
      "target": null
    },
    {
      "analyzer": "sender",
      "indicator": "SPF_AUTHENTICATION_FAILED",
      "description": "Sending server is not authorized under the domain's published SPF policy.",
      "severity": "info",
      "target": null
    },
    {
      "analyzer": "content",
      "indicator": "CONTENT_URGENCY_PRESSURE",
      "description": "Email body: Language exerts psychological time pressure or threatens account suspension to compel immediate recipient action.",
      "severity": "medium",
      "target": null
    },
    {
      "analyzer": "content",
      "indicator": "CONTENT_GENERIC_SALUTATION",
      "description": "Email body: Uses an impersonal salutation (e.g., 'Dear Customer') rather than addressing the recipient by name, typical of mass automated phishing campaigns.",
      "severity": "low",
      "target": null
    },
    {
      "analyzer": "url",
      "indicator": "URL_BRAND_NAME_IN_UNRELATED_DOMAIN",
      "description": "URL hostname 'paypal.com.attacker-portal.net' places trusted brand name(s) ['paypal'] into a subdomain of an unrelated domain 'attacker-portal.net'.",
      "severity": "high",
      "target": null
    },
    {
      "analyzer": "ml_url",
      "indicator": "ML_URL_SUSPICIOUS_LEXICAL_ANOMALY",
      "description": "Machine learning lexical model classified URL 'https://paypal.com.attacker-portal.net/login' as suspicious (probability: 0.9937, threshold: 0.2232).",
      "severity": "medium",
      "target": "attacker-portal.net"
    }
  ],
  "recommendations": [
    "Verify suspicious emails through known, out-of-band communication channels.",
    "Do not click unverified links or supply credentials on unknown websites.",
    "Sender domain appears deceptive or mimics a well-known brand. Check the domain spelling carefully.",
    "Message failed domain alignment (DMARC). The email may be forged or sent by an unauthorized mail relay.",
    "Be cautious of artificial deadlines or threats of account suspension; independently confirm account status.",
    "Links in this message appear to imitate legitimate services using deceptive domain names. Check destination URLs carefully before interacting.",
    "One or more links show statistical anomalies common to phishing attacks. Exercise extreme caution."
  ]
}
```

*Inconclusive Gate Behavior:* When an incoming message lacks evaluatable substance (empty subject, body under 10 characters, and no user-supplied URLs), the API returns `risk_category: "Inconclusive"` with `risk_score: null`.

### 2. Operational Health Endpoints
- **`GET /health`**: General application health check returning `{"status": "ok"}`.
- **`GET /api/v1/health/ml`**: Reports ML URL model operational readiness:
  ```json
  {
    "available": true,
    "status": "active",
    "threshold": 0.2231700469605578
  }
  ```

---

## Detection Engines

### 1. Sender Analyzer (`app/detectors/sender/`)
- **Lookalike Brand Spoofing:** Identifies deceptive domain variations against configured trusted domains (`paypal.com`, `google.com`, `microsoft.com`, `apple.com`, `amazon.com`) using Levenshtein distance $\le 1$ and leet-speak character substitutions (`0` $\to$ `o`, `1` $\to$ `l`, `vv` $\to$ `w`, `5` $\to$ `s`, etc.).
- **Subdomain Brand Injection:** Detects trusted brand names placed inside subdomain labels of unrelated registered domains (tokenized across dots and hyphens).
- **Authentication Alignment:** Evaluates DMARC, SPF, and DKIM inputs. When DMARC explicitly fails (`HIGH` severity), SPF and DKIM failures are downgraded to `INFO` severity to prevent artificial score inflation from correlated failure mechanisms.

### 2. Content Heuristics Analyzer (`app/detectors/content/`)
- **Sanitization & Normalization:** Strips zero-width evasion codepoints (`\u200b`, `\u200c`, `\u200d`, `\ufeff`, `\u00ad`), decodes HTML entities, suppresses `<script>` and `<style>` blocks, and applies Unicode NFKD normalization.
- **Behavioral Lures:** Matches compiled regular expressions for psychological urgency, credential solicitation, financial lures, authority impersonation, and generic salutations within the introductory 100 characters.

### 3. Deterministic URL Analyzer (`app/detectors/url/`)
- **Authority Integrity:** Detects embedded authentication credentials (`user:pass@host`), public IP literals, non-standard web ports, and Punycode hostnames.
- **Structural Anomalies:** Identifies suspicious top-level domains, excessive path depth ($\ge 6$), double percent-encoding (`%25xx`), unencrypted HTTP on credential paths, and open redirect parameters.

### 4. Machine Learning URL Analyzer (`app/detectors/ml/`)
- **Model Architecture:** Offline Scikit-learn `RandomForestClassifier` (100 estimators, max depth 12, min samples per leaf 5).
- **14 Lexical Features:**
  1. `length_url`: Total character length of normalized URL
  2. `length_host`: Character length of hostname
  3. `length_path`: Character length of path
  4. `count_dots`: Total dot count in URL
  5. `count_hyphens`: Total hyphen count in URL
  6. `count_underscores`: Total underscore count in URL
  7. `count_slashes`: Total slash count in path
  8. `count_digits_url`: Numeric digit count across entire URL
  9. `ratio_digits_host`: Ratio of numeric digits to total hostname length
  10. `entropy_host`: Shannon entropy (base 2) of hostname characters
  11. `subdomain_depth`: Number of dot-separated subdomain levels
  12. `has_ip_host`: Binary flag indicating whether the host is an IP address
  13. `has_at_symbol`: Binary flag indicating embedded credentials (`@`)
  14. `is_https`: Binary flag indicating HTTPS protocol usage
- **Inference & Fallback:** Emits finding `ML_URL_SUSPICIOUS_LEXICAL_ANOMALY` (`MEDIUM` severity) when predicted phishing probability meets or exceeds the threshold ($T \approx 0.2232$). If the artifact is unavailable, it gracefully sets `is_available = False` and returns zero findings without service failure.

---

## Risk Scoring & Containment Invariants

Configured in `app/core/config.py` and calculated in `app/services/risk_assessor.py`:

### Base Severity Weights
| Severity | Base Weight |
| :--- | :--- |
| **HIGH** | 35 points |
| **MEDIUM** | 18 points |
| **LOW** | 7 points |
| **INFO** | 0 points |

### Aggregation Rules
1. **Deduplication:** Findings sharing the exact `(analyzer, indicator, target)` tuple are collapsed.
2. **Indicator Grouping:** Multiple findings under the same indicator across different targets adopt the maximum observed severity.
3. **Repeat Target Bonus:** Each distinct additional target beyond the first adds $+2$ points, capped at $+6$ points per indicator group.
4. **Compound Synergies:**
   - *Identity Mimicry & Credential Solicitation:* $+15$ points
   - *Urgency Pressure & Financial Lure:* $+10$ points
   - *Unencrypted Insecure Credential Collection:* $+10$ points
5. **Score Clamping:** Scores are bounded strictly between $0$ and $100$.

### Qualitative Category Thresholds
- **0–24**: **Low Risk** — Minimal or low-severity indicators observed.
- **25–59**: **Suspicious** — Multiple low or medium indicators present; warrants caution.
- **60–100**: **High Risk** — Strong indicator combinations or high-severity indicators detected.
- **Insufficient Input**: **Inconclusive** (Score: `null`) — Subject and body lack evaluatable content.

*(Note: The system defines exactly four qualitative categories. There is no "Critical" category.)*

### Mathematical Containment Proof for ML URL Findings
The ML URL detector emits finding code `ML_URL_SUSPICIOUS_LEXICAL_ANOMALY` at `MEDIUM` severity ($18$ base points).
1. When multiple URLs trigger this finding across distinct target domains, each additional target adds $+2$ points up to the configured `MAX_REPEAT_BONUS = 6`.
2. The maximum possible point contribution from the ML URL detector is therefore bounded at:
   $$\text{Max ML Score} = 18 + 6 = 24 \text{ points}$$
3. Furthermore, `ML_URL_SUSPICIOUS_LEXICAL_ANOMALY` is not part of the `_IDENTITY_INDICATORS` set (`LOOKALIKE_TRUSTED_DOMAIN`, `BRAND_NAME_IN_UNRELATED_DOMAIN`, `URL_LOOKALIKE_DOMAIN`, `URL_BRAND_NAME_IN_UNRELATED_DOMAIN`) and cannot trigger any compound synergy bonuses.
4. Because the `Suspicious` category boundary begins at **25 points**, **ML URL findings alone strictly cannot exceed `Low Risk` ($0\text{--}24$)**. An assessment can only transition to `Suspicious` ($25\text{--}59$) or `High Risk` ($60\text{--}100$) when corroborated by additional distinct indicators from the deterministic analyzers.

---

## Machine Learning Pipeline

Decoupled scripts located in `backend/scripts/`:

### 1. Dataset Preparation (`scripts/prepare_dataset.py`)
- Ingests raw records from `backend/data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` (UCI ML Repository Dataset ID: 967).
- Inverts labels: raw `1` $\to$ `0` (Legitimate), raw `0` $\to$ `1` (Phishing).
- Groups records by domain to ensure **zero domain group overlap** across partitions.
- Allocates partitions via greedy deficit-filling into 70% Train, 15% Validation, and 15% Test.
- Exports split CSVs (`train.csv`, `val.csv`, `test.csv`) and `metadata.json` to `backend/data/processed/`.

```powershell
python scripts/prepare_dataset.py --max-urls 25000 --seed 42
```

### 2. Model Training (`scripts/train_url_model.py`)
- Trains a `RandomForestClassifier` on `train.csv`.
- Calibrates the decision threshold on `val.csv` to satisfy $\text{FPR} \le 1.50\%$ with maximum sensitivity.
- Exports the model atomically to `backend/app/models/artifacts/url_rf_model.joblib`.

```powershell
python scripts/train_url_model.py --target-fpr 0.015 --seed 42
```

---

## Project Layout

```text
backend/
├── app/
│   ├── api/
│   │   └── v1/
│   │       └── endpoints/
│   │           ├── analysis.py       # POST /api/v1/analyze
│   │           └── health.py         # GET /api/v1/health/ml
│   ├── core/
│   │   └── config.py                 # Central configuration and scoring settings
│   ├── detectors/
│   │   ├── content/                  # Text normalizers and heuristics
│   │   ├── ml/                       # Offline ML URL analyzer
│   │   ├── sender/                   # Sender domain and auth analyzer
│   │   └── url/                      # Deterministic URL analyzer
│   ├── middleware/
│   │   └── request_size.py           # 250 KB streaming payload size limiter
│   ├── ml/
│   │   └── features.py               # 14 lexical URL feature extractors
│   ├── models/
│   │   └── artifacts/
│   │       └── url_rf_model.joblib   # Serialized Random Forest model artifact
│   ├── schemas/
│   │   └── analysis.py               # Pydantic request and response schemas
│   ├── services/
│   │   ├── analysis_service.py       # Pipeline orchestration
│   │   └── risk_assessor.py          # Centralized risk scoring engine
│   └── main.py                       # FastAPI application entry point
├── data/
│   ├── raw/                          # Raw dataset CSV (PhiUSIIL)
│   └── processed/                    # Partitioned CSVs and metadata.json
├── docs/
│   └── model_evaluation.md           # Dataset limitations and FPR analysis
├── scripts/
│   ├── prepare_dataset.py            # Dataset cleaning and domain-group splitting
│   └── train_url_model.py            # Model training and artifact export
├── tests/
│   ├── unit/                         # Unit test suites across modules
│   ├── test_analysis_contract.py     # End-to-end API integration tests
│   ├── test_health.py                # System health check tests
│   └── test_ml_health.py             # ML operational readiness tests
├── requirements.txt                  # Production runtime dependencies
└── requirements-dev.txt              # Testing and development dependencies
```

---

## Environment Setup

Run commands from the `backend/` directory in PowerShell:

```powershell
# 1. Create Python virtual environment
python -m venv .venv

# 2. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

---

## Running the Application

Start the local development server:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- **Interactive Swagger Docs:** http://127.0.0.1:8000/docs
- **ReDoc Documentation:** http://127.0.0.1:8000/redoc
- **Application Health:** http://127.0.0.1:8000/health
- **ML Engine Health:** http://127.0.0.1:8000/api/v1/health/ml

---

## Test Suite & Verification

Run the entire regression test suite using `pytest`:

```powershell
pytest -q
```

**Verified Test Status:**
- **Results:** **118 passed** tests across 14 test modules in ~4.8s.
- **Coverage Areas:** API request/response contracts, health endpoints, payload size limits, zero-width character stripping, NFKD Unicode decomposition, brand lookalike algorithms, Public Suffix List decomposition, deterministic URL heuristics, ML feature extraction, model threshold selection, domain-isolated group partitioning, and risk scoring synergies.

---

## Known Limitations & Empirical Biases

Detailed empirical findings are documented in [`backend/docs/model_evaluation.md`](docs/model_evaluation.md):

1. **Offline Lexical Scope:** Analyzers inspect text and URL structures statically without active DNS queries, page fetching, or DOM execution.
2. **Caller-Supplied Authentication:** SPF, DKIM, and DMARC results reflect caller-provided inputs; the service does not evaluate DNS cryptographic signatures directly.
3. **Demonstrated False Positive on Google Query Example:**
   - Evaluating `https://www.google.com/search?q=cybersecurity` with the loaded model produces an exact predicted phishing probability of **`0.993749`** against the threshold of **`0.223170`**, triggering a false positive (`ML_URL_SUSPICIOUS_LEXICAL_ANOMALY`).
   - *Empirical Cause:* In the local UCI PhiUSIIL dataset ($235,795$ rows), all $134,850$ legitimate records are root domain URLs with zero query parameters (`?`), lengths $\le 60$, and $\le 3$ slashes. As a result, lexical models trained on this split associate query strings and deep subpaths heavily with phishing. This demonstrates a documented limitation of lexical models trained on root-only benign sets, though it does not imply that every search URL across the web will produce identical probabilities.
4. **Validation FPR Benchmark Scope:**
   - Metrics recorded in the model artifact metadata:
     - **Validation Sample Count:** $3,756$ URLs
     - **True Negatives:** $2,062$
     - **False Positives:** $31$
     - **False Negatives:** $13$
     - **True Positives:** $1,650$
     - **Validation FPR:** **$1.4811\%$** (satisfies the design target of $\le 1.50\%$)
     - **Validation Precision:** **$98.1559\%$**
     - **Validation Recall:** **$99.2183\%$**
     - **Validation F1-Score:** **$98.6842\%$**
   - *Scope Distinction:* These metrics reflect performance strictly on the domain-separated benchmark validation split derived from the PhiUSIIL corpus. They are validation benchmark metrics and do not represent expected performance across unconstrained real-world traffic.

---

## Troubleshooting

### 1. `GET /api/v1/health/ml` reports `"available": false`
- **Cause:** `backend/app/models/artifacts/url_rf_model.joblib` is missing, unreadable, or invalid.
- **Resolution:** Run `scripts/prepare_dataset.py` followed by `scripts/train_url_model.py`. Check the `status` field in the response (`artifact_not_found`, `corrupt_artifact`, or `incompatible_artifact`).

### 2. HTTP 413 Payload Too Large
- **Cause:** Request body exceeds the **250 KB (256,000 bytes)** streaming transport limit.
- **Resolution:** Truncate large email bodies. The API enforces a $100,000$ character ceiling on the `body` field.

### 3. HTTP 422 Unprocessable Entity
- **Cause:** Failed Pydantic schema validation (malformed email syntax or URL exceeding $2,048$ characters).
- **Resolution:** Verify input syntax against `AnalysisRequest` in `app/schemas/analysis.py`.