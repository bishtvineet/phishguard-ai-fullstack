# URL Machine Learning Model Evaluation & Known Limitations

## 1. Subsystem Overview
The machine learning URL detection component uses an offline `RandomForestClassifier` trained on 14 lexical features extracted from URLs. It functions as an offline, advisory signal evaluated alongside deterministic rule-based analyzers.

- **Artifact Path:** `backend/app/models/artifacts/url_rf_model.joblib`
- **Model Type:** `RandomForestClassifier` (100 estimators, max depth 12)
- **Features:** 14 lexical features (`length_url`, `length_host`, `length_path`, `count_dots`, `count_hyphens`, `count_underscores`, `count_slashes`, `count_digits_url`, `ratio_digits_host`, `entropy_host`, `subdomain_depth`, `has_ip_host`, `has_at_symbol`, `is_https`)
- **Calibrated Decision Threshold:** `0.22317`

---

## 2. Dataset Distribution & Measured Characteristics

The model was trained and evaluated on partitions created from the local raw **UCI PhiUSIIL Phishing URL Dataset (Dataset ID: 967)** located at `backend/data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`.

Across the 235,795 rows in the source CSV, measuring structural features by original dataset label produced the following distribution:

| Structural Attribute | Legitimate (Raw Label 1, N=134,850) | Phishing (Raw Label 0, N=100,945) |
| :--- | :--- | :--- |
| **Contains Query Parameters (`?`)** | **0 (0.00%)** | **6,142 (6.08%)** |
| **Deep Paths (>3 slashes)** | **0 (0.00%)** | **19,759 (19.57%)** |
| **Length > 30 characters** | 31,835 (23.61%) | 60,644 (60.08%) |
| **Length > 60 characters** | **0 (0.00%)** | **16,068 (15.92%)** |
| **HTTPS Scheme** | 134,850 (100.00%) | 49,196 (48.74%) |
| **Contains Hyphens (`-`)** | 10,064 (7.46%) | 36,579 (36.24%) |

### Measured Observations:
1. **Legitimate URL Slice Characteristics:** Across all 134,850 legitimate URLs in the raw CSV, zero contain query parameters (`?`), zero exceed 60 characters in total length, and zero contain more than three slashes (`count_slashes <= 3`). 100% of legitimate records use the HTTPS scheme.
2. **Phishing URL Slice Characteristics:** Phishing URLs in the dataset exhibit query strings (6,142 URLs), paths with more than three slashes (19,759 URLs), and lengths exceeding 60 characters (16,068 URLs).

---

## 3. Structural Bias & Demonstrated False-Positive Behavior

Because the benign training set contains no URLs with query strings or paths containing more than three slashes, the model associates these lexical features strongly with the phishing class.

- **Demonstrated Example:**
  - URL: `https://www.google.com/search?q=cybersecurity`
  - Extracted Features: `length_url=45.0`, `length_host=14.0`, `length_path=7.0`, `count_slashes=1.0`, `is_https=1.0`, `count_dots=2.0`
  - Model Phishing Probability: `0.993749`
  - Decision at Threshold (`0.22317`): Flagged as `ML_URL_SUSPICIOUS_LEXICAL_ANOMALY` (False Positive)
- **Consequence:** Legitimate benign URLs that contain query strings, parameters, or longer path hierarchies can receive high phishing probability scores from the lexical model.

---

## 4. Benchmark Validation-Set Evaluation

Evaluation on the local domain-separated validation partition (`backend/data/processed/val.csv`, N=3,756 URLs across 3,259 distinct domain groups) yielded:

- **Validation Confusion Matrix:**
  - True Negatives (TN): 2,062
  - False Positives (FP): 31
  - False Negatives (FN): 13
  - True Positives (TP): 1,650
- **Validation Metrics (at threshold 0.22317):**
  - **Validation FPR:** 1.48% (satisfies the validation-set design target of <= 1.50%)
  - **Validation Precision:** 98.16%
  - **Validation Recall:** 99.22%
  - **Validation F1-Score:** 98.68%

**Scope of Evaluation:**
These metrics reflect performance strictly on the validation partition derived from the PhiUSIIL dataset, in which legitimate URLs have no query parameters and have lengths <= 60 characters. They are validation-set benchmark metrics and do not represent expected performance on unconstrained real-world traffic or an independent external test corpus.

---

## 5. Architectural Integration & Scoring Impact

As implemented in `app/detectors/ml/analyzer.py` and `app/services/risk_assessor.py`:

1. **Severity Classification:** The ML URL detector emits finding code `ML_URL_SUSPICIOUS_LEXICAL_ANOMALY` strictly at `Severity.MEDIUM`.
2. **Point Calculation:**
   - Under `RiskAssessor`, a `MEDIUM` severity finding contributes a base score of `15` points.
   - Additional occurrences of identical finding indicators add `+2` points each, up to a repeat cap of `+6` points per indicator (yielding a maximum possible contribution of 21 points from `ML_URL_SUSPICIOUS_LEXICAL_ANOMALY`).
3. **Category Boundaries:**
   - `0 - 19`: Low Risk
   - `20 - 49`: Suspicious
   - `50 - 74`: High Risk
   - `75 - 100`: Critical
4. **Independent Score Containment:** Because the maximum contribution from this indicator is capped at 21 points, an analysis where only `ML_URL_SUSPICIOUS_LEXICAL_ANOMALY` findings are triggered cannot exceed 21 points, placing the evaluation in `Suspicious` (or `Low Risk` if only a single URL triggers at 15 points). Reaching `High Risk` (50+) or `Critical` (75+) requires accumulated points from additional distinct findings emitted across the analysis pipeline.
5. **Deterministic Fallback:** If the model artifact is missing or an inference exception occurs, the analyzer sets `is_available = False` and returns no findings, allowing analysis to proceed without service failure.
