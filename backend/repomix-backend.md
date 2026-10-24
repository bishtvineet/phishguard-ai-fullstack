This file is a merged representation of a subset of the codebase, containing files not matching ignore patterns, combined into a single document by Repomix.

# File Summary

## Purpose
This file contains a packed representation of a subset of the repository's contents that is considered the most important context.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching these patterns are excluded: **/.venv/**, **/__pycache__/**, **/*.joblib, **/*.pkl, **/*.parquet, **/*.csv
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
app/__init__.py
app/api/__init__.py
app/api/v1/__init__.py
app/api/v1/endpoints/__init__.py
app/api/v1/endpoints/analysis.py
app/api/v1/endpoints/health.py
app/core/__init__.py
app/core/config.py
app/detectors/__init__.py
app/detectors/content/__init__.py
app/detectors/content/analyzer.py
app/detectors/content/text_utils.py
app/detectors/ml/__init__.py
app/detectors/ml/analyzer.py
app/detectors/sender/__init__.py
app/detectors/sender/analyzer.py
app/detectors/sender/domain_utils.py
app/detectors/url/__init__.py
app/detectors/url/analyzer.py
app/detectors/url/url_utils.py
app/main.py
app/middleware/__init__.py
app/middleware/request_size.py
app/ml/__init__.py
app/ml/features.py
app/schemas/__init__.py
app/schemas/analysis.py
app/services/__init__.py
app/services/analysis_service.py
app/services/risk_assessor.py
backend/docs/model_evaluation.md
data/processed/metadata.json
docs/model_evaluation.md
README.md
requirements-dev.txt
requirements.txt
scripts/prepare_dataset.py
scripts/train_url_model.py
tests/__init__.py
tests/test_analysis_contract.py
tests/test_health.py
tests/test_ml_health.py
tests/unit/__init__.py
tests/unit/test_content_analyzer.py
tests/unit/test_content_text_utils.py
tests/unit/test_ml_analyzer.py
tests/unit/test_ml_features.py
tests/unit/test_prepare_dataset.py
tests/unit/test_risk_assessor.py
tests/unit/test_sender_analyzer.py
tests/unit/test_sender_domain_utils.py
tests/unit/test_train_url_model.py
tests/unit/test_url_analyzer.py
tests/unit/test_url_utils.py
```

# Files

## File: app/__init__.py
````python

````

## File: app/api/__init__.py
````python

````

## File: app/api/v1/__init__.py
````python

````

## File: app/api/v1/endpoints/__init__.py
````python

````

## File: app/api/v1/endpoints/analysis.py
````python
from fastapi import APIRouter, status
from app.schemas.analysis import AnalysisRequest, AnalysisResponse
from app.services.analysis_service import analysis_service

router = APIRouter(prefix="/analyze", tags=["Analysis"])


@router.post(
    "",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze suspicious email content",
    description="Accepts email headers, content, URLs, and optional authentication signals for phishing evaluation.",
)
def analyze_email(request: AnalysisRequest) -> AnalysisResponse:
    """Delegates request to the analysis service layer."""
    return analysis_service.analyze_email(request)
````

## File: app/api/v1/endpoints/health.py
````python
from typing import Any, Dict, Optional
from fastapi import APIRouter
from pydantic import BaseModel

from app.detectors.ml.analyzer import ml_url_analyzer

router = APIRouter(prefix="/health", tags=["Health"])


class MLHealthResponse(BaseModel):
    available: bool
    status: str
    threshold: Optional[float] = None


@router.get("/ml", response_model=MLHealthResponse)
def get_ml_health() -> Dict[str, Any]:
    """Provides operational readiness and status diagnostics for the ML URL model."""
    return {
        "available": ml_url_analyzer.is_available,
        "status": ml_url_analyzer.status_reason,
        "threshold": ml_url_analyzer.threshold if ml_url_analyzer.is_available else None,
    }
````

## File: app/core/__init__.py
````python

````

## File: app/core/config.py
````python
import re
from dataclasses import dataclass, field
from typing import Pattern, Set


@dataclass(frozen=True)
class ContentAnalysisSettings:
    """Centralized regex patterns and thresholds for content heuristic detection."""

    URGENCY_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(within\s+\d+\s+(?:hours?|days?)|immediate(?:ly)?\s+action|account\s+will\s+be\s+suspended|final\s+notice|immediate\s+suspension)\b",
            re.IGNORECASE,
        )
    )

    CREDENTIAL_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(verify|confirm|reset|update|enter)\b[\w\s]{0,20}\b(password|passcode|pin|login\s+credentials|secret\s+key)\b",
            re.IGNORECASE,
        )
    )

    FINANCIAL_LURE_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(unclaimed\s+(?:funds?|assets?|inheritance)|lottery\s+winner|wire\s+transfer\s+reward|crypto\s+giveaway|tax\s+refund\s+pending|pending\s+tax\s+refund)\b",
            re.IGNORECASE,
        )
    )

    AUTHORITY_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(it\s+support\s+desk|account\s+investigation\s+unit|security\s+dispatch\s+team|legal\s+compliance\s+department)\b",
            re.IGNORECASE,
        )
    )

    SALUTATION_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"^(?:dear\s+(?:customer|user|member|client|sir\s*/\s*madam|account\s+holder))\b",
            re.IGNORECASE,
        )
    )

    SALUTATION_MAX_OFFSET: int = 100


@dataclass(frozen=True)
class URLAnalysisSettings:
    """Centralized configuration, patterns, and thresholds for URL analysis."""

    SUSPICIOUS_TLDS: Set[str] = field(
        default_factory=lambda: {
            "top",
            "xyz",
            "fit",
            "rest",
            "buzz",
            "cfd",
            "sbs",
            "club",
            "work",
            "surf",
        }
    )

    STANDARD_PORTS: Set[int] = field(
        default_factory=lambda: {80, 443, 8080}
    )

    MAX_URLS_TO_ANALYZE: int = 50
    MAX_URL_LENGTH: int = 2048
    MAX_PATH_DEPTH: int = 6

    CREDENTIAL_PATH_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(login|signin|account|verify|password|auth|billing)\b",
            re.IGNORECASE,
        )
    )

    REDIRECT_PARAM_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"[?&](?:next|redirect|redirect_uri|url|dest|destination|target)=https?://",
            re.IGNORECASE,
        )
    )


@dataclass(frozen=True)
class RiskScoringSettings:
    """Weights, repeat steps, and thresholds for centralized risk assessment."""

    WEIGHT_HIGH: int = 35
    WEIGHT_MEDIUM: int = 18
    WEIGHT_LOW: int = 7
    WEIGHT_INFO: int = 0

    REPEAT_STEP: int = 2
    MAX_REPEAT_BONUS: int = 6

    SYNERGY_IDENTITY_CREDENTIAL: int = 15
    SYNERGY_URGENCY_FINANCIAL: int = 10
    SYNERGY_INSECURE_CREDENTIAL: int = 10

    THRESHOLD_SUSPICIOUS: int = 25
    THRESHOLD_HIGH_RISK: int = 60


@dataclass(frozen=True)
class AppSettings:
    """Aggregated configuration for all detection engines."""

    # Sender Analysis Settings
    TRUSTED_DOMAINS: Set[str] = field(
        default_factory=lambda: {
            "paypal.com",
            "google.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
        }
    )

    SUSPICIOUS_DOMAIN_KEYWORDS: Set[str] = field(
        default_factory=lambda: {
            "verify",
            "verification",
            "secure",
            "security",
            "login",
            "signin",
            "update",
            "billing",
            "account",
            "support",
            "banking",
        }
    )

    WELL_KNOWN_BULK_SENDERS: Set[str] = field(
        default_factory=lambda: {
            "sendgrid.net",
            "mailchimp.com",
            "amazonses.com",
            "zendesk.com",
            "salesforce.com",
            "hubspot.com",
            "mailgun.org",
        }
    )

    MAX_UNSUSPICIOUS_SUBDOMAIN_DEPTH: int = 4

    # Sub-Engine Settings
    content: ContentAnalysisSettings = field(default_factory=ContentAnalysisSettings)
    url: URLAnalysisSettings = field(default_factory=URLAnalysisSettings)
    scoring: RiskScoringSettings = field(default_factory=RiskScoringSettings)


settings = AppSettings()
````

## File: app/detectors/__init__.py
````python

````

## File: app/detectors/content/__init__.py
````python

````

## File: app/detectors/content/analyzer.py
````python
from typing import List, Optional, Set
from app.core.config import settings
from app.detectors.content.text_utils import NormalizedText, normalize_content_text
from app.schemas.analysis import AnalysisRequest, Finding, FindingSeverity


class ContentAnalyzer:
    """Evaluates email subject and body content using explainable heuristics."""

    def __init__(self, config=settings):
        self.config = config.content

    def analyze(self, request: AnalysisRequest) -> List[Finding]:
        findings: List[Finding] = []

        norm_subject = normalize_content_text(request.subject)
        norm_body = normalize_content_text(request.body)

        # 1. Pre-normalization obfuscation check
        self._check_obfuscation(norm_subject, norm_body, findings)

        # 2. Heuristic pattern checks
        self._check_urgency(norm_subject, norm_body, findings)
        self._check_credentials(norm_subject, norm_body, findings)
        self._check_financial_lures(norm_subject, norm_body, findings)
        self._check_authority_impersonation(norm_subject, norm_body, findings)
        self._check_generic_salutation(norm_body, findings)

        return findings

    def _determine_location(self, in_subject: bool, in_body: bool) -> str:
        if in_subject and in_body:
            return "Detected in both subject line and email body"
        if in_subject:
            return "Subject line"
        return "Email body"

    def _check_obfuscation(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = subject.has_zero_width_obfuscation
        in_body = body.has_zero_width_obfuscation

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            total_count = subject.zero_width_count + body.zero_width_count
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_SUSPICIOUS_OBFUSCATION",
                    description=(
                        f"{location}: Contains hidden zero-width or formatting characters "
                        f"({total_count} detected) commonly used to evade text security filters."
                    ),
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_urgency(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = bool(self.config.URGENCY_PATTERN.search(subject.cleaned_text))
        in_body = bool(self.config.URGENCY_PATTERN.search(body.cleaned_text))

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_URGENCY_PRESSURE",
                    description=(
                        f"{location}: Language exerts psychological time pressure or threatens account suspension "
                        "to compel immediate recipient action."
                    ),
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_credentials(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = bool(self.config.CREDENTIAL_PATTERN.search(subject.cleaned_text))
        in_body = bool(self.config.CREDENTIAL_PATTERN.search(body.cleaned_text))

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_CREDENTIAL_SOLICITATION",
                    description=(
                        f"{location}: Contains an actionable request soliciting passwords, PINs, or "
                        "account authentication credentials."
                    ),
                    severity=FindingSeverity.HIGH,
                )
            )

    def _check_financial_lures(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = bool(self.config.FINANCIAL_LURE_PATTERN.search(subject.cleaned_text))
        in_body = bool(self.config.FINANCIAL_LURE_PATTERN.search(body.cleaned_text))

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_FINANCIAL_LURE",
                    description=(
                        f"{location}: Contains lures regarding unexpected financial windfalls, unclaimed prizes, "
                        "or pending refunds."
                    ),
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_authority_impersonation(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = bool(self.config.AUTHORITY_PATTERN.search(subject.cleaned_text))
        in_body = bool(self.config.AUTHORITY_PATTERN.search(body.cleaned_text))

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_AUTHORITY_IMPERSONATION",
                    description=(
                        f"{location}: Employs formal corporate IT support, investigation units, or compliance "
                        "department titles to establish false authority."
                    ),
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_generic_salutation(
        self,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        if not body.cleaned_text:
            return

        # Restrict check to introductory offset window
        intro_sample = body.cleaned_text[: self.config.SALUTATION_MAX_OFFSET]
        if self.config.SALUTATION_PATTERN.search(intro_sample):
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_GENERIC_SALUTATION",
                    description=(
                        "Email body: Uses an impersonal salutation (e.g., 'Dear Customer') rather than addressing "
                        "the recipient by name, typical of mass automated phishing campaigns."
                    ),
                    severity=FindingSeverity.LOW,
                )
            )


content_analyzer = ContentAnalyzer()
````

## File: app/detectors/content/text_utils.py
````python
import html
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import List, Tuple

# Targeted invisible/zero-width formatting codepoints commonly used for filter evasion
ZERO_WIDTH_CHARS = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / BOM
    "\u00ad",  # Soft hyphen
}

# Regex to safely strip closed script/style tags and their internal content in fallback mode
_SCRIPT_STYLE_BLOCK_RE = re.compile(
    r"<(script|style|noscript)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL
)

# Hardened fallback regex: matches an opening <script>, <style>, or <noscript> tag
# whether delimited by '>' or truncated/incomplete at EOF, and conservatively
# suppresses all ambiguous trailing content through EOF without speculative resumption.
_UNCLOSED_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript)\b(?:[^>]*>|[^>]*$).*$", re.IGNORECASE | re.DOTALL
)

_TAG_STRIP_RE = re.compile(r"<[^>]+>")


class SafeHTMLTextExtractor(HTMLParser):
    """Parses HTML document bodies into plain text.
    
    Suppresses content inside <script>, <style>, and <noscript> tags,
    unescapes HTML entities, and separates tag boundaries with whitespace.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._suppress_depth = 0
        self._text_fragments: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() in ("script", "style", "noscript"):
            self._suppress_depth += 1

    def handle_endtag(self, tag: str):
        if tag.lower() in ("script", "style", "noscript"):
            if self._suppress_depth > 0:
                self._suppress_depth -= 1

    def handle_data(self, data: str):
        if self._suppress_depth == 0 and data:
            self._text_fragments.append(data)

    def get_text(self) -> str:
        return " ".join(self._text_fragments)

    @property
    def has_unclosed_suppressed_block(self) -> bool:
        return self._suppress_depth > 0


@dataclass(frozen=True)
class NormalizedText:
    raw_text: str
    cleaned_text: str
    has_zero_width_obfuscation: bool
    zero_width_count: int


def scan_and_strip_zero_width(text: str) -> Tuple[str, bool, int]:
    """Inspects raw text for invisible/zero-width codepoints before removing them.
    
    Returns (cleaned_text, is_suspicious, count).
    """
    if not text:
        return "", False, 0

    count = 0
    clean_chars = []
    has_intra_word_obfuscation = False

    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH_CHARS:
            count += 1
            # Check if placed between alphanumeric word characters (e.g., p\u200Bw\u200Bd)
            if 0 < i < len(text) - 1:
                prev_char = text[i - 1]
                next_char = text[i + 1]
                if prev_char.isalnum() and next_char.isalnum():
                    has_intra_word_obfuscation = True
        else:
            clean_chars.append(ch)

    is_suspicious = count >= 2 or has_intra_word_obfuscation
    return "".join(clean_chars), is_suspicious, count


def _sanitize_html_fallback(html_content: str) -> str:
    """Deterministic fallback sanitizer for severely malformed HTML markup.
    
    1. Strips closed <script>, <style>, and <noscript> blocks with their content.
    2. Conservatively suppresses any unclosed or truncated opening tag and its
       trailing content through EOF.
    3. Strips remaining HTML tag markers.
    4. Unescapes HTML entities.
    """
    # 1. Strip properly closed blocks
    sanitized = _SCRIPT_STYLE_BLOCK_RE.sub(" ", html_content)
    # 2. Suppress unclosed or truncated opening tags and trailing remainder through EOF
    sanitized = _UNCLOSED_SCRIPT_STYLE_RE.sub(" ", sanitized)
    # 3. Strip remaining HTML tags
    sanitized = _TAG_STRIP_RE.sub(" ", sanitized)
    # 4. Unescape entities
    return html.unescape(sanitized)


def strip_html_safely(html_content: str) -> str:
    """Strips HTML markup and unescapes entities safely.
    
    Uses SafeHTMLTextExtractor. If parsing fails on malformed input, it invokes
    _sanitize_html_fallback to ensure script/style content is never leaked.
    """
    if not html_content or "<" not in html_content:
        return html.unescape(html_content) if html_content else ""

    parser = SafeHTMLTextExtractor()
    try:
        parser.feed(html_content)
        parser.close()
        raw_result = parser.get_text()
    except Exception:
        raw_result = _sanitize_html_fallback(html_content)

    # Clean and collapse multi-space gaps caused by adjacent tag transitions
    return re.sub(r"\s+", " ", raw_result).strip()


def normalize_content_text(text: str) -> NormalizedText:
    """Performs end-to-end normalization on an email text field (subject or body).
    
    1. Scans and strips zero-width codepoints.
    2. Strips HTML markup and resolves entities safely.
    3. Normalizes Unicode via NFKD decomposition.
    4. Collapses whitespace.
    """
    if not text:
        return NormalizedText(
            raw_text="",
            cleaned_text="",
            has_zero_width_obfuscation=False,
            zero_width_count=0,
        )

    # 1. Zero-width character scan and purge
    no_zw_text, has_obfuscation, zw_count = scan_and_strip_zero_width(text)

    # 2. HTML stripping and entity unescaping
    plain_text = strip_html_safely(no_zw_text)

    # 3. Unicode NFKD normalization
    normalized_unicode = unicodedata.normalize("NFKD", plain_text)

    # 4. Whitespace cleanup (preserve case in cleaned_text; regex checks can match lower/case-insensitively)
    collapsed_whitespace = re.sub(r"\s+", " ", normalized_unicode).strip()

    return NormalizedText(
        raw_text=text,
        cleaned_text=collapsed_whitespace,
        has_zero_width_obfuscation=has_obfuscation,
        zero_width_count=zw_count,
    )
````

## File: app/detectors/ml/__init__.py
````python

````

## File: app/detectors/ml/analyzer.py
````python
import logging
from math import isfinite
from pathlib import Path
from typing import List, Optional

import joblib
import numpy as np

from app.detectors.url.url_utils import ParsedURLComponents
from app.ml.features import FEATURE_NAMES, extract_lexical_features
from app.schemas.analysis import Finding, FindingSeverity

logger = logging.getLogger(__name__)

DEFAULT_ARTIFACT_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "artifacts" / "url_rf_model.joblib"


class MLURLAnalyzer:
    """Offline-first URL phishing detector using a pre-trained Random Forest model."""

    def __init__(self, artifact_path: Optional[Path] = None):
        self.artifact_path = artifact_path or DEFAULT_ARTIFACT_PATH
        self._is_available = False
        self._status_reason = "uninitialized"
        self._model = None
        self._threshold = 0.5
        self._positive_class_idx = 1

        self._load_and_validate_artifact()

    @property
    def is_available(self) -> bool:
        return self._is_available

    @property
    def status_reason(self) -> str:
        return self._status_reason

    @property
    def threshold(self) -> float:
        return self._threshold

    def _load_and_validate_artifact(self) -> None:
        """Loads and validates the artifact once at initialization without raising uncaught exceptions."""
        if not self.artifact_path.exists():
            self._is_available = False
            self._status_reason = "artifact_not_found"
            logger.info("ML model artifact not found at %s. ML inference disabled.", self.artifact_path)
            return

        try:
            artifact = joblib.load(self.artifact_path)
        except Exception as e:
            self._is_available = False
            self._status_reason = "corrupt_artifact"
            logger.warning("Failed to deserialize ML model artifact: %s", e)
            return

        if not isinstance(artifact, dict):
            self._is_available = False
            self._status_reason = "incompatible_artifact"
            logger.warning("Artifact is not a valid dictionary.")
            return

        # 1. Required keys
        required_keys = {"metadata", "feature_schema", "threshold", "model"}
        if not required_keys.issubset(artifact.keys()):
            self._is_available = False
            self._status_reason = "incompatible_artifact"
            logger.warning("Artifact missing required keys: %s", required_keys - set(artifact.keys()))
            return

        metadata = artifact.get("metadata", {})
        if metadata.get("model_type") != "RandomForestClassifier":
            self._is_available = False
            self._status_reason = "incompatible_artifact"
            logger.warning("Unsupported model type: %s", metadata.get("model_type"))
            return

        # 2. Feature schema and order verification
        schema = artifact.get("feature_schema", {})
        if schema.get("expected_count") != len(FEATURE_NAMES):
            self._is_available = False
            self._status_reason = "incompatible_artifact"
            logger.warning("Feature count mismatch.")
            return

        if schema.get("feature_names") != FEATURE_NAMES:
            self._is_available = False
            self._status_reason = "incompatible_artifact"
            logger.warning("Feature names or feature ordering mismatch.")
            return

        # 3. Threshold bounds
        raw_threshold = artifact.get("threshold")
        if not isinstance(raw_threshold, (int, float)) or not isfinite(raw_threshold):
            self._is_available = False
            self._status_reason = "incompatible_artifact"
            logger.warning("Threshold is non-finite or not a number.")
            return

        if not (0.0 < float(raw_threshold) < 1.0):
            self._is_available = False
            self._status_reason = "incompatible_artifact"
            logger.warning("Threshold %s outside valid interval (0.0, 1.0).", raw_threshold)
            return
        self._threshold = float(raw_threshold)

        # 4. Model estimator checks
        model = artifact.get("model")
        if not hasattr(model, "predict_proba") or not hasattr(model, "classes_"):
            self._is_available = False
            self._status_reason = "incompatible_artifact"
            logger.warning("Model lacks predict_proba or classes_ attributes.")
            return

        try:
            classes_list = list(model.classes_)
            if 1 not in classes_list:
                self._is_available = False
                self._status_reason = "incompatible_artifact"
                logger.warning("Class label 1 (phishing) not found in model.classes_.")
                return
            self._positive_class_idx = classes_list.index(1)
        except Exception as e:
            self._is_available = False
            self._status_reason = "incompatible_artifact"
            logger.warning("Failed to determine positive class index: %s", e)
            return

        self._model = model
        self._is_available = True
        self._status_reason = "active"
        logger.info("ML URL model initialized successfully (threshold: %.4f).", self._threshold)

    def analyze_urls(self, parsed_urls: List[ParsedURLComponents]) -> List[Finding]:
        """Runs offline inference on pre-parsed, unique URLs."""
        if not self._is_available or self._model is None:
            return []

        findings: List[Finding] = []

        for u in parsed_urls:
            feat = extract_lexical_features(u.normalized_url)
            if feat is None:
                continue

            try:
                X = np.array([feat], dtype=np.float64)
                prob = float(self._model.predict_proba(X)[0, self._positive_class_idx])
            except Exception as e:
                logger.warning("Inference failed for URL '%s': %s", u.normalized_url, e)
                continue

            if prob >= self._threshold:
                target_entity = u.registered_domain if u.registered_domain else u.hostname
                findings.append(
                    Finding(
                        analyzer="ml_url",
                        indicator="ML_URL_SUSPICIOUS_LEXICAL_ANOMALY",
                        severity=FindingSeverity.MEDIUM,
                        target=target_entity,
                        description=(
                            f"Machine learning lexical model classified URL '{u.normalized_url}' "
                            f"as suspicious (probability: {prob:.4f}, threshold: {self._threshold:.4f})."
                        ),
                    )
                )

        return findings


ml_url_analyzer = MLURLAnalyzer()
````

## File: app/detectors/sender/__init__.py
````python

````

## File: app/detectors/sender/analyzer.py
````python
from typing import List, Optional
from app.core.config import settings
from app.detectors.sender.domain_utils import (
    ParsedDomain,
    parse_and_normalize_email_domain,
    is_lookalike_of_trusted_domain,
)
from app.schemas.analysis import AnalysisRequest, AuthStatus, Finding, FindingSeverity


class SenderAnalyzer:
    """Evaluates sender identity, domain structures, and authentication records."""

    def __init__(self, config=settings):
        self.config = config

    def analyze(self, request: AnalysisRequest) -> List[Finding]:
        findings: List[Finding] = []

        sender_parsed = parse_and_normalize_email_domain(request.sender_email)
        if not sender_parsed:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="SENDER_SYNTAX_MALFORMED",
                    description="Sender email address could not be safely parsed into a valid domain.",
                    severity=FindingSeverity.HIGH,
                )
            )
            return findings

        # 1. Structural domain rules
        self._check_ip_literal(sender_parsed, findings)
        self._check_punycode(sender_parsed, findings)
        self._check_brand_in_subdomain(sender_parsed, findings)
        self._check_lookalike_domains(sender_parsed, findings)
        self._check_suspicious_labels(sender_parsed, findings)
        self._check_subdomain_depth(sender_parsed, findings)

        # 2. Reply-To relationship
        if request.reply_to:
            self._check_reply_to_mismatch(sender_parsed, request.reply_to, findings)

        # 3. Authentication evaluation (SPF, DKIM, DMARC) with correlation safeguards
        self._evaluate_authentication(request, findings)

        return findings

    def _check_ip_literal(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.is_ip_literal:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="IP_LITERAL_SENDER_DOMAIN",
                    description=f"Sender domain is a raw IP literal ({parsed.registered_domain}) rather than a named host.",
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_punycode(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.has_punycode:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="PUNYCODE_DOMAIN",
                    description=(
                        f"Sender domain uses internationalized (Punycode) encoding ({parsed.normalized_ascii}). "
                        "While standard for non-Latin scripts, it can be abused for visual spoofing."
                    ),
                    severity=FindingSeverity.INFO,
                )
            )

    def _check_brand_in_subdomain(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.is_ip_literal or not parsed.subdomain:
            return

        # Tokenize subdomain labels across both dot and hyphen delimiters
        # to detect hyphen-delimited brand lures without naive substring collisions (e.g., 'snapple')
        subdomain_tokens = set()
        for label in parsed.subdomain.lower().split("."):
            subdomain_tokens.update(label.split("-"))

        for trusted in self.config.TRUSTED_DOMAINS:
            brand_label = trusted.split(".")[0]
            if parsed.registered_domain == trusted:
                continue

            if brand_label in subdomain_tokens or trusted in parsed.subdomain.lower():
                findings.append(
                    Finding(
                        analyzer="sender",
                        indicator="BRAND_NAME_IN_UNRELATED_DOMAIN",
                        description=(
                            f"Trusted brand name '{brand_label}' appears in a subdomain label, "
                            f"but the registered domain is '{parsed.registered_domain}'."
                        ),
                        severity=FindingSeverity.MEDIUM,
                    )
                )
                break

    def _check_lookalike_domains(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.is_ip_literal:
            return

        candidate_label = parsed.domain.lower()

        for trusted in self.config.TRUSTED_DOMAINS:
            trusted_label = trusted.split(".")[0]
            # Skip if exact brand domain or valid subdomain of it
            if parsed.registered_domain == trusted:
                return

            if is_lookalike_of_trusted_domain(candidate_label, trusted_label):
                findings.append(
                    Finding(
                        analyzer="sender",
                        indicator="LOOKALIKE_TRUSTED_DOMAIN",
                        description=(
                            f"Sender domain label '{parsed.domain}' closely resembles trusted brand '{trusted}' "
                            "via character substitution or edit distance."
                        ),
                        severity=FindingSeverity.HIGH,
                    )
                )
                return

    def _check_suspicious_labels(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.is_ip_literal:
            return

        domain_lower = parsed.domain.lower()
        matched_keywords = [
            kw for kw in self.config.SUSPICIOUS_DOMAIN_KEYWORDS if kw in domain_lower and kw != domain_lower
        ]

        if matched_keywords and "-" in domain_lower:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="SUSPICIOUS_DOMAIN_LABEL",
                    description=(
                        f"Sender domain label '{parsed.domain}' contains sensitive action keywords "
                        f"({', '.join(matched_keywords)}) in a hyphenated pattern."
                    ),
                    severity=FindingSeverity.LOW,
                )
            )

    def _check_subdomain_depth(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.subdomain_depth >= self.config.MAX_UNSUSPICIOUS_SUBDOMAIN_DEPTH:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="SUSPICIOUS_SUBDOMAIN_DEPTH",
                    description=(
                        f"Sender domain has an unusually deep subdomain structure ({parsed.subdomain_depth} levels). "
                        "Deep nesting can obscure the actual registered domain."
                    ),
                    severity=FindingSeverity.LOW,
                )
            )

    def _check_reply_to_mismatch(
        self, sender_parsed: ParsedDomain, reply_to_str: str, findings: List[Finding]
    ) -> None:
        reply_parsed = parse_and_normalize_email_domain(reply_to_str)
        if not reply_parsed:
            return

        # Same registered domain (e.g., mail.paypal.com and paypal.com)
        if sender_parsed.registered_domain == reply_parsed.registered_domain:
            return

        # Reply-To belongs to an authorized bulk mailing or CRM service
        if reply_parsed.registered_domain in self.config.WELL_KNOWN_BULK_SENDERS:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="REPLY_TO_BULK_PROVIDER",
                    description=(
                        f"Reply-To domain '{reply_parsed.registered_domain}' differs from sender, "
                        "but matches a recognized bulk mailing or support service provider."
                    ),
                    severity=FindingSeverity.INFO,
                )
            )
            return

        # Unrelated domains
        findings.append(
            Finding(
                analyzer="sender",
                indicator="REPLY_TO_DOMAIN_MISMATCH",
                description=(
                    f"Reply-To address points to an unrelated domain ('{reply_parsed.registered_domain}') "
                    f"instead of the sender domain ('{sender_parsed.registered_domain}')."
                ),
                severity=FindingSeverity.MEDIUM,
            )
        )

    def _evaluate_authentication(self, request: AnalysisRequest, findings: List[Finding]) -> None:
        auth = request.authentication
        dmarc_failed = auth.dmarc == AuthStatus.FAIL

        # DMARC Evaluation
        if dmarc_failed:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="DMARC_POLICY_FAILED",
                    description=(
                        "Email explicitly failed reported DMARC policy validation, indicating failure "
                        "of domain alignment across SPF or DKIM mechanisms."
                    ),
                    severity=FindingSeverity.HIGH,
                )
            )

        # SPF Evaluation
        if auth.spf == AuthStatus.FAIL:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="SPF_AUTHENTICATION_FAILED",
                    description="Sending server is not authorized under the domain's published SPF policy.",
                    severity=FindingSeverity.INFO if dmarc_failed else FindingSeverity.MEDIUM,
                )
            )

        # DKIM Evaluation
        if auth.dkim == AuthStatus.FAIL:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="DKIM_AUTHENTICATION_FAILED",
                    description="Cryptographic DKIM signature failed verification or was absent when required.",
                    severity=FindingSeverity.INFO if dmarc_failed else FindingSeverity.MEDIUM,
                )
            )


sender_analyzer = SenderAnalyzer()
````

## File: app/detectors/sender/domain_utils.py
````python
import ipaddress
from dataclasses import dataclass
from typing import Optional
import idna
import tldextract

# Initialize extractor with local cache/offline PSL snapshot
_extractor = tldextract.TLDExtract(cache_dir=None)

SUBSTITUTION_MAP = {
    "0": "o",
    "1": "l",
    "l": "i",
    "vv": "w",
    "rn": "m",
    "5": "s",
}


@dataclass(frozen=True)
class ParsedDomain:
    raw_domain: str
    normalized_ascii: str
    is_ip_literal: bool
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str
    subdomain_depth: int
    has_punycode: bool


def parse_and_normalize_email_domain(email_str: str) -> Optional[ParsedDomain]:
    """Parses, cleans, and normalizes an email address's domain portion."""
    if not email_str or "@" not in email_str:
        return None

    email_cleaned = email_str.strip()
    parts = email_cleaned.rsplit("@", 1)
    if len(parts) != 2:
        return None

    raw_domain = parts[1].strip()

    # Remove optional trailing DNS root dot
    if raw_domain.endswith("."):
        raw_domain = raw_domain[:-1]

    if not raw_domain:
        return None

    # Check for IP-literal: e.g., [192.0.2.1] or bare IP
    ip_candidate = raw_domain.strip("[]")
    is_ip = False
    try:
        ipaddress.ip_address(ip_candidate)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        return ParsedDomain(
            raw_domain=raw_domain,
            normalized_ascii=ip_candidate.lower(),
            is_ip_literal=True,
            subdomain="",
            domain=ip_candidate,
            suffix="",
            registered_domain=ip_candidate,
            subdomain_depth=0,
            has_punycode=False,
        )

    # Normalize through IDNA (Punycode conversion)
    try:
        normalized_ascii = idna.encode(raw_domain.lower()).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        normalized_ascii = raw_domain.lower()

    has_punycode = "xn--" in normalized_ascii

    ext = _extractor(normalized_ascii)
    subdomain = ext.subdomain
    domain = ext.domain
    suffix = ext.suffix

    if domain and suffix:
        registered_domain = f"{domain}.{suffix}"
    elif "." in normalized_ascii:
        # Fallback for synthetic/testing TLDs like .example or .test not on the public suffix list
        labels = normalized_ascii.split(".")
        registered_domain = ".".join(labels[-2:])
        domain = labels[-2]
        suffix = labels[-1]
        subdomain = ".".join(labels[:-2])
    else:
        registered_domain = normalized_ascii
        domain = normalized_ascii
        suffix = ""
        subdomain = ""

    subdomain_depth = len(subdomain.split(".")) if subdomain else 0

    return ParsedDomain(
        raw_domain=raw_domain,
        normalized_ascii=normalized_ascii,
        is_ip_literal=False,
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        registered_domain=registered_domain,
        subdomain_depth=subdomain_depth,
        has_punycode=has_punycode,
    )


def compute_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes standard edit distance between two strings."""
    if len(s1) < len(s2):
        return compute_levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_leet_substitutions(label: str) -> str:
    """Converts common lookalike leet characters into standard Latin equivalents."""
    res = label.lower()
    for k, v in SUBSTITUTION_MAP.items():
        res = res.replace(k, v)
    return res


def is_lookalike_of_trusted_domain(candidate_label: str, trusted_label: str) -> bool:
    """Evaluates whether a candidate domain label is a deceptive lookalike of a trusted label.
    
    Returns False if exact match or if lengths differ by more than 1 character.
    """
    candidate = candidate_label.lower()
    trusted = trusted_label.lower()

    if candidate == trusted:
        return False

    if abs(len(candidate) - len(trusted)) > 1:
        return False

    if normalize_leet_substitutions(candidate) == trusted:
        return True

    dist = compute_levenshtein_distance(candidate, trusted)
    return dist == 1
````

## File: app/detectors/url/__init__.py
````python

````

## File: app/detectors/url/analyzer.py
````python
import re
from typing import List, Set

from app.core.config import settings
from app.detectors.sender.domain_utils import is_lookalike_of_trusted_domain
from app.detectors.url.url_utils import ParsedURLComponents, extract_urls
from app.schemas.analysis import AnalysisRequest, Finding, FindingSeverity

_DOUBLE_ENCODING_RE = re.compile(r"%25[0-9a-fA-F]{2}")


class URLAnalyzer:
    """Evaluates URLs extracted from email bodies and additional parameters using deterministic heuristics."""

    def __init__(self, config=settings):
        self.config = config.url
        self.trusted_domains = config.TRUSTED_DOMAINS
        # Extract brand names from trusted domains (e.g., 'paypal' from 'paypal.com')
        self.trusted_brands = {d.split(".")[0].lower() for d in self.trusted_domains}

    def analyze(self, request: AnalysisRequest) -> List[Finding]:
        parsed_urls, limit_findings = extract_urls(request.body, request.additional_urls)
        return self.analyze_parsed(parsed_urls, limit_findings)

    def analyze_parsed(
        self, parsed_urls: List[ParsedURLComponents], limit_findings: List[Finding]
    ) -> List[Finding]:
        findings: List[Finding] = list(limit_findings)

        # Track (indicator, target_key) to deduplicate findings across multiple URLs
        seen_indicator_targets: Set[tuple] = set()

        for u in parsed_urls:
            # 1. Userinfo / embedded credentials
            if u.has_userinfo:
                key = ("URL_USERINFO_CREDENTIAL_EMBEDDED", u.hostname)
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_USERINFO_CREDENTIAL_EMBEDDED",
                            description=f"URL '{u.raw_url}' embeds authentication credentials or userinfo syntax ('@') before the hostname to obscure the destination.",
                            severity=FindingSeverity.HIGH,
                        )
                    )

            # 2. IP literal hostnames
            if u.is_ip:
                if u.is_global_ip:
                    key = ("URL_IP_LITERAL_HOST", u.hostname)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_IP_LITERAL_HOST",
                                description=f"URL uses a raw public IP literal host '{u.hostname}' rather than a registered domain name.",
                                severity=FindingSeverity.MEDIUM,
                            )
                        )
                else:
                    key = ("URL_NON_GLOBAL_IP_HOST", u.hostname)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_NON_GLOBAL_IP_HOST",
                                description=f"URL points to a non-global, private, or documentation IP address '{u.hostname}'.",
                                severity=FindingSeverity.INFO,
                            )
                        )

            # Domain-based checks (only if not an IP address)
            if not u.is_ip and u.registered_domain:
                is_legit_brand_domain = u.registered_domain in self.trusted_domains

                # 3. Lookalike domain check (skip if it is an exact legitimate trusted domain)
                if not is_legit_brand_domain:
                    is_lookalike = False
                    for trusted_domain in self.trusted_domains:
                        trusted_label = trusted_domain.split(".")[0]
                        if is_lookalike_of_trusted_domain(u.domain_label, trusted_label):
                            is_lookalike = True
                            break

                    if is_lookalike:
                        key = ("URL_LOOKALIKE_DOMAIN", u.registered_domain)
                        if key not in seen_indicator_targets:
                            seen_indicator_targets.add(key)
                            findings.append(
                                Finding(
                                    analyzer="url",
                                    indicator="URL_LOOKALIKE_DOMAIN",
                                    description=f"URL registered domain '{u.registered_domain}' appears to mimic a trusted brand via typosquatting or character substitution.",
                                    severity=FindingSeverity.HIGH,
                                )
                            )

                # 4. Brand name in unrelated subdomain (only if registered domain is NOT legitimate brand property)
                if not is_legit_brand_domain and u.subdomain:
                    # Tokenize subdomain across dots and hyphens
                    sub_tokens = set(re.split(r"[.-]", u.subdomain))
                    matched_brands = sub_tokens.intersection(self.trusted_brands)
                    if matched_brands:
                        key = ("URL_BRAND_NAME_IN_UNRELATED_DOMAIN", u.hostname)
                        if key not in seen_indicator_targets:
                            seen_indicator_targets.add(key)
                            findings.append(
                                Finding(
                                    analyzer="url",
                                    indicator="URL_BRAND_NAME_IN_UNRELATED_DOMAIN",
                                    description=f"URL hostname '{u.hostname}' places trusted brand name(s) {sorted(matched_brands)} into a subdomain of an unrelated domain '{u.registered_domain}'.",
                                    severity=FindingSeverity.HIGH,
                                )
                            )

                # 5. Punycode check
                if "xn--" in u.hostname:
                    key = ("URL_PUNYCODE_HOST", u.hostname)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_PUNYCODE_HOST",
                                description=f"URL hostname '{u.hostname}' uses Punycode encoding (IDN).",
                                severity=FindingSeverity.INFO,
                            )
                        )

                # 6. Suspicious TLD check (weak signal)
                if u.suffix in self.config.SUSPICIOUS_TLDS:
                    key = ("URL_SUSPICIOUS_TLD", u.suffix)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_SUSPICIOUS_TLD",
                                description=f"URL uses top-level domain '.{u.suffix}', which has a statistically elevated association with abuse infrastructure.",
                                severity=FindingSeverity.LOW,
                            )
                        )

            # 7. Obfuscation: double-percent encoding
            full_raw_path = f"{u.path}?{u.query}" if u.query else u.path
            if _DOUBLE_ENCODING_RE.search(full_raw_path):
                key = ("URL_SUSPICIOUS_OBFUSCATION", u.normalized_url)
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_SUSPICIOUS_OBFUSCATION",
                            description=f"URL '{u.raw_url}' contains double percent-encoding, commonly used to evade pattern security filters.",
                            severity=FindingSeverity.MEDIUM,
                        )
                    )

            # 8. Insecure HTTP on credential-related path
            if u.scheme == "http":
                path_and_query = f"{u.path} {u.query}"
                if self.config.CREDENTIAL_PATH_PATTERN.search(path_and_query):
                    key = ("URL_INSECURE_HTTP_CREDENTIAL_PATH", u.hostname)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_INSECURE_HTTP_CREDENTIAL_PATH",
                                description=f"URL '{u.raw_url}' requests authentication or sensitive operations over plaintext HTTP.",
                                severity=FindingSeverity.LOW,
                            )
                        )

            # 9. Unusual port check
            if u.port is not None and u.port not in self.config.STANDARD_PORTS:
                key = ("URL_UNUSUAL_PORT", f"{u.hostname}:{u.port}")
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_UNUSUAL_PORT",
                            description=f"URL connects to a non-standard web port '{u.port}'.",
                            severity=FindingSeverity.LOW,
                        )
                    )

            # 10. High path depth (weak signal)
            path_segments = [seg for seg in u.path.split("/") if seg]
            if len(path_segments) >= self.config.MAX_PATH_DEPTH:
                key = ("URL_HIGH_PATH_DEPTH", u.hostname)
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_HIGH_PATH_DEPTH",
                            description=f"URL '{u.raw_url}' exhibits excessive path nesting ({len(path_segments)} levels).",
                            severity=FindingSeverity.LOW,
                        )
                    )

            # 11. Embedded redirect parameter check
            if u.query and self.config.REDIRECT_PARAM_PATTERN.search(f"?{u.query}"):
                key = ("URL_REDIRECT_PARAMETER_PRESENT", u.hostname)
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_REDIRECT_PARAMETER_PRESENT",
                            description=f"URL '{u.raw_url}' contains an embedded target URL parameter commonly utilized in open redirection chains.",
                            severity=FindingSeverity.INFO,
                        )
                    )

        return findings


url_analyzer = URLAnalyzer()
````

## File: app/detectors/url/url_utils.py
````python
import html
import ipaddress
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import List, Optional, Set, Tuple
from urllib.parse import urlsplit

from app.core.config import settings
from app.detectors.sender.domain_utils import _extractor
from app.schemas.analysis import Finding, FindingSeverity

# Bounded regex for opening <a> tag href attributes (resilience against unclosed/malformed tags)
_ANCHOR_HREF_RE = re.compile(
    r"""<a\b[^>]*?\bhref\s*=\s*(?P<quote>["'])(https?://[^\s"'<>]+)(?P=quote)""",
    re.IGNORECASE,
)

# Plain text URL regex
_PLAIN_TEXT_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Punctuation commonly attached to plain-text URLs at end of sentences
_TRAILING_PUNCTUATION = ".,;:!?)[]}>\"'"


class SafeHTMLAnchorExtractor(HTMLParser):
    """Parses HTML document bodies to extract HTTP/HTTPS href targets from anchor tags."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() == "a":
            for attr_name, attr_val in attrs:
                if attr_name.lower() == "href" and attr_val:
                    unescaped = html.unescape(attr_val.strip())
                    if unescaped.lower().startswith(("http://", "https://")):
                        self.urls.append(unescaped)


@dataclass(frozen=True)
class ParsedURLComponents:
    raw_url: str
    normalized_url: str
    scheme: str
    netloc: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    subdomain: str
    registered_domain: str
    domain_label: str
    suffix: str
    is_ip: bool
    is_global_ip: bool
    has_userinfo: bool


def validate_and_normalize_url(url: str) -> Tuple[Optional[ParsedURLComponents], bool]:
    """Validates structural authority and port constraints, then applies conservative normalization.
    
    Returns:
        (components, is_malformed)
    """
    try:
        parts = urlsplit(url)
    except (ValueError, AttributeError):
        return None, True

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None, False

    netloc = parts.netloc
    if not netloc:
        return None, True

    # Userinfo presence
    has_userinfo = "@" in netloc

    # Hostname extraction & bracket validation
    try:
        hostname = parts.hostname
    except ValueError:
        return None, True

    if not hostname:
        return None, True

    hostname = hostname.lower()

    # Port extraction and validation
    explicit_port = None
    try:
        explicit_port = parts.port
    except ValueError:
        # Non-numeric or invalid port
        return None, True

    if explicit_port is not None and not (1 <= explicit_port <= 65535):
        return None, True

    # IP address validation
    is_ip = False
    is_global_ip = False
    # Strip brackets for IPv6 address object validation
    host_to_test = hostname[1:-1] if (hostname.startswith("[") and hostname.endswith("]")) else hostname
    try:
        ip_obj = ipaddress.ip_address(host_to_test)
        is_ip = True
        is_global_ip = ip_obj.is_global
    except ValueError:
        is_ip = False

    # Conservative normalization:
    # 1. Strip default ports
    effective_port = explicit_port
    if (scheme == "http" and explicit_port == 80) or (scheme == "https" and explicit_port == 443):
        effective_port = None

    reconstructed_netloc = hostname
    if effective_port is not None:
        reconstructed_netloc = f"{hostname}:{effective_port}"
    if has_userinfo:
        userinfo = netloc.split("@")[0]
        reconstructed_netloc = f"{userinfo}@{reconstructed_netloc}"

    # 2. Strip single trailing slash ONLY on bare root paths
    path = parts.path
    if path == "/" and not parts.query and not parts.fragment:
        path = ""

    normalized_url = f"{scheme}://{reconstructed_netloc}{path}"
    if parts.query:
        normalized_url += f"?{parts.query}"
    if parts.fragment:
        normalized_url += f"#{parts.fragment}"

    # Offline PSL decomposition
    subdomain = ""
    domain_label = ""
    suffix = ""
    registered_domain = ""

    if not is_ip:
        ext = _extractor(hostname)
        subdomain = ext.subdomain.lower()
        domain_label = ext.domain.lower()
        suffix = ext.suffix.lower()
        if domain_label and suffix:
            registered_domain = f"{domain_label}.{suffix}"
        elif domain_label:
            registered_domain = domain_label

    components = ParsedURLComponents(
        raw_url=url,
        normalized_url=normalized_url,
        scheme=scheme,
        netloc=reconstructed_netloc,
        hostname=hostname,
        port=explicit_port,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
        subdomain=subdomain,
        registered_domain=registered_domain,
        domain_label=domain_label,
        suffix=suffix,
        is_ip=is_ip,
        is_global_ip=is_global_ip,
        has_userinfo=has_userinfo,
    )
    return components, False


def extract_urls(
    body: Optional[str],
    additional_urls: Optional[List[str]] = None,
) -> Tuple[List[ParsedURLComponents], List[Finding]]:
    """Extracts, validates, deduplicates, and caps HTTP/HTTPS URLs from email body and additional_urls."""
    raw_candidates: List[str] = []
    limit_findings: List[Finding] = []

    # 1. Explicit additional URLs
    if additional_urls:
        for u in additional_urls:
            if isinstance(u, str) and u.strip().lower().startswith(("http://", "https://")):
                raw_candidates.append(u.strip())

    if body:
        # 2. HTML anchor extraction (Pass A: HTMLParser)
        parser = SafeHTMLAnchorExtractor()
        try:
            parser.feed(body)
            parser.close()
            raw_candidates.extend(parser.urls)
        except Exception:
            pass

        # 3. Tag-level regex extraction (Pass B: guarantees recovery of valid anchors around malformed tags)
        for match in _ANCHOR_HREF_RE.finditer(body):
            raw_candidates.append(html.unescape(match.group(2).strip()))

        # 4. Plain-text regex extraction (Pass C: plain-text URLs in body)
        for match in _PLAIN_TEXT_URL_RE.finditer(body):
            raw_url = match.group(0).rstrip(_TRAILING_PUNCTUATION)
            raw_candidates.append(html.unescape(raw_url))

    # Deduplicate raw candidates preserving discovery order
    seen_raw: Set[str] = set()
    unique_candidates: List[str] = []
    for candidate in raw_candidates:
        if candidate not in seen_raw:
            seen_raw.add(candidate)
            unique_candidates.append(candidate)

    # Validate, normalize, and enforce length boundaries
    parsed_urls: List[ParsedURLComponents] = []
    seen_normalized: Set[str] = set()
    has_malformed = False
    has_excessive_length = False

    for candidate in unique_candidates:
        if len(candidate) > settings.url.MAX_URL_LENGTH:
            has_excessive_length = True
            continue

        components, is_malformed = validate_and_normalize_url(candidate)
        if is_malformed:
            has_malformed = True
            continue

        if components and components.normalized_url not in seen_normalized:
            seen_normalized.add(components.normalized_url)
            parsed_urls.append(components)

    if has_malformed:
        limit_findings.append(
            Finding(
                analyzer="url",
                indicator="URL_SYNTAX_MALFORMED",
                description="One or more URLs in the message contained malformed authorities, unclosed brackets, or invalid ports.",
                severity=FindingSeverity.INFO,
            )
        )

    if has_excessive_length:
        limit_findings.append(
            Finding(
                analyzer="url",
                indicator="URL_EXCESSIVE_LENGTH",
                description=f"One or more URLs exceeded the maximum length bound ({settings.url.MAX_URL_LENGTH} characters) and were omitted.",
                severity=FindingSeverity.LOW,
            )
        )

    # Enforce global evaluation cap
    if len(parsed_urls) > settings.url.MAX_URLS_TO_ANALYZE:
        parsed_urls = parsed_urls[: settings.url.MAX_URLS_TO_ANALYZE]
        limit_findings.append(
            Finding(
                analyzer="url",
                indicator="URL_EVALUATION_CAP_EXCEEDED",
                description=f"Total extracted URLs exceeded the evaluation cap. Analysis was bounded to the first {settings.url.MAX_URLS_TO_ANALYZE} unique URLs.",
                severity=FindingSeverity.INFO,
            )
        )

    return parsed_urls, limit_findings
````

## File: app/main.py
````python
from fastapi import FastAPI
from app.api.v1.endpoints.analysis import router as analysis_router
from app.api.v1.endpoints.health import router as health_router
from app.middleware.request_size import LimitPayloadSizeMiddleware

app = FastAPI(
    title="AI-Based Phishing Detection and Awareness System",
    description="Backend API for email phishing risk assessment and explainable security guidance.",
    version="0.1.0",
)

# Register request size protection middleware (250 KB ceiling)
app.add_middleware(LimitPayloadSizeMiddleware)

# Register API v1 routes
app.include_router(analysis_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """Health check endpoint to verify that the service is running."""
    return {"status": "ok"}
````

## File: app/middleware/__init__.py
````python

````

## File: app/middleware/request_size.py
````python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Maximum permissible payload size: 250 KB
MAX_BODY_BYTES = 250 * 1024


class LimitPayloadSizeMiddleware(BaseHTTPMiddleware):
    """Enforces a strict upper bound on the HTTP request body size.
    
    Protects against memory-exhaustion denial-of-service (DoS) attempts
    by validating Content-Length and actively limiting streamed bytes.
    """

    def __init__(self, app, max_upload_size: int = MAX_BODY_BYTES):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        # Quick check: inspect Content-Length header if provided
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_upload_size:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Payload exceeds maximum allowed limit of {self.max_upload_size} bytes."},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )

        # Stream-level protection for chunked transfers or omitted headers
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            if len(body) > self.max_upload_size:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Payload exceeds maximum allowed limit of {self.max_upload_size} bytes."},
                )

        return await call_next(request)
````

## File: app/ml/__init__.py
````python
"""Shared machine learning utilities and feature extraction pipeline."""
````

## File: app/ml/features.py
````python
import math
from collections import Counter
from typing import List, Optional

from app.detectors.url.url_utils import validate_and_normalize_url

# Ordered schema of the 14 offline lexical URL features
FEATURE_NAMES: List[str] = [
    "length_url",
    "length_host",
    "length_path",
    "count_dots",
    "count_hyphens",
    "count_underscores",
    "count_slashes",
    "count_digits_url",
    "ratio_digits_host",
    "entropy_host",
    "subdomain_depth",
    "has_ip_host",
    "has_at_symbol",
    "is_https",
]


def compute_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy (base 2) for a given string.

    Returns 0.0 for empty or single-character strings. All outputs are finite floats >= 0.0.
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return float(entropy)


def extract_lexical_features(url: str) -> Optional[List[float]]:
    """Extracts a fixed 14-element numerical feature vector from a raw URL string.

    Reuses validate_and_normalize_url for parsing, scheme checks, and offline domain decomposition.

    Returns:
        List[float] matching FEATURE_NAMES ordering if the URL is structurally valid.
        None if the URL is malformed, has an unsupported scheme, or cannot be parsed.
    """
    if not isinstance(url, str) or not url.strip():
        return None

    components, is_malformed = validate_and_normalize_url(url.strip())
    if is_malformed or components is None:
        return None

    norm_url = components.normalized_url
    hostname = components.hostname
    path = components.path

    # Subdomain depth: count dot-separated segments in subdomain; 0 if empty
    subdomain_depth = (
        float(len(components.subdomain.split(".")))
        if components.subdomain
        else 0.0
    )

    # Host digit ratio: safely bounded against empty host
    host_len = len(hostname)
    digits_host = sum(c.isdigit() for c in hostname)
    ratio_digits_host = float(digits_host / host_len) if host_len > 0 else 0.0

    # Shannon entropy of hostname
    entropy_host = compute_shannon_entropy(hostname)

    features: List[float] = [
        float(len(norm_url)),                                   # 1. length_url
        float(host_len),                                        # 2. length_host
        float(len(path)),                                       # 3. length_path
        float(norm_url.count(".")),                             # 4. count_dots
        float(norm_url.count("-")),                             # 5. count_hyphens
        float(norm_url.count("_")),                             # 6. count_underscores
        float(path.count("/")),                                 # 7. count_slashes
        float(sum(c.isdigit() for c in norm_url)),              # 8. count_digits_url
        ratio_digits_host,                                      # 9. ratio_digits_host
        entropy_host,                                           # 10. entropy_host
        subdomain_depth,                                        # 11. subdomain_depth
        1.0 if components.is_ip else 0.0,                       # 12. has_ip_host
        1.0 if components.has_userinfo else 0.0,                 # 13. has_at_symbol
        1.0 if components.scheme == "https" else 0.0,           # 14. is_https
    ]

    return features
````

## File: app/schemas/__init__.py
````python

````

## File: app/schemas/analysis.py
````python
import re
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

# RFC 5322-compliant structural pattern supporting both domain hostnames and bracketed IP literals
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+|\[[a-zA-Z0-9:.]+\])$"
)


class AuthStatus(str, Enum):
    """Represents the evaluation state of email authentication mechanisms.
    
    PASS: Explicitly authenticated (cryptographic signature or SPF match succeeded).
    FAIL: Explicitly failed authentication (hard or soft failure).
    NONE: Record was evaluated, but no policy or signature was published.
    UNKNOWN: Information is unavailable, stripped by upstream relays, or unverifiable.
             Carries zero negative score penalty.
    """
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    UNKNOWN = "unknown"


class RiskCategory(str, Enum):
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    INCONCLUSIVE = "Inconclusive"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    analyzer: str = Field(..., min_length=1, max_length=50, description="Analyzer identifier (e.g., sender, content, url, ml)")
    indicator: str = Field(..., min_length=1, max_length=100, description="Machine-readable indicator code")
    description: str = Field(..., min_length=1, max_length=500, description="Explainable finding for non-technical users")
    severity: FindingSeverity = Field(default=FindingSeverity.INFO, description="Severity rating of this specific indicator")
    target: Optional[str] = Field(default=None, max_length=255, description="Normalized entity target for deduplication and repeat scoring")


class EmailAuthenticationInput(BaseModel):
    spf: AuthStatus = Field(default=AuthStatus.UNKNOWN, description="Reported SPF verification outcome")
    dkim: AuthStatus = Field(default=AuthStatus.UNKNOWN, description="Reported DKIM verification outcome")
    dmarc: AuthStatus = Field(default=AuthStatus.UNKNOWN, description="Reported DMARC verification outcome")


class AnalysisRequest(BaseModel):
    sender_email: str = Field(
        ...,
        min_length=3,
        max_length=320,
        description="Sender email address from header or envelope",
    )
    reply_to: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=320,
        description="Optional Reply-To header address",
    )
    subject: str = Field(
        default="",
        max_length=998,
        description="Email subject line (RFC 5322 line limit)",
    )
    body: str = Field(
        default="",
        max_length=100_000,
        description="Raw email body text (capped at 100,000 characters)",
    )
    additional_urls: List[str] = Field(
        default_factory=list,
        max_length=50,
        description="Optional list of user-provided URLs (maximum 50 items)",
    )
    authentication: EmailAuthenticationInput = Field(
        default_factory=EmailAuthenticationInput,
        description="Optional email authentication outcomes",
    )

    @field_validator("sender_email", "reply_to")
    @classmethod
    def validate_email_syntax(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value_stripped = value.strip()
        if not EMAIL_REGEX.match(value_stripped):
            raise ValueError(f"'{value}' is not a valid email address syntax.")
        return value_stripped

    @field_validator("additional_urls")
    @classmethod
    def validate_url_lengths(cls, urls: List[str]) -> List[str]:
        for url in urls:
            if len(url) > 2048:
                raise ValueError("Individual URL exceeds maximum allowed length of 2048 characters.")
        return urls


class AnalysisResponse(BaseModel):
    risk_score: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Synthesized risk score (0-100). Must be None if risk_category is Inconclusive.",
    )
    risk_category: RiskCategory = Field(..., description="Overall qualitative assessment verdict")
    summary: str = Field(..., min_length=1, max_length=1000, description="High-level narrative of the assessment")
    findings: List[Finding] = Field(default_factory=list, description="Granular evidence collected across analyzers")
    recommendations: List[str] = Field(default_factory=list, description="Actionable security guidance tailored to findings")

    @model_validator(mode="after")
    def verify_score_category_cohesion(self) -> "AnalysisResponse":
        if self.risk_category == RiskCategory.INCONCLUSIVE:
            if self.risk_score is not None:
                raise ValueError("risk_score must be None when risk_category is 'Inconclusive'.")
        else:
            if self.risk_score is None:
                raise ValueError(f"risk_score is required when risk_category is '{self.risk_category.value}'.")
        return self
````

## File: app/services/__init__.py
````python

````

## File: app/services/analysis_service.py
````python
from app.detectors.content.analyzer import content_analyzer
from app.detectors.ml.analyzer import ml_url_analyzer
from app.detectors.sender.analyzer import sender_analyzer
from app.detectors.url.analyzer import url_analyzer
from app.detectors.url.url_utils import extract_urls
from app.schemas.analysis import AnalysisRequest, AnalysisResponse
from app.services.risk_assessor import risk_assessor


class AnalysisService:
    """Orchestrates email analysis components and coordinates centralized risk evaluation."""

    def __init__(
        self,
        sender_engine=sender_analyzer,
        content_engine=content_analyzer,
        url_engine=url_analyzer,
        ml_url_engine=ml_url_analyzer,
        assessor=risk_assessor,
    ):
        self.sender_engine = sender_engine
        self.content_engine = content_engine
        self.url_engine = url_engine
        self.ml_url_engine = ml_url_engine
        self.assessor = assessor

    def analyze_email(self, request: AnalysisRequest) -> AnalysisResponse:
        """Evaluates submitted email data across Sender, Content, URL, and ML modules and scores risk."""
        # 1. Execute sender and content analyzers
        sender_findings = self.sender_engine.analyze(request)
        content_findings = self.content_engine.analyze(request)

        # 2. Shared single-pass URL extraction
        parsed_urls, limit_findings = extract_urls(request.body, request.additional_urls)

        # 3. Deterministic URL heuristic analysis
        url_findings = self.url_engine.analyze_parsed(parsed_urls, limit_findings)

        # 4. Machine learning URL inference (safe fallback if inactive)
        ml_url_findings = self.ml_url_engine.analyze_urls(parsed_urls)

        all_findings = sender_findings + content_findings + url_findings + ml_url_findings

        # 5. Synthesize risk score, category, and narrative
        risk_score, risk_category, summary = self.assessor.evaluate(request, all_findings)

        # 6. Assemble actionable security recommendations
        recommendations = [
            "Verify suspicious emails through known, out-of-band communication channels.",
            "Do not click unverified links or supply credentials on unknown websites.",
        ]

        if any(f.indicator in ("LOOKALIKE_TRUSTED_DOMAIN", "BRAND_NAME_IN_UNRELATED_DOMAIN") for f in sender_findings):
            recommendations.append(
                "Sender domain appears deceptive or mimics a well-known brand. Check the domain spelling carefully."
            )

        if any(f.indicator == "DMARC_POLICY_FAILED" for f in sender_findings):
            recommendations.append(
                "Message failed domain alignment (DMARC). The email may be forged or sent by an unauthorized mail relay."
            )

        if any(f.indicator == "CONTENT_CREDENTIAL_SOLICITATION" for f in content_findings):
            recommendations.append(
                "Never enter passwords, PINs, or security credentials via links received in unverified emails."
            )

        if any(f.indicator == "CONTENT_URGENCY_PRESSURE" for f in content_findings):
            recommendations.append(
                "Be cautious of artificial deadlines or threats of account suspension; independently confirm account status."
            )

        if any(f.indicator == "CONTENT_FINANCIAL_LURE" for f in content_findings):
            recommendations.append(
                "Do not respond to unexpected financial claims, prizes, wire distributions, or refund notifications."
            )

        if any(f.indicator in ("URL_USERINFO_CREDENTIAL_EMBEDDED", "URL_IP_LITERAL_HOST") for f in url_findings):
            recommendations.append(
                "The email contains links directing to raw IP addresses or obscured hostnames. Avoid opening these links."
            )

        if any(f.indicator in ("URL_BRAND_NAME_IN_UNRELATED_DOMAIN", "URL_LOOKALIKE_DOMAIN") for f in url_findings):
            recommendations.append(
                "Links in this message appear to imitate legitimate services using deceptive domain names. Check destination URLs carefully before interacting."
            )

        if any(f.indicator == "URL_INSECURE_HTTP_CREDENTIAL_PATH" for f in url_findings):
            recommendations.append(
                "Links requesting authentication or account access use unencrypted connections (HTTP). Never enter credentials over unencrypted connections."
            )

        if any(f.indicator == "ML_URL_SUSPICIOUS_LEXICAL_ANOMALY" for f in ml_url_findings):
            recommendations.append(
                "One or more links show statistical anomalies common to phishing attacks. Exercise extreme caution."
            )

        return AnalysisResponse(
            risk_score=risk_score,
            risk_category=risk_category,
            summary=summary,
            findings=all_findings,
            recommendations=recommendations,
        )


analysis_service = AnalysisService()
````

## File: app/services/risk_assessor.py
````python
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from app.core.config import settings
from app.schemas.analysis import AnalysisRequest, Finding, FindingSeverity, RiskCategory

_QUOTED_RE = re.compile(r"'([^']+)'")
_PAREN_RE = re.compile(r"\(([^)]+)\)")
_IDENTITY_INDICATORS = {
    "LOOKALIKE_TRUSTED_DOMAIN",
    "BRAND_NAME_IN_UNRELATED_DOMAIN",
    "URL_LOOKALIKE_DOMAIN",
    "URL_BRAND_NAME_IN_UNRELATED_DOMAIN",
}


def extract_normalized_target(finding: Finding) -> str:
    """Deterministically extracts the target entity from a finding description or structured target field."""
    if finding.target:
        return finding.target.strip().lower()

    desc = finding.description

    if finding.analyzer == "sender":
        # Prioritize explicit registered domain label if stated
        m_reg = re.search(r"registered domain is '([^']+)'", desc)
        if m_reg:
            return m_reg.group(1).strip().lower()

        # Otherwise take the last quoted token (representing domain/infrastructure rather than brand)
        all_quotes = _QUOTED_RE.findall(desc)
        if all_quotes:
            return all_quotes[-1].strip().lower()

        # Check for parenthesized target (e.g., IP literal: (192.168.1.1))
        all_parens = _PAREN_RE.findall(desc)
        if all_parens:
            return all_parens[-1].strip().lower()

        return "global_fallback"

    elif finding.analyzer == "url":
        all_quotes = _QUOTED_RE.findall(desc)
        if all_quotes:
            first_quote = all_quotes[0].strip().lower()
            if first_quote.startswith(("http://", "https://")):
                try:
                    parts = urlsplit(first_quote)
                    return parts.netloc.lower() or first_quote
                except Exception:
                    return first_quote
            return first_quote
        return "global_fallback"

    elif finding.analyzer == "content":
        if desc.startswith("Subject line:"):
            return "subject"
        elif desc.startswith("Email body:"):
            return "body"
        elif desc.startswith("Detected in both"):
            return "both"
        return "global_fallback"

    return "global_fallback"


class RiskAssessor:
    """Evaluates findings across all detection engines to compute deterministic risk scores."""

    def __init__(self, config=settings.scoring):
        self.config = config

    def evaluate(
        self, request: AnalysisRequest, findings: List[Finding]
    ) -> Tuple[Optional[int], RiskCategory, str]:
        # 1. Check Inconclusive Gate
        if self._is_inconclusive(request, findings):
            summary = (
                "Insufficient content and telemetry provided to perform a conclusive assessment. "
                "The email body and subject lacked analyzable data."
            )
            return None, RiskCategory.INCONCLUSIVE, summary

        # 2. Exact Deduplication
        deduped_findings: List[Finding] = []
        seen_exact: Set[Tuple[str, str, str]] = set()

        for f in findings:
            target = extract_normalized_target(f)
            exact_key = (f.analyzer, f.indicator, target)
            if exact_key not in seen_exact:
                seen_exact.add(exact_key)
                deduped_findings.append(f)

        if not deduped_findings:
            summary = (
                "Analysis completed with 0 weighted risk indicators detected. "
                "Note: A score of 0 indicates that no known heuristic anomalies were observed, "
                "but it does not prove an email is completely safe. Always verify unexpected communications independently."
            )
            return 0, RiskCategory.LOW_RISK, summary

        # 3. Indicator Grouping & Scoring
        indicator_groups: Dict[str, Dict] = {}
        severity_rank = {
            FindingSeverity.INFO: 0,
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
        }
        severity_weights = {
            FindingSeverity.INFO: self.config.WEIGHT_INFO,
            FindingSeverity.LOW: self.config.WEIGHT_LOW,
            FindingSeverity.MEDIUM: self.config.WEIGHT_MEDIUM,
            FindingSeverity.HIGH: self.config.WEIGHT_HIGH,
        }

        for f in deduped_findings:
            ind = f.indicator
            target = extract_normalized_target(f)

            if ind not in indicator_groups:
                indicator_groups[ind] = {
                    "max_severity": f.severity,
                    "targets": {target},
                }
            else:
                curr_max = indicator_groups[ind]["max_severity"]
                if severity_rank[f.severity] > severity_rank[curr_max]:
                    indicator_groups[ind]["max_severity"] = f.severity
                indicator_groups[ind]["targets"].add(target)

        raw_score = 0
        for ind, data in indicator_groups.items():
            base_wt = severity_weights[data["max_severity"]]
            distinct_count = len(data["targets"])
            repeat_count = max(0, distinct_count - 1)
            repeat_bonus = min(self.config.MAX_REPEAT_BONUS, repeat_count * self.config.REPEAT_STEP)
            raw_score += (base_wt + repeat_bonus)

        # 4. Single-Fire Synergies
        present_indicators = set(indicator_groups.keys())
        fired_synergies: List[str] = []

        # Synergy 1: Identity Spoofing + Credential Solicitation
        if bool(present_indicators.intersection(_IDENTITY_INDICATORS)) and (
            "CONTENT_CREDENTIAL_SOLICITATION" in present_indicators
        ):
            raw_score += self.config.SYNERGY_IDENTITY_CREDENTIAL
            fired_synergies.append("Identity Mimicry & Credential Solicitation")

        # Synergy 2: Urgency Pressure + Financial Lure
        if (
            "CONTENT_URGENCY_PRESSURE" in present_indicators
            and "CONTENT_FINANCIAL_LURE" in present_indicators
        ):
            raw_score += self.config.SYNERGY_URGENCY_FINANCIAL
            fired_synergies.append("Urgency Pressure & Financial Lure")

        # Synergy 3: Insecure Credential Path + Credential Solicitation
        if (
            "URL_INSECURE_HTTP_CREDENTIAL_PATH" in present_indicators
            and "CONTENT_CREDENTIAL_SOLICITATION" in present_indicators
        ):
            raw_score += self.config.SYNERGY_INSECURE_CREDENTIAL
            fired_synergies.append("Unencrypted Insecure Credential Collection")

        # 5. Clamping [0, 100]
        final_score = max(0, min(100, raw_score))

        # 6. Threshold Mapping
        if final_score >= self.config.THRESHOLD_HIGH_RISK:
            category = RiskCategory.HIGH_RISK
        elif final_score >= self.config.THRESHOLD_SUSPICIOUS:
            category = RiskCategory.SUSPICIOUS
        else:
            category = RiskCategory.LOW_RISK

        # 7. Summary Narrative
        if final_score == 0:
            summary = (
                f"Analysis completed with {len(deduped_findings)} informational finding(s) and 0 weighted risk score. "
                "Note: A score of 0 indicates that no known heuristic anomalies were observed, "
                "but it does not prove an email is completely safe. Always verify unexpected communications independently."
            )
        else:
            synergy_text = f" Compound risk modifiers applied: {', '.join(fired_synergies)}." if fired_synergies else ""
            summary = (
                f"Analysis completed with {len(deduped_findings)} indicator(s) resulting in a risk score of {final_score}/100 ({category.value})."
                f"{synergy_text}"
            )

        return final_score, category, summary

    def _is_inconclusive(self, request: AnalysisRequest, findings: List[Finding]) -> bool:
        """Determines if the payload lacks sufficient substance across all analyzers."""
        if len(findings) > 0:
            return False

        has_no_subject = not request.subject or request.subject.strip() == ""
        has_minimal_body = not request.body or len(request.body.strip()) < 10
        has_no_urls = not request.additional_urls or len(request.additional_urls) == 0

        return has_no_subject and has_minimal_body and has_no_urls


risk_assessor = RiskAssessor()
````

## File: backend/docs/model_evaluation.md
````markdown
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
````

## File: data/processed/metadata.json
````json
{
  "source_dataset_id": "UCI_PhiUSIIL_Phishing_URL_Dataset (ID 967)",
  "execution_timestamp": "2026-10-23T11:41:00.710789+00:00",
  "random_seed": 42,
  "max_urls_parameter": 25000,
  "actual_urls_processed": 25000,
  "cleaning_statistics": {
    "raw_records_read": 235795,
    "dropped_missing_values": 0,
    "dropped_malformed_urls": 0,
    "dropped_exact_duplicates": 900,
    "dropped_label_conflicts": 1,
    "retained_clean_records": 234894,
    "total_unique_domain_groups": 175508
  },
  "splits": {
    "train": {
      "url_count": 17487,
      "domain_group_count": 12302,
      "phishing_count": 7412,
      "legitimate_count": 10075,
      "phishing_ratio": 0.4239
    },
    "val": {
      "url_count": 3756,
      "domain_group_count": 3259,
      "phishing_count": 1663,
      "legitimate_count": 2093,
      "phishing_ratio": 0.4428
    },
    "test": {
      "url_count": 3757,
      "domain_group_count": 3235,
      "phishing_count": 1690,
      "legitimate_count": 2067,
      "phishing_ratio": 0.4498
    }
  }
}
````

## File: docs/model_evaluation.md
````markdown
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
````

## File: README.md
````markdown
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
````

## File: requirements-dev.txt
````
-r requirements.txt
pytest>=8.0.0,<9.0.0
httpx>=0.27.0,<1.0.0
````

## File: requirements.txt
````
fastapi>=0.110.0,<1.0.0
uvicorn[standard]>=0.28.0,<1.0.0
pydantic>=2.6.0,<3.0.0
tldextract>=5.1.0,<6.0.0
scikit-learn>=1.4.0,<2.0.0
joblib>=1.3.0,<2.0.0
````

## File: scripts/prepare_dataset.py
````python
import argparse
import csv
import json
import os
import sys
import random
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Ensure backend root is on sys.path for absolute imports
CURRENT_DIR = Path(__file__).resolve().parent
BACKEND_ROOT = CURRENT_DIR.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.detectors.url.url_utils import ParsedURLComponents, validate_and_normalize_url
from app.ml.features import extract_lexical_features

DEFAULT_RAW_PATH = BACKEND_ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
DEFAULT_PROCESSED_DIR = BACKEND_ROOT / "data" / "processed"


def derive_group_key(components: ParsedURLComponents) -> str:
    """Derives a collision-safe grouping key. Never returns empty or generic keys."""
    if components.is_ip:
        clean_ip = components.hostname.strip("[]").lower()
        return f"ip:{clean_ip}"
    if components.registered_domain and components.suffix:
        return f"domain:{components.registered_domain.lower()}"
    if components.hostname:
        return f"host:{components.hostname.lower()}"
    return f"netloc:{components.netloc.lower()}"


class CleanRecord:
    __slots__ = ("raw_url", "normalized_url", "target_label", "group_key")

    def __init__(self, raw_url: str, normalized_url: str, target_label: int, group_key: str):
        self.raw_url = raw_url
        self.normalized_url = normalized_url
        self.target_label = target_label
        self.group_key = group_key


def parse_and_clean_dataset(
    csv_path: Path,
) -> Tuple[List[CleanRecord], Dict[str, int]]:
    """Reads raw CSV, validates columns and label values, normalizes, and drops conflicts."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Source dataset not found at expected path: {csv_path}")

    stats = {
        "raw_records_read": 0,
        "dropped_missing_values": 0,
        "dropped_malformed_urls": 0,
        "dropped_exact_duplicates": 0,
        "dropped_label_conflicts": 0,
    }

    # First pass: read and validate URL syntax + labels
    url_to_labels: Dict[str, Set[int]] = defaultdict(set)
    url_to_components: Dict[str, Tuple[str, ParsedURLComponents]] = {}

    with open(csv_path, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "URL" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("Input CSV must contain both 'URL' and 'label' header columns.")

        for row in reader:
            stats["raw_records_read"] += 1
            raw_url = row.get("URL")
            raw_label = row.get("label")

            if raw_url is None or raw_label is None:
                stats["dropped_missing_values"] += 1
                continue

            raw_url = raw_url.strip()
            raw_label = raw_label.strip()

            if not raw_url or raw_label not in ("0", "1"):
                stats["dropped_missing_values"] += 1
                continue

            # Validate structural validity and extract features
            feat = extract_lexical_features(raw_url)
            if feat is None:
                stats["dropped_malformed_urls"] += 1
                continue

            components, is_malformed = validate_and_normalize_url(raw_url)
            if is_malformed or components is None:
                stats["dropped_malformed_urls"] += 1
                continue

            norm_url = components.normalized_url
            # Map labels: 0 -> 1 (Phishing), 1 -> 0 (Legitimate)
            target = 1 - int(raw_label)

            url_to_labels[norm_url].add(target)
            if norm_url not in url_to_components:
                url_to_components[norm_url] = (raw_url, components)

    # Second pass: detect duplicates, purge label conflicts, build clean records
    clean_records: List[CleanRecord] = []
    for norm_url, labels in url_to_labels.items():
        if len(labels) > 1:
            stats["dropped_label_conflicts"] += 1
            continue

        target = next(iter(labels))
        raw_url, components = url_to_components[norm_url]
        group_key = derive_group_key(components)
        clean_records.append(CleanRecord(raw_url, norm_url, target, group_key))

    # Calculate exact duplicates
    total_valid = stats["raw_records_read"] - stats["dropped_missing_values"] - stats["dropped_malformed_urls"]
    stats["dropped_exact_duplicates"] = max(0, total_valid - len(url_to_labels))

    return clean_records, stats

def allocate_domain_groups(
    records: List[CleanRecord],
    max_urls: Optional[int] = 25000,
    seed: int = 42,
) -> Tuple[List[CleanRecord], List[CleanRecord], List[CleanRecord]]:
    """Deterministically allocates whole domain groups into train, validation, and test partitions."""
    # Group records by domain group key
    groups: Dict[str, List[CleanRecord]] = defaultdict(list)
    for r in records:
        groups[r.group_key].append(r)

    # Sort groups deterministically by key first
    all_group_keys = sorted(groups.keys())

    # Deterministically shuffle group order to ensure diverse domain sampling
    rng = random.Random(seed)
    rng.shuffle(all_group_keys)

    # Subsample domain groups if max_urls is specified
    selected_groups: List[Tuple[str, List[CleanRecord]]] = []
    accumulated_urls = 0

    if max_urls is not None and max_urls > 0:
        for grp_key in all_group_keys:
            grp_records = groups[grp_key]
            selected_groups.append((grp_key, grp_records))
            accumulated_urls += len(grp_records)
            if accumulated_urls >= max_urls:
                break
    else:
        selected_groups = [(k, groups[k]) for k in all_group_keys]

    target_ratios = {"train": 0.70, "val": 0.15, "test": 0.15}
    total_selected = sum(len(grp[1]) for grp in selected_groups)
    target_counts = {part: total_selected * target_ratios[part] for part in target_ratios}

    partition_records: Dict[str, List[CleanRecord]] = {"train": [], "val": [], "test": []}
    partition_phish: Dict[str, int] = {"train": 0, "val": 0, "test": 0}

    # Greedy allocation: assign group to the partition with highest proportional deficit
    for grp_key, grp_recs in selected_groups:
        grp_len = len(grp_recs)
        grp_p = sum(1 for r in grp_recs if r.target_label == 1)

        best_part = None
        highest_deficit = -float("inf")

        for part in ("train", "val", "test"):
            current_len = len(partition_records[part])
            # Deficit ratio: how far below its target count is this partition
            # A higher deficit means the partition needs data most urgently
            deficit = (target_counts[part] - current_len) / max(1.0, target_counts[part])

            # Secondary balance adjustment (slight penalty if class imbalance diverges from 0.50)
            new_len = current_len + grp_len
            new_p = partition_phish[part] + grp_p
            balance_divergence = abs((new_p / max(1, new_len)) - 0.50)

            score = deficit - (balance_divergence * 0.1)

            if score > highest_deficit:
                highest_deficit = score
                best_part = part

        partition_records[best_part].extend(grp_recs)
        partition_phish[best_part] += grp_p

    return partition_records["train"], partition_records["val"], partition_records["test"]


def write_partition_csv(file_path: Path, records: List[CleanRecord]) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "normalized_url", "label", "domain_group"])
        for r in records:
            writer.writerow([r.raw_url, r.normalized_url, r.target_label, r.group_key])


def prepare_dataset_pipeline(
    raw_csv: Path = DEFAULT_RAW_PATH,
    output_dir: Path = DEFAULT_PROCESSED_DIR,
    max_urls: Optional[int] = 25000,
    seed: int = 42,
) -> Dict:
    """Orchestrates dataset parsing, cleaning, group allocation, export, and metadata generation."""
    clean_records, cleaning_stats = parse_and_clean_dataset(raw_csv)
    train_recs, val_recs, test_recs = allocate_domain_groups(clean_records, max_urls=max_urls, seed=seed)

    # Invariant assertion: zero domain group overlap
    train_groups = {r.group_key for r in train_recs}
    val_groups = {r.group_key for r in val_recs}
    test_groups = {r.group_key for r in test_recs}

    assert train_groups.isdisjoint(val_groups), "Domain leakage detected between train and val!"
    assert train_groups.isdisjoint(test_groups), "Domain leakage detected between train and test!"
    assert val_groups.isdisjoint(test_groups), "Domain leakage detected between val and test!"

    output_dir.mkdir(parents=True, exist_ok=True)
    write_partition_csv(output_dir / "train.csv", train_recs)
    write_partition_csv(output_dir / "val.csv", val_recs)
    write_partition_csv(output_dir / "test.csv", test_recs)

    def split_summary(recs: List[CleanRecord], groups: Set[str]) -> Dict:
        phish = sum(1 for r in recs if r.target_label == 1)
        legit = len(recs) - phish
        return {
            "url_count": len(recs),
            "domain_group_count": len(groups),
            "phishing_count": phish,
            "legitimate_count": legit,
            "phishing_ratio": round(phish / max(1, len(recs)), 4),
        }

    metadata = {
        "source_dataset_id": "UCI_PhiUSIIL_Phishing_URL_Dataset (ID 967)",
        "execution_timestamp": datetime.now(timezone.utc).isoformat(),
        "random_seed": seed,
        "max_urls_parameter": max_urls,
        "actual_urls_processed": len(train_recs) + len(val_recs) + len(test_recs),
        "cleaning_statistics": {
            **cleaning_stats,
            "retained_clean_records": len(clean_records),
            "total_unique_domain_groups": len({r.group_key for r in clean_records}),
        },
        "splits": {
            "train": split_summary(train_recs, train_groups),
            "val": split_summary(val_recs, val_groups),
            "test": split_summary(test_recs, test_groups),
        },
    }

    with open(output_dir / "metadata.json", mode="w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


def main():
    parser = argparse.ArgumentParser(description="Prepare and split PhiUSIIL phishing URL dataset.")
    parser.add_argument("--raw-csv", type=Path, default=DEFAULT_RAW_PATH, help="Path to raw PhiUSIIL CSV file")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_PROCESSED_DIR, help="Output directory for processed CSVs")
    parser.add_argument("--max-urls", type=int, default=25000, help="Maximum approximate URLs to include (default: 25000)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic allocation")

    args = parser.parse_args()

    try:
        print(f"[INFO] Preparing dataset from {args.raw_csv} ...")
        meta = prepare_dataset_pipeline(
            raw_csv=args.raw_csv,
            output_dir=args.output_dir,
            max_urls=args.max_urls,
            seed=args.seed,
        )
        print("[SUCCESS] Dataset successfully prepared and split:")
        print(f"  Train: {meta['splits']['train']['url_count']} URLs across {meta['splits']['train']['domain_group_count']} groups")
        print(f"  Val:   {meta['splits']['val']['url_count']} URLs across {meta['splits']['val']['domain_group_count']} groups")
        print(f"  Test:  {meta['splits']['test']['url_count']} URLs across {meta['splits']['test']['domain_group_count']} groups")
        print(f"  Metadata saved to: {args.output_dir / 'metadata.json'}")
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
````

## File: scripts/train_url_model.py
````python
import argparse
import csv
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

# Ensure backend root is on sys.path for absolute imports
CURRENT_DIR = Path(__file__).resolve().parent
BACKEND_ROOT = CURRENT_DIR.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.ml.features import FEATURE_NAMES, extract_lexical_features

DEFAULT_TRAIN_CSV = BACKEND_ROOT / "data" / "processed" / "train.csv"
DEFAULT_VAL_CSV = BACKEND_ROOT / "data" / "processed" / "val.csv"
DEFAULT_ARTIFACT_PATH = BACKEND_ROOT / "app" / "models" / "artifacts" / "url_rf_model.joblib"


def load_and_validate_split(csv_path: Path) -> Tuple[np.ndarray, np.ndarray]:
    """Loads a partition CSV, validates columns and labels, extracts features, and returns (X, y).
    
    Raises:
        FileNotFoundError: If the CSV file does not exist.
        ValueError: If required columns, valid labels, class balance, or features are invalid.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"Partition CSV file not found: {csv_path}")

    X_list: List[List[float]] = []
    y_list: List[int] = []

    with open(csv_path, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "url" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError(f"Input CSV {csv_path} must contain 'url' and 'label' header columns.")

        for row_idx, row in enumerate(reader, start=2):
            raw_url = row.get("url")
            raw_label = row.get("label")

            if raw_url is None or raw_label is None:
                raise ValueError(f"Row {row_idx} in {csv_path} contains missing URL or label.")

            raw_url = raw_url.strip()
            raw_label = raw_label.strip()

            if not raw_url:
                raise ValueError(f"Row {row_idx} in {csv_path} has empty URL.")

            if raw_label not in ("0", "1"):
                raise ValueError(f"Row {row_idx} in {csv_path} has invalid label '{raw_label}'. Must be '0' or '1'.")

            feat = extract_lexical_features(raw_url)
            if feat is None:
                raise ValueError(f"Row {row_idx} in {csv_path} URL '{raw_url}' could not be parsed for features.")

            if len(feat) != len(FEATURE_NAMES):
                raise ValueError(
                    f"Row {row_idx} in {csv_path} produced {len(feat)} features, expected {len(FEATURE_NAMES)}."
                )

            if not all(isinstance(v, (int, float)) and np.isfinite(v) for v in feat):
                raise ValueError(f"Row {row_idx} in {csv_path} produced non-finite feature values.")

            X_list.append(feat)
            y_list.append(int(raw_label))

    if not y_list:
        raise ValueError(f"Partition CSV {csv_path} contains zero records.")

    y = np.array(y_list, dtype=np.int32)
    unique_classes = set(y.tolist())
    if unique_classes != {0, 1}:
        raise ValueError(
            f"Partition CSV {csv_path} must contain both classes {0, 1}, but found: {unique_classes}."
        )

    X = np.array(X_list, dtype=np.float64)
    return X, y


def select_validation_threshold(
    y_val: np.ndarray,
    y_prob: np.ndarray,
    target_fpr: float = 0.015,
) -> Tuple[float, Dict[str, float]]:
    """Selects the lowest probability threshold meeting FPR <= target_fpr with non-zero recall.

    Considers boundary classifications and distinct prediction probability cutoffs.
    
    Raises:
        RuntimeError: If no candidate threshold achieves FPR <= target_fpr with recall > 0.
    """
    negatives_mask = (y_val == 0)
    positives_mask = (y_val == 1)
    total_negatives = int(np.sum(negatives_mask))
    total_positives = int(np.sum(positives_mask))

    if total_negatives == 0:
        raise ValueError("Validation set contains zero negative (legitimate) samples.")
    if total_positives == 0:
        raise ValueError("Validation set contains zero positive (phishing) samples.")

    # Unique probability thresholds + midpoints
    unique_probs = np.unique(y_prob)
    midpoints = (unique_probs[:-1] + unique_probs[1:]) / 2.0 if len(unique_probs) > 1 else np.array([])
    candidate_thresholds = np.unique(
        np.clip(
            np.concatenate(([0.0], unique_probs, midpoints)),
            0.0,
            1.0,
        )
    )
    candidate_thresholds.sort()

    valid_candidates: List[Tuple[float, float, float, float, float]] = []
    min_observed_fpr = float("inf")
    best_at_min_fpr = (1.0, 1.0)

    for T in candidate_thresholds:
        y_pred = (y_prob >= T).astype(int)
        
        # Guard: A threshold that predicts 0 positives across the entire set has 0 recall
        # and is operationally inert
        tp = int(np.sum((y_pred == 1) & positives_mask))
        if tp == 0:
            continue

        fp = int(np.sum((y_pred == 1) & negatives_mask))
        fpr = float(fp / total_negatives)

        if fpr < min_observed_fpr:
            min_observed_fpr = fpr
            best_at_min_fpr = (T, fpr)

        if fpr <= target_fpr:
            prec = float(precision_score(y_val, y_pred, zero_division=0))
            rec = float(recall_score(y_val, y_pred, zero_division=0))
            f1 = float(f1_score(y_val, y_pred, zero_division=0))
            valid_candidates.append((float(T), fpr, prec, rec, f1))

    if not valid_candidates:
        best_t, best_fpr = best_at_min_fpr
        raise RuntimeError(
            f"Model failed to achieve target FPR <= {target_fpr * 100:.2f}% on validation data. "
            f"Minimum achievable FPR was {best_fpr * 100:.2f}% at threshold T = {best_t:.4f}. "
            f"Artifact export aborted."
        )

    # Deterministic tie-breaking: select lowest threshold in valid candidates (maximizing sensitivity)
    valid_candidates.sort(key=lambda item: item[0])
    selected_t, fpr, prec, rec, f1 = valid_candidates[0]

    metrics = {
        "threshold": selected_t,
        "fpr": fpr,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
    }
    return selected_t, metrics


def train_and_export_pipeline(
    train_csv: Path = DEFAULT_TRAIN_CSV,
    val_csv: Path = DEFAULT_VAL_CSV,
    artifact_path: Path = DEFAULT_ARTIFACT_PATH,
    random_seed: int = 42,
    target_fpr: float = 0.015,
) -> Dict:
    """Trains Random Forest, tunes threshold, and exports serialized artifact atomically."""
    print(f"[INFO] Loading and validating training split: {train_csv}")
    X_train, y_train = load_and_validate_split(train_csv)

    print(f"[INFO] Loading and validating validation split: {val_csv}")
    X_val, y_val = load_and_validate_split(val_csv)

    print(f"[INFO] Fitting RandomForestClassifier (n_estimators=100, max_depth=12, seed={random_seed}) ...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=random_seed,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)

    print("[INFO] Computing validation probabilities and selecting threshold ...")
    val_probs = rf.predict_proba(X_val)[:, 1]
    selected_threshold, val_metrics = select_validation_threshold(y_val, val_probs, target_fpr=target_fpr)

    val_preds = (val_probs >= selected_threshold).astype(int)
    cm = confusion_matrix(y_val, val_preds).tolist()

    artifact = {
        "metadata": {
            "model_version": "1.0.0",
            "model_type": "RandomForestClassifier",
            "scikit_learn_version": sklearn.__version__,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "target_mapping": {"0": "legitimate", "1": "phishing"},
            "random_seed": random_seed,
            "train_sample_count": int(len(X_train)),
            "val_sample_count": int(len(X_val)),
            "validation_metrics": {
                **val_metrics,
                "confusion_matrix": {
                    "tn": cm[0][0],
                    "fp": cm[0][1],
                    "fn": cm[1][0],
                    "tp": cm[1][1],
                },
            },
        },
        "feature_schema": {
            "expected_count": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
        },
        "threshold": selected_threshold,
        "model": rf,
    }

    # Atomic artifact export using temporary sibling file and os.replace
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_path_str = tempfile.mkstemp(
        prefix="url_rf_model_",
        suffix=".tmp",
        dir=str(artifact_path.parent),
    )
    os.close(temp_fd)
    temp_path = Path(temp_path_str)

    try:
        joblib.dump(artifact, temp_path)
        os.replace(temp_path, artifact_path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise

    return artifact["metadata"]


def main():
    parser = argparse.ArgumentParser(description="Train offline Random Forest URL phishing classifier.")
    parser.add_argument("--train-csv", type=Path, default=DEFAULT_TRAIN_CSV, help="Path to train.csv")
    parser.add_argument("--val-csv", type=Path, default=DEFAULT_VAL_CSV, help="Path to val.csv")
    parser.add_argument("--artifact-path", type=Path, default=DEFAULT_ARTIFACT_PATH, help="Path to output .joblib")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for estimator")
    parser.add_argument("--target-fpr", type=float, default=0.015, help="Maximum validation FPR target (default: 0.015)")

    args = parser.parse_args()

    try:
        meta = train_and_export_pipeline(
            train_csv=args.train_csv,
            val_csv=args.val_csv,
            artifact_path=args.artifact_path,
            random_seed=args.seed,
            target_fpr=args.target_fpr,
        )
        print("[SUCCESS] Model trained and exported successfully:")
        print(f"  Artifact Path:     {args.artifact_path}")
        print(f"  Selected Threshold:{meta['validation_metrics']['threshold']:.4f}")
        print(f"  Validation FPR:    {meta['validation_metrics']['fpr'] * 100:.2f}%")
        print(f"  Validation Prec:   {meta['validation_metrics']['precision'] * 100:.2f}%")
        print(f"  Validation Recall: {meta['validation_metrics']['recall'] * 100:.2f}%")
        print(f"  Validation F1:     {meta['validation_metrics']['f1_score'] * 100:.2f}%")
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
````

## File: tests/__init__.py
````python

````

## File: tests/test_analysis_contract.py
````python
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.analysis import RiskCategory

client = TestClient(app)


def test_analysis_endpoint_success_with_findings():
    payload = {
        "sender_email": "security@paypa1.com",
        "subject": "Urgent: Account Verification",
        "body": "Dear customer, please verify your credentials within 24 hours: https://paypal.com.attacker.com/login",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] is not None
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_category"] in (RiskCategory.SUSPICIOUS.value, RiskCategory.HIGH_RISK.value)
    assert len(data["findings"]) > 0
    assert len(data["recommendations"]) > 0


def test_analysis_endpoint_inconclusive_on_empty_content():
    payload = {
        "sender_email": "user@example.com",
        "subject": "",
        "body": "hi",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] is None
    assert data["risk_category"] == RiskCategory.INCONCLUSIVE.value
    assert "Insufficient content" in data["summary"]


def test_analysis_endpoint_invalid_email_syntax():
    payload = {
        "sender_email": "not-an-email",
        "subject": "Hello",
        "body": "Test body",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 422


def test_analysis_endpoint_clean_email_scores_low_risk():
    payload = {
        "sender_email": "colleague@company.com",
        "subject": "Sprint Review Notes",
        "body": "Hi team, please find attached our sprint review agenda for tomorrow morning.",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] == 0
    assert data["risk_category"] == RiskCategory.LOW_RISK.value
    assert "does not prove an email is completely safe" in data["summary"]


def test_analysis_endpoint_payload_too_large_413():
    huge_body = "x" * (255 * 1024)
    payload = {
        "sender_email": "user@example.com",
        "subject": "Huge Email",
        "body": huge_body,
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 413
````

## File: tests/test_health.py
````python
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_check_returns_200_and_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
````

## File: tests/test_ml_health.py
````python
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ml_health_endpoint_contract():
    response = client.get("/api/v1/health/ml")
    assert response.status_code == 200
    data = response.json()
    assert "available" in data
    assert isinstance(data["available"], bool)
    assert "status" in data
    assert isinstance(data["status"], str)
    if data["available"]:
        assert data["threshold"] is not None
        assert 0.0 < data["threshold"] < 1.0


def test_system_health_remains_unchanged():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
````

## File: tests/unit/__init__.py
````python

````

## File: tests/unit/test_content_analyzer.py
````python
from app.detectors.content.analyzer import content_analyzer
from app.schemas.analysis import AnalysisRequest, FindingSeverity


def test_clean_corporate_email_emits_no_findings():
    req = AnalysisRequest(
        sender_email="colleague@company.com",
        subject="Project Standup Notes",
        body="Hi Team, please find attached the meeting notes from today's discussion. See you tomorrow at 10 AM.",
    )
    findings = content_analyzer.analyze(req)
    assert len(findings) == 0


def test_urgency_pressure_detected():
    req = AnalysisRequest(
        sender_email="notice@alerts-domain.com",
        subject="Urgent Action Required",
        body="Your account will be suspended within 24 hours if action is not taken.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_URGENCY_PRESSURE" in indicators
    finding = next(f for f in findings if f.indicator == "CONTENT_URGENCY_PRESSURE")
    assert finding.severity == FindingSeverity.MEDIUM
    assert "Email body" in finding.description


def test_credential_solicitation_detected():
    req = AnalysisRequest(
        sender_email="security@portal-auth.com",
        subject="Security Notification",
        body="Please confirm your password to restore immediate access.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_CREDENTIAL_SOLICITATION" in indicators
    finding = next(f for f in findings if f.indicator == "CONTENT_CREDENTIAL_SOLICITATION")
    assert finding.severity == FindingSeverity.HIGH


def test_financial_lures_tax_refund_pending_and_pending_tax_refund():
    # Case A: 'tax refund pending'
    req_a = AnalysisRequest(
        sender_email="irs-notice@irs-rebate.com",
        subject="Tax notification",
        body="You have a tax refund pending from your previous filing.",
    )
    findings_a = content_analyzer.analyze(req_a)
    assert "CONTENT_FINANCIAL_LURE" in [f.indicator for f in findings_a]

    # Case B: 'pending tax refund'
    req_b = AnalysisRequest(
        sender_email="irs-notice@irs-rebate.com",
        subject="Tax notification",
        body="You have a pending tax refund waiting for wire disbursement.",
    )
    findings_b = content_analyzer.analyze(req_b)
    assert "CONTENT_FINANCIAL_LURE" in [f.indicator for f in findings_b]


def test_authority_impersonation_detected():
    req = AnalysisRequest(
        sender_email="dispatch@internal-desk.com",
        subject="Ticket Update",
        body="This is an urgent ticket escalation from the IT Support Desk.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_AUTHORITY_IMPERSONATION" in indicators
    finding = next(f for f in findings if f.indicator == "CONTENT_AUTHORITY_IMPERSONATION")
    assert finding.severity == FindingSeverity.MEDIUM


def test_generic_salutation_detected():
    req = AnalysisRequest(
        sender_email="newsletter@generic-promo.com",
        subject="Important Service Notice",
        body="Dear Customer, we are making routine modifications to our terms.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_GENERIC_SALUTATION" in indicators
    finding = next(f for f in findings if f.indicator == "CONTENT_GENERIC_SALUTATION")
    assert finding.severity == FindingSeverity.LOW


def test_suspicious_obfuscation_detected():
    req = AnalysisRequest(
        sender_email="alert@deceptive-inbox.com",
        subject="Account notice",
        body="Please r\u200bes\u200bet your password immediately.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_SUSPICIOUS_OBFUSCATION" in indicators
    assert "CONTENT_CREDENTIAL_SOLICITATION" in indicators


def test_location_attribution_both_subject_and_body():
    req = AnalysisRequest(
        sender_email="service@warning.com",
        subject="Final notice: immediate action",
        body="Your account will be suspended within 24 hours.",
    )
    findings = content_analyzer.analyze(req)
    finding = next(f for f in findings if f.indicator == "CONTENT_URGENCY_PRESSURE")
    assert "Detected in both subject line and email body" in finding.description


def test_false_positive_safeguards_pin_shipping_shopping():
    req = AnalysisRequest(
        sender_email="orders@ecommerce-hub.com",
        subject="Order Confirmation",
        body="Your tracking PIN is 1234. Your shopping cart has shipped via ground shipping.",
    )
    findings = content_analyzer.analyze(req)
    assert len(findings) == 0


def test_false_positive_safeguards_pinpoint():
    req = AnalysisRequest(
        sender_email="lead@devteam.com",
        subject="Post-Mortem Review",
        body="Let's pinpoint the exact root cause in tomorrow's standup meeting.",
    )
    findings = content_analyzer.analyze(req)
    assert len(findings) == 0


def test_false_positive_safeguards_legitimate_billing_invoice():
    req = AnalysisRequest(
        sender_email="billing@cloudprovider.com",
        subject="Monthly Cloud Billing Statement",
        body="Please find attached the monthly invoice for your standard cloud usage.",
    )
    findings = content_analyzer.analyze(req)
    assert len(findings) == 0
````

## File: tests/unit/test_content_text_utils.py
````python
from app.detectors.content.text_utils import (
    _sanitize_html_fallback,
    normalize_content_text,
    scan_and_strip_zero_width,
    strip_html_safely,
)


def test_plain_text_normalization():
    raw = "   Please   verify    your   account immediately.   "
    res = normalize_content_text(raw)
    assert res.cleaned_text == "Please verify your account immediately."
    assert not res.has_zero_width_obfuscation
    assert res.zero_width_count == 0


def test_html_stripping_and_entities():
    html_input = "<p>Hello &amp; welcome! Click <a href='https://test.com'>here</a> &quot;now&quot;.</p>"
    text = strip_html_safely(html_input)
    assert "Hello & welcome!" in text
    assert 'here "now".' in text
    assert "<p>" not in text
    assert "<a" not in text


def test_html_script_and_style_exclusion():
    html_input = (
        "<html><head>"
        "<style>body { color: red; } .password { display: none; }</style>"
        "<script>var secret_token = '12345'; alert('verify password');</script>"
        "</head><body><p>Legitimate account notice.</p></body></html>"
    )
    res = normalize_content_text(html_input)
    assert "Legitimate account notice." in res.cleaned_text
    assert "color: red" not in res.cleaned_text
    assert "secret_token" not in res.cleaned_text
    assert "alert('verify password')" not in res.cleaned_text


def test_malformed_html_handling():
    # Broken/unclosed tags and truncated markers must not expose script body or crash
    malformed_input = (
        "<div><b>Important notice:</b> <script>malicious_code();</script>"
        "<p unclosed attribute='test>Your invoice is ready. <a href='broken"
    )
    res = normalize_content_text(malformed_input)
    assert "Important notice:" in res.cleaned_text
    assert "Your invoice is ready." in res.cleaned_text
    assert "malicious_code" not in res.cleaned_text


def test_zero_width_intra_word_obfuscation():
    # Intra-word insertion with 2 zero-width spaces: p\u200Bw\u200Bd
    raw = "Please reset your p\u200Bw\u200Bd now."
    cleaned, is_suspicious, count = scan_and_strip_zero_width(raw)
    assert cleaned == "Please reset your pwd now."
    assert is_suspicious is True
    assert count == 2

    res = normalize_content_text(raw)
    assert res.cleaned_text == "Please reset your pwd now."
    assert res.has_zero_width_obfuscation is True
    assert res.zero_width_count == 2


def test_zero_width_multiple_occurrences():
    # Multiple invisible codepoints
    raw = "Urgent\u200C notice\u200D regarding account."
    cleaned, is_suspicious, count = scan_and_strip_zero_width(raw)
    assert cleaned == "Urgent notice regarding account."
    assert is_suspicious is True
    assert count == 2


def test_unicode_nfkd_decomposition():
    # Ligature 'ﬁ' -> 'fi', full-width characters 'Ｐａｓｓ' -> 'Pass'
    raw = "Please conﬁrm your Ｐａｓｓword."
    res = normalize_content_text(raw)
    assert "confirm your Password." in res.cleaned_text


def test_normally_closed_script_and_style_tags_suppress_only_content():
    # Public path: parser cleanly suppresses script/style blocks and retains surrounding text
    raw = (
        "<p>Pre-script text.</p>"
        "<script type='text/javascript'>console.log('internal code');</script>"
        "<style>body { background: #000; }</style>"
        "<p>Post-script text.</p>"
    )
    res = normalize_content_text(raw)
    assert "Pre-script text." in res.cleaned_text
    assert "Post-script text." in res.cleaned_text
    assert "console.log" not in res.cleaned_text
    assert "background: #000" not in res.cleaned_text


def test_unclosed_script_tag_safely_suppresses_ambiguous_remainder():
    # Public path: parser reaches EOF with unclosed script tag; ambiguous remainder is suppressed
    raw = "<p>Legitimate header.</p><script>var code = 1;\nPlease verify your password immediately."
    res = normalize_content_text(raw)
    assert "Legitimate header." in res.cleaned_text
    assert "code = 1" not in res.cleaned_text
    assert "Please verify your password immediately." not in res.cleaned_text


def test_fallback_sanitizer_closed_script_and_style_tags():
    # Deterministic test: fallback helper removes closed script/style blocks cleanly
    raw = (
        "<div>Pre-fallback text.</div>"
        "<script>bad_script();</script>"
        "<style>.hide { display: none; }</style>"
        "<div>Post-fallback text.</div>"
    )
    cleaned = _sanitize_html_fallback(raw)
    assert "Pre-fallback text." in cleaned
    assert "Post-fallback text." in cleaned
    assert "bad_script" not in cleaned
    assert "display: none" not in cleaned


def test_fallback_sanitizer_unclosed_script_suppresses_trailing_remainder():
    # Deterministic test: fallback helper suppresses opening tag and all subsequent text through EOF
    raw = (
        "<div>Header notice.</div>"
        "<script type='text/javascript'>var exploit = 'active';"
        "<div>Apparent trailing visible text.</div>"
    )
    cleaned = _sanitize_html_fallback(raw)
    assert "Header notice." in cleaned
    assert "exploit" not in cleaned
    assert "Apparent trailing visible text." not in cleaned


def test_fallback_sanitizer_incomplete_opening_tag_at_eof():
    # Deterministic test: tag truncated at EOF without closing '>' delimiter
    raw = "<div>Visible text.</div><script type='text/javascript' unclosed"
    cleaned = _sanitize_html_fallback(raw)
    assert "Visible text." in cleaned
    assert "script" not in cleaned
    assert "unclosed" not in cleaned


def test_fallback_sanitizer_does_not_suppress_ordinary_words():
    # Ensures words like 'scripture' or 'styleguide' are not erroneously stripped
    raw = "<p>Reading scripture in the styleguide.</p>"
    cleaned = _sanitize_html_fallback(raw)
    assert "Reading scripture in the styleguide." in cleaned
````

## File: tests/unit/test_ml_analyzer.py
````python
from pathlib import Path
import joblib
import numpy as np
import pytest

from app.detectors.ml.analyzer import MLURLAnalyzer
from app.detectors.url.url_utils import validate_and_normalize_url
from app.ml.features import FEATURE_NAMES
from app.schemas.analysis import AnalysisRequest, Finding, FindingSeverity
from app.services.risk_assessor import RiskAssessor, extract_normalized_target


class DummyEstimator:
    """Picklable estimator for testing MLURLAnalyzer without needing full scikit-learn models."""

    def __init__(self, classes, predict_probs):
        self.classes_ = np.array(classes)
        self._predict_probs = np.array(predict_probs)

    def predict_proba(self, X):
        return self._predict_probs


def _create_mock_artifact(
    path: Path,
    classes=(0, 1),
    predict_probs=((0.1, 0.9),),
    threshold=0.70,
    model_type="RandomForestClassifier",
    feature_names=None,
    omit_key=None,
):
    model = DummyEstimator(classes=classes, predict_probs=predict_probs)

    artifact = {
        "metadata": {
            "model_type": model_type,
            "version": "1.0.0",
        },
        "feature_schema": {
            "expected_count": 14,
            "feature_names": feature_names or FEATURE_NAMES,
        },
        "threshold": threshold,
        "model": model,
    }
    if omit_key:
        artifact.pop(omit_key, None)

    joblib.dump(artifact, path)
    return model


def test_ml_analyzer_missing_artifact_graceful_fallback(tmp_path: Path):
    non_existent = tmp_path / "missing.joblib"
    analyzer = MLURLAnalyzer(artifact_path=non_existent)
    assert analyzer.is_available is False
    assert analyzer.status_reason == "artifact_not_found"
    assert analyzer.analyze_urls([]) == []


def test_ml_analyzer_corrupted_artifact(tmp_path: Path):
    corrupt_file = tmp_path / "corrupt.joblib"
    corrupt_file.write_bytes(b"NOT_A_VALID_JOBLIB_DATA_STREAM")
    analyzer = MLURLAnalyzer(artifact_path=corrupt_file)
    assert analyzer.is_available is False
    assert analyzer.status_reason == "corrupt_artifact"
    assert analyzer.analyze_urls([]) == []


def test_ml_analyzer_incompatible_artifact_missing_keys(tmp_path: Path):
    artifact_path = tmp_path / "bad_schema.joblib"
    _create_mock_artifact(artifact_path, omit_key="feature_schema")
    analyzer = MLURLAnalyzer(artifact_path=artifact_path)
    assert analyzer.is_available is False
    assert analyzer.status_reason == "incompatible_artifact"


def test_ml_analyzer_incompatible_feature_names_order(tmp_path: Path):
    artifact_path = tmp_path / "inverted_features.joblib"
    inverted = list(reversed(FEATURE_NAMES))
    _create_mock_artifact(artifact_path, feature_names=inverted)
    analyzer = MLURLAnalyzer(artifact_path=artifact_path)
    assert analyzer.is_available is False
    assert analyzer.status_reason == "incompatible_artifact"


def test_ml_analyzer_incompatible_threshold_bounds(tmp_path: Path):
    artifact_path = tmp_path / "bad_thresh.joblib"
    _create_mock_artifact(artifact_path, threshold=1.5)
    analyzer = MLURLAnalyzer(artifact_path=artifact_path)
    assert analyzer.is_available is False
    assert analyzer.status_reason == "incompatible_artifact"


def test_ml_analyzer_correct_phishing_class_index_and_threshold_behavior(tmp_path: Path):
    artifact_path = tmp_path / "valid.joblib"
    # Inverted classes: class 1 is at index 0, class 0 is at index 1
    # predict_proba returns [0.85, 0.15] -> probability of phishing (class 1) is 0.85
    _create_mock_artifact(
        artifact_path,
        classes=(1, 0),
        predict_probs=((0.85, 0.15),),
        threshold=0.80,
    )
    analyzer = MLURLAnalyzer(artifact_path=artifact_path)
    assert analyzer.is_available is True
    assert analyzer.status_reason == "active"

    comp, _ = validate_and_normalize_url("https://suspicious-login.com/auth")
    findings = analyzer.analyze_urls([comp])

    assert len(findings) == 1
    f = findings[0]
    assert f.analyzer == "ml_url"
    assert f.indicator == "ML_URL_SUSPICIOUS_LEXICAL_ANOMALY"
    assert f.severity == FindingSeverity.MEDIUM
    assert f.target == "suspicious-login.com"
    assert "0.8500" in f.description


def test_ml_analyzer_below_threshold_emits_no_finding(tmp_path: Path):
    artifact_path = tmp_path / "valid.joblib"
    # Probability of class 1 is 0.7999, threshold is 0.80 -> emit zero findings
    _create_mock_artifact(
        artifact_path,
        classes=(0, 1),
        predict_probs=((0.2001, 0.7999),),
        threshold=0.80,
    )
    analyzer = MLURLAnalyzer(artifact_path=artifact_path)
    comp, _ = validate_and_normalize_url("https://benign-site.com/home")
    findings = analyzer.analyze_urls([comp])
    assert len(findings) == 0


def test_structured_target_normalization_and_repeat_bonus_capping():
    assessor = RiskAssessor()

    f1 = Finding(
        analyzer="ml_url",
        indicator="ML_URL_SUSPICIOUS_LEXICAL_ANOMALY",
        description="ML finding for domain A",
        severity=FindingSeverity.MEDIUM,
        target="domain-a.com",
    )
    assert extract_normalized_target(f1) == "domain-a.com"

    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Alert",
        body="Check https://domain-a.com/login",
    )
    score_1, cat_1, _ = assessor.evaluate(req, [f1])
    assert score_1 == 18
    assert cat_1.value == "Low Risk"

    f1_dup = Finding(
        analyzer="ml_url",
        indicator="ML_URL_SUSPICIOUS_LEXICAL_ANOMALY",
        description="Second ML finding for domain A",
        severity=FindingSeverity.MEDIUM,
        target="domain-a.com",
    )
    score_same, _, _ = assessor.evaluate(req, [f1, f1_dup])
    assert score_same == 18

    f2 = Finding(
        analyzer="ml_url",
        indicator="ML_URL_SUSPICIOUS_LEXICAL_ANOMALY",
        description="ML finding for domain B",
        severity=FindingSeverity.MEDIUM,
        target="domain-b.com",
    )
    f3 = Finding(
        analyzer="ml_url",
        indicator="ML_URL_SUSPICIOUS_LEXICAL_ANOMALY",
        description="ML finding for domain C",
        severity=FindingSeverity.MEDIUM,
        target="domain-c.com",
    )
    f4 = Finding(
        analyzer="ml_url",
        indicator="ML_URL_SUSPICIOUS_LEXICAL_ANOMALY",
        description="ML finding for domain D",
        severity=FindingSeverity.MEDIUM,
        target="domain-d.com",
    )
    f5 = Finding(
        analyzer="ml_url",
        indicator="ML_URL_SUSPICIOUS_LEXICAL_ANOMALY",
        description="ML finding for domain E",
        severity=FindingSeverity.MEDIUM,
        target="domain-e.com",
    )

    score_multi, cat_multi, _ = assessor.evaluate(req, [f1, f2, f3, f4, f5])
    assert score_multi == 24
    assert cat_multi.value == "Low Risk"
````

## File: tests/unit/test_ml_features.py
````python
import math
import pytest

from app.ml.features import FEATURE_NAMES, extract_lexical_features


def test_feature_names_count_and_uniqueness():
    assert len(FEATURE_NAMES) == 14
    assert len(set(FEATURE_NAMES)) == 14


def test_extract_lexical_features_returns_none_for_invalid_urls():
    assert extract_lexical_features("") is None
    assert extract_lexical_features("not-a-url") is None
    assert extract_lexical_features("javascript:alert(1)") is None
    assert extract_lexical_features("ftp://ftp.example.com/file.txt") is None


def test_extract_lexical_features_returns_correct_length_and_finite_numbers():
    features = extract_lexical_features("https://www.example.com/path/to/page?param1=value&param2=123#section")
    assert features is not None
    assert len(features) == 14
    for val in features:
        assert isinstance(val, (int, float))
        assert math.isfinite(val)


def test_url_length_feature():
    url = "http://example.com/test"
    features = extract_lexical_features(url)
    assert features is not None
    # Feature 0: length_url
    assert features[0] == float(len(url))


def test_ip_address_detection_features():
    ip_url = "http://192.168.1.1/login"
    features = extract_lexical_features(ip_url)
    assert features is not None
    # Feature 11: has_ip_host
    assert features[11] == 1.0


def test_non_ip_hostname_features():
    domain_url = "https://accounts.google.com/signin"
    features = extract_lexical_features(domain_url)
    assert features is not None
    # Feature 11: has_ip_host
    assert features[11] == 0.0


def test_https_feature():
    https_url = "https://security-update.com/verify"
    features_https = extract_lexical_features(https_url)
    assert features_https is not None
    # Feature 13: is_https
    assert features_https[13] == 1.0

    http_url = "http://security-update.com/verify"
    features_http = extract_lexical_features(http_url)
    assert features_http is not None
    # Feature 13: is_https
    assert features_http[13] == 0.0


def test_at_symbol_detection():
    tricky_url = "http://legit.com@phishing.site/login"
    features = extract_lexical_features(tricky_url)
    assert features is not None
    # Feature 12: has_at_symbol
    assert features[12] == 1.0

    clean_url = "http://phishing.site/login"
    features_clean = extract_lexical_features(clean_url)
    assert features_clean is not None
    assert features_clean[12] == 0.0


def test_subdomain_depth_and_hyphen_features():
    multi_sub_url = "http://login.secure-portal.update.example.co.uk/path"
    features = extract_lexical_features(multi_sub_url)
    assert features is not None
    # Feature 4: count_hyphens
    assert features[4] >= 1.0
    # Feature 10: subdomain_depth
    assert features[10] >= 2.0
````

## File: tests/unit/test_prepare_dataset.py
````python
import csv
import json
import pytest
from pathlib import Path

from scripts.prepare_dataset import (
    CleanRecord,
    allocate_domain_groups,
    derive_group_key,
    parse_and_clean_dataset,
    prepare_dataset_pipeline,
)
from app.detectors.url.url_utils import validate_and_normalize_url


def test_derive_group_key_collision_safety():
    # IP literal host
    comp_ip, _ = validate_and_normalize_url("http://192.168.1.1:8080/login")
    assert derive_group_key(comp_ip) == "ip:192.168.1.1"

    # Registered domain
    comp_domain, _ = validate_and_normalize_url("https://sub.portal.paypal.com/auth")
    assert derive_group_key(comp_domain) == "domain:paypal.com"

    # Bare hostname
    comp_bare, _ = validate_and_normalize_url("http://localhost/path")
    assert derive_group_key(comp_bare) == "host:localhost"


def test_parse_and_clean_dataset_removes_invalid_and_conflicts(tmp_path: Path):
    sample_csv = tmp_path / "sample.csv"
    sample_csv.write_text(
        "URL,label\n"
        "https://clean1.com/login,1\n"         # Legitimate -> target 0
        "https://phish1.com/account,0\n"       # Phishing -> target 1
        "https://conflict.com/test,0\n"        # Conflicting label
        "https://conflict.com/test,1\n"        # Conflicting label (both dropped)
        "javascript:alert(1),0\n"              # Malformed (dropped)
        "https://clean1.com/login,1\n",        # Duplicate (dropped)
        encoding="utf-8",
    )

    records, stats = parse_and_clean_dataset(sample_csv)

    urls = [r.normalized_url for r in records]
    assert "https://clean1.com/login" in urls
    assert "https://phish1.com/account" in urls
    assert "https://conflict.com/test" not in urls
    assert len(records) == 2

    # Check label mapping: raw 1 -> target 0; raw 0 -> target 1
    r_clean = next(r for r in records if r.normalized_url == "https://clean1.com/login")
    r_phish = next(r for r in records if r.normalized_url == "https://phish1.com/account")
    assert r_clean.target_label == 0
    assert r_phish.target_label == 1
    assert stats["dropped_label_conflicts"] == 1
    assert stats["dropped_malformed_urls"] == 1


def test_parse_and_clean_dataset_missing_columns_raises_error(tmp_path: Path):
    bad_csv = tmp_path / "bad.csv"
    bad_csv.write_text("wrong_col,label\nhttps://test.com,0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Input CSV must contain both 'URL' and 'label'"):
        parse_and_clean_dataset(bad_csv)


def test_domain_disjoint_allocation_preserves_zero_overlap():
    records = []
    # 30 domains with 4 URLs each
    for d_idx in range(30):
        domain = f"domain{d_idx}.com"
        for u_idx in range(4):
            records.append(
                CleanRecord(
                    raw_url=f"https://{domain}/path{u_idx}",
                    normalized_url=f"https://{domain}/path{u_idx}",
                    target_label=d_idx % 2,
                    group_key=f"domain:{domain}",
                )
            )

    train_recs, val_recs, test_recs = allocate_domain_groups(records, max_urls=None)

    train_groups = {r.group_key for r in train_recs}
    val_groups = {r.group_key for r in val_recs}
    test_groups = {r.group_key for r in test_recs}

    assert train_groups.isdisjoint(val_groups)
    assert train_groups.isdisjoint(test_groups)
    assert val_groups.isdisjoint(test_groups)
    assert len(train_recs) + len(val_recs) + len(test_recs) == len(records)


def test_prepare_dataset_pipeline_end_to_end_with_metadata(tmp_path: Path):
    raw_csv = tmp_path / "raw.csv"
    raw_csv.write_text(
        "URL,label\n"
        "https://d1.com/1,0\n"
        "https://d1.com/2,0\n"
        "https://d2.com/1,1\n"
        "https://d2.com/2,1\n"
        "https://d3.com/1,0\n"
        "https://d4.com/1,1\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "processed"

    meta = prepare_dataset_pipeline(raw_csv=raw_csv, output_dir=out_dir, max_urls=10)

    assert (out_dir / "train.csv").exists()
    assert (out_dir / "val.csv").exists()
    assert (out_dir / "test.csv").exists()
    assert (out_dir / "metadata.json").exists()

    with open(out_dir / "metadata.json", "r", encoding="utf-8") as f:
        meta_loaded = json.load(f)

    assert meta_loaded["source_dataset_id"] == "UCI_PhiUSIIL_Phishing_URL_Dataset (ID 967)"
    assert meta_loaded["actual_urls_processed"] == 6
````

## File: tests/unit/test_risk_assessor.py
````python
from app.schemas.analysis import (
    AnalysisRequest,
    AuthStatus,
    EmailAuthenticationInput,
    Finding,
    FindingSeverity,
    RiskCategory,
)
from app.services.risk_assessor import extract_normalized_target, risk_assessor


def test_target_extraction_precedence_on_sender_brand_subdomain():
    # Description contains both brand 'paypal' and registered domain 'attacker-a.com'
    finding = Finding(
        analyzer="sender",
        indicator="BRAND_NAME_IN_UNRELATED_DOMAIN",
        description="Trusted brand 'paypal' appears in a subdomain label, but the registered domain is 'attacker-a.com'.",
        severity=FindingSeverity.MEDIUM,
    )
    target = extract_normalized_target(finding)
    assert target == "attacker-a.com"


def test_target_extraction_fallback_on_unquoted_text():
    finding = Finding(
        analyzer="sender",
        indicator="SUSPICIOUS_SUBDOMAIN_DEPTH",
        description="Sender domain has an unusually deep subdomain structure with no quotes.",
        severity=FindingSeverity.LOW,
    )
    target = extract_normalized_target(finding)
    assert target == "global_fallback"


def test_cross_analyzer_collision_resolves_highest_severity_and_repeat_bonus():
    # Sender emits MEDIUM (18 pts), URL emits HIGH (35 pts) on distinct targets
    f1 = Finding(
        analyzer="sender",
        indicator="BRAND_NAME_IN_UNRELATED_DOMAIN",
        description="Trusted brand 'paypal' appears in a subdomain label, but the registered domain is 'attacker-a.com'.",
        severity=FindingSeverity.MEDIUM,
    )
    f2 = Finding(
        analyzer="url",
        indicator="BRAND_NAME_IN_UNRELATED_DOMAIN",
        description="URL hostname 'paypal.com.attacker-b.com' places trusted brand into a subdomain.",
        severity=FindingSeverity.HIGH,
    )
    req = AnalysisRequest(sender_email="user@example.com", subject="Test", body="Valid length body content")
    score, category, _ = risk_assessor.evaluate(req, [f1, f2])
    # Base weight 35 (max of MEDIUM, HIGH) + 2 (1 repeat) = 37 pts
    assert score == 37
    assert category == RiskCategory.SUSPICIOUS


def test_exact_duplicate_findings_do_not_add_repeat_bonus():
    f1 = Finding(
        analyzer="sender",
        indicator="LOOKALIKE_TRUSTED_DOMAIN",
        description="Sender domain label 'paypa1' closely resembles trusted brand 'paypal.com'.",
        severity=FindingSeverity.HIGH,
    )
    f2 = Finding(
        analyzer="sender",
        indicator="LOOKALIKE_TRUSTED_DOMAIN",
        description="Sender domain label 'paypa1' closely resembles trusted brand 'paypal.com'.",
        severity=FindingSeverity.HIGH,
    )
    req = AnalysisRequest(sender_email="user@paypa1.com", subject="Test", body="Valid length body content")
    score, category, _ = risk_assessor.evaluate(req, [f1, f2])
    assert score == 35  # Exact duplicate ignored


def test_repeat_bonus_capped_at_maximum():
    # 5 distinct targets under URL_SUSPICIOUS_TLD
    findings = [
        Finding(
            analyzer="url",
            indicator="URL_SUSPICIOUS_TLD",
            description=f"URL uses top-level domain '.{tld}'.",
            severity=FindingSeverity.LOW,
        )
        for tld in ["xyz", "top", "buzz", "rest", "club"]
    ]
    req = AnalysisRequest(sender_email="user@example.com", subject="Deals", body="Valid length body content")
    score, category, _ = risk_assessor.evaluate(req, findings)
    # Base weight 7 + min(6, 4 * 2) = 7 + 6 = 13 pts
    assert score == 13
    assert category == RiskCategory.LOW_RISK


def test_all_info_findings_produce_zero_score_with_disclaimer():
    f1 = Finding(
        analyzer="url",
        indicator="URL_PUNYCODE_HOST",
        description="URL hostname 'xn--pple-43d.com' uses Punycode encoding.",
        severity=FindingSeverity.INFO,
    )
    f2 = Finding(
        analyzer="url",
        indicator="URL_REDIRECT_PARAMETER_PRESENT",
        description="URL 'https://sso.com' contains redirect parameter.",
        severity=FindingSeverity.INFO,
    )
    req = AnalysisRequest(sender_email="user@example.com", subject="Login", body="Valid length body content")
    score, category, summary = risk_assessor.evaluate(req, [f1, f2])
    assert score == 0
    assert category == RiskCategory.LOW_RISK
    assert "0 weighted risk score" in summary
    assert "does not prove an email is completely safe" in summary


def test_synergy_identity_and_credential_fires_once():
    f_sender = Finding(
        analyzer="sender",
        indicator="LOOKALIKE_TRUSTED_DOMAIN",
        description="Sender domain label 'paypa1' mimics paypal.com.",
        severity=FindingSeverity.HIGH,
    )
    f_url = Finding(
        analyzer="url",
        indicator="URL_BRAND_NAME_IN_UNRELATED_DOMAIN",
        description="URL hostname 'paypal.com.attacker.com' mimics paypal.",
        severity=FindingSeverity.HIGH,
    )
    f_cred = Finding(
        analyzer="content",
        indicator="CONTENT_CREDENTIAL_SOLICITATION",
        description="Email body: Contains actionable credential request.",
        severity=FindingSeverity.HIGH,
    )
    req = AnalysisRequest(sender_email="user@paypa1.com", subject="Alert", body="Please enter password")
    score, category, summary = risk_assessor.evaluate(req, [f_sender, f_url, f_cred])
    # Base: 35 + 35 + 35 = 105. Synergy SYN_IDENTITY_CREDENTIAL fires once (+15) -> 120 -> clamped to 100
    assert score == 100
    assert category == RiskCategory.HIGH_RISK
    assert "Identity Mimicry & Credential Solicitation" in summary


def test_synergy_urgency_and_financial_fires_once():
    f_urg = Finding(
        analyzer="content",
        indicator="CONTENT_URGENCY_PRESSURE",
        description="Email body: Immediate action required.",
        severity=FindingSeverity.MEDIUM,
    )
    f_fin = Finding(
        analyzer="content",
        indicator="CONTENT_FINANCIAL_LURE",
        description="Email body: Unclaimed funds available.",
        severity=FindingSeverity.MEDIUM,
    )
    req = AnalysisRequest(sender_email="user@example.com", subject="Funds", body="Claim your funds immediately")
    score, category, summary = risk_assessor.evaluate(req, [f_urg, f_fin])
    # 18 + 18 + 10 = 46 pts
    assert score == 46
    assert category == RiskCategory.SUSPICIOUS
    assert "Urgency Pressure & Financial Lure" in summary


def test_threshold_boundaries():
    req = AnalysisRequest(sender_email="user@example.com", subject="Test", body="Valid length body content")

    # Score 24 -> LOW_RISK
    # 1 Medium (18 pts) + 1 Low (7 pts) with distinct repeat target on Low:
    # Or 2 Lows (7 + 7 = 14) + 5 repeat bonus = not 24.
    # Craft exactly 24: 1 Medium (18) + 3 repeat targets on that Medium (repeat bonus = 3 * 2 = 6) -> 18 + 6 = 24!
    f_24 = [
        Finding(analyzer="url", indicator="M", description=f"Host '{i}.com'", severity=FindingSeverity.MEDIUM)
        for i in range(4)  # 1 base (18) + 3 repeats (6) = 24
    ]
    score_24, cat_24, _ = risk_assessor.evaluate(req, f_24)
    assert score_24 == 24
    assert cat_24 == RiskCategory.LOW_RISK

    # Score 25 -> SUSPICIOUS: 1 Medium (18) + 1 Low (7) = 25
    score_25, cat_25, _ = risk_assessor.evaluate(
        req,
        [
            Finding(analyzer="url", indicator="M", description="Host 'a.com'", severity=FindingSeverity.MEDIUM),
            Finding(analyzer="url", indicator="L", description="Host 'b.com'", severity=FindingSeverity.LOW),
        ],
    )
    assert score_25 == 25
    assert cat_25 == RiskCategory.SUSPICIOUS

    # Score 59 -> SUSPICIOUS:
    # 1 High (35) + 3 repeats on High (max repeat bonus = 6) = 41
    # 1 Medium (18) = 18
    # Total = 41 + 18 = 59
    f_59 = [
        Finding(analyzer="url", indicator="H", description="Host '1.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="H", description="Host '2.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="H", description="Host '3.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="H", description="Host '4.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="M", description="Host 'm.com'", severity=FindingSeverity.MEDIUM),
    ]
    score_59, cat_59, _ = risk_assessor.evaluate(req, f_59)
    assert score_59 == 59
    assert cat_59 == RiskCategory.SUSPICIOUS

    # Score 60 -> HIGH_RISK:
    # 1 High (35) + 1 Medium (18) + 1 Low (7) = 60
    f_60 = [
        Finding(analyzer="url", indicator="H", description="Host 'h.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="M", description="Host 'm.com'", severity=FindingSeverity.MEDIUM),
        Finding(analyzer="url", indicator="L", description="Host 'l.com'", severity=FindingSeverity.LOW),
    ]
    score_60, cat_60, _ = risk_assessor.evaluate(req, f_60)
    assert score_60 == 60
    assert cat_60 == RiskCategory.HIGH_RISK


def test_inconclusive_on_empty_content_with_no_findings():
    req = AnalysisRequest(sender_email="user@example.com", subject="", body="hi")
    score, category, summary = risk_assessor.evaluate(req, [])
    assert score is None
    assert category == RiskCategory.INCONCLUSIVE
    assert "Insufficient content" in summary


def test_mismatched_reply_to_with_empty_content_is_not_inconclusive():
    # Minimal body and empty subject, but findings exist (REPLY_TO_DOMAIN_MISMATCH)
    f = Finding(
        analyzer="sender",
        indicator="REPLY_TO_DOMAIN_MISMATCH",
        description="Reply-To address points to an unrelated domain ('attacker.com').",
        severity=FindingSeverity.MEDIUM,
    )
    req = AnalysisRequest(
        sender_email="user@legit.com",
        reply_to="attacker@attacker.com",
        subject="",
        body="hi",
    )
    score, category, _ = risk_assessor.evaluate(req, [f])
    assert score == 18
    assert category == RiskCategory.LOW_RISK


def test_sender_ip_literal_with_empty_body_scores_exact_eighteen():
    f = Finding(
        analyzer="sender",
        indicator="IP_LITERAL_SENDER_DOMAIN",
        description="Sender domain is a raw IP literal (192.168.1.1) rather than a named host.",
        severity=FindingSeverity.MEDIUM,
    )
    req = AnalysisRequest(sender_email="user@[192.168.1.1]", subject="", body="")
    score, category, _ = risk_assessor.evaluate(req, [f])
    assert score == 18
    assert category == RiskCategory.LOW_RISK


def test_neutral_authentication_unknown_and_none_scores_zero():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Meeting Notes",
        body="Attached are the notes from our sprint planning meeting.",
        authentication=EmailAuthenticationInput(
            spf=AuthStatus.UNKNOWN,
            dkim=AuthStatus.NONE,
            dmarc=AuthStatus.UNKNOWN,
        ),
    )
    score, category, _ = risk_assessor.evaluate(req, [])
    assert score == 0
    assert category == RiskCategory.LOW_RISK
````

## File: tests/unit/test_sender_analyzer.py
````python
from app.detectors.sender.analyzer import sender_analyzer
from app.schemas.analysis import AnalysisRequest, AuthStatus, EmailAuthenticationInput, FindingSeverity


def test_clean_trusted_domain_emits_no_findings():
    req = AnalysisRequest(sender_email="security@paypal.com")
    findings = sender_analyzer.analyze(req)
    assert len(findings) == 0


def test_legitimate_subdomain_of_trusted_domain_emits_no_findings():
    req = AnalysisRequest(sender_email="support@mail.paypal.com")
    findings = sender_analyzer.analyze(req)
    assert len(findings) == 0


def test_brand_in_subdomain_detected():
    req = AnalysisRequest(sender_email="security@paypal.com.attacker.com")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "BRAND_NAME_IN_UNRELATED_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "BRAND_NAME_IN_UNRELATED_DOMAIN")
    assert finding.severity == FindingSeverity.MEDIUM
    assert "attacker.com" in finding.description


def test_lookalike_trusted_domain_detected():
    req = AnalysisRequest(sender_email="alert@paypa1.com")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "LOOKALIKE_TRUSTED_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "LOOKALIKE_TRUSTED_DOMAIN")
    assert finding.severity == FindingSeverity.HIGH


def test_legitimate_hyphenated_domain_false_positive_safeguard():
    req = AnalysisRequest(sender_email="contact@e-commerce-shop.com")
    findings = sender_analyzer.analyze(req)
    assert len(findings) == 0


def test_legitimate_bulk_provider_reply_to():
    req = AnalysisRequest(
        sender_email="billing@acme-corp.com",
        reply_to="support@zendesk.com",
    )
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "REPLY_TO_BULK_PROVIDER" in indicators
    assert "REPLY_TO_DOMAIN_MISMATCH" not in indicators
    finding = next(f for f in findings if f.indicator == "REPLY_TO_BULK_PROVIDER")
    assert finding.severity == FindingSeverity.INFO


def test_unrelated_reply_to_mismatch():
    req = AnalysisRequest(
        sender_email="security@mybank.com",
        reply_to="attacker@random-inbox.com",
    )
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "REPLY_TO_DOMAIN_MISMATCH" in indicators
    finding = next(f for f in findings if f.indicator == "REPLY_TO_DOMAIN_MISMATCH")
    assert finding.severity == FindingSeverity.MEDIUM


def test_missing_or_unknown_authentication_produces_no_penalty():
    req = AnalysisRequest(
        sender_email="service@acme-corp.com",
        authentication=EmailAuthenticationInput(
            spf=AuthStatus.UNKNOWN,
            dkim=AuthStatus.UNKNOWN,
            dmarc=AuthStatus.UNKNOWN,
        ),
    )
    findings = sender_analyzer.analyze(req)
    assert len(findings) == 0


def test_correlated_authentication_failure_avoids_triple_counting():
    req = AnalysisRequest(
        sender_email="spoofed@victim-domain.com",
        authentication=EmailAuthenticationInput(
            spf=AuthStatus.FAIL,
            dkim=AuthStatus.FAIL,
            dmarc=AuthStatus.FAIL,
        ),
    )
    findings = sender_analyzer.analyze(req)
    indicators = {f.indicator: f for f in findings}

    assert "DMARC_POLICY_FAILED" in indicators
    assert indicators["DMARC_POLICY_FAILED"].severity == FindingSeverity.HIGH

    # Correlated SPF and DKIM failures should be downgraded to INFO
    assert "SPF_AUTHENTICATION_FAILED" in indicators
    assert indicators["SPF_AUTHENTICATION_FAILED"].severity == FindingSeverity.INFO
    assert "DKIM_AUTHENTICATION_FAILED" in indicators
    assert indicators["DKIM_AUTHENTICATION_FAILED"].severity == FindingSeverity.INFO


def test_punycode_domain_detected():
    req = AnalysisRequest(sender_email="info@xn--pple-43d.com")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "PUNYCODE_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "PUNYCODE_DOMAIN")
    assert finding.severity == FindingSeverity.INFO


def test_ip_literal_sender_detected():
    req = AnalysisRequest(sender_email="admin@[192.0.2.1]")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "IP_LITERAL_SENDER_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "IP_LITERAL_SENDER_DOMAIN")
    assert finding.severity == FindingSeverity.MEDIUM

def test_brand_in_subdomain_hyphenated_detected():
    # Detects hyphen-bounded brand lures in unrelated subdomains
    req = AnalysisRequest(sender_email="alert@login-paypal-verification.attacker.com")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "BRAND_NAME_IN_UNRELATED_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "BRAND_NAME_IN_UNRELATED_DOMAIN")
    assert finding.severity == FindingSeverity.MEDIUM
    assert "paypal" in finding.description
    assert "attacker.com" in finding.description


def test_brand_in_subdomain_false_positive_safeguards():
    # Ensures words embedding a brand name as a substring (e.g. 'snapple', 'pineapples') do not trigger
    req_snapple = AnalysisRequest(sender_email="promotions@snapple-beverages.attacker.com")
    findings_snapple = sender_analyzer.analyze(req_snapple)
    assert "BRAND_NAME_IN_UNRELATED_DOMAIN" not in [f.indicator for f in findings_snapple]

    req_pineapples = AnalysisRequest(sender_email="orders@pineapples.organic-store.com")
    findings_pineapples = sender_analyzer.analyze(req_pineapples)
    assert "BRAND_NAME_IN_UNRELATED_DOMAIN" not in [f.indicator for f in findings_pineapples]
````

## File: tests/unit/test_sender_domain_utils.py
````python
from app.detectors.sender.domain_utils import (
    parse_and_normalize_email_domain,
    compute_levenshtein_distance,
    is_lookalike_of_trusted_domain,
)


def test_parse_domain_standard_clean():
    parsed = parse_and_normalize_email_domain("user@paypal.com")
    assert parsed is not None
    assert parsed.registered_domain == "paypal.com"
    assert parsed.domain == "paypal"
    assert parsed.suffix == "com"
    assert parsed.subdomain == ""
    assert parsed.subdomain_depth == 0
    assert not parsed.is_ip_literal
    assert not parsed.has_punycode


def test_parse_domain_strips_trailing_dns_dot_and_case():
    parsed = parse_and_normalize_email_domain("Alerts@Mail.Google.Com.")
    assert parsed is not None
    assert parsed.normalized_ascii == "mail.google.com"
    assert parsed.registered_domain == "google.com"
    assert parsed.subdomain == "mail"
    assert parsed.subdomain_depth == 1


def test_parse_domain_subdomain_spoofing():
    parsed = parse_and_normalize_email_domain("security@paypal.com.attacker.com")
    assert parsed is not None
    assert parsed.registered_domain == "attacker.com"
    assert parsed.subdomain == "paypal.com"
    assert parsed.subdomain_depth == 2


def test_parse_domain_ip_literal():
    parsed = parse_and_normalize_email_domain("admin@[192.0.2.1]")
    assert parsed is not None
    assert parsed.is_ip_literal is True
    assert parsed.registered_domain == "192.0.2.1"


def test_parse_domain_punycode():
    parsed = parse_and_normalize_email_domain("info@xn--pple-43d.com")
    assert parsed is not None
    assert parsed.has_punycode is True
    assert parsed.suffix == "com"


def test_levenshtein_distance():
    assert compute_levenshtein_distance("paypal", "paypal") == 0
    assert compute_levenshtein_distance("paypal", "paypa1") == 1
    assert compute_levenshtein_distance("google", "g00gle") == 2
    assert compute_levenshtein_distance("apple", "bpple") == 1


def test_lookalike_trusted_domain():
    # 1-char substitution or edit distance
    assert is_lookalike_of_trusted_domain("paypa1", "paypal") is True
    assert is_lookalike_of_trusted_domain("pypal", "paypal") is True
    assert is_lookalike_of_trusted_domain("paypals", "paypal") is True
    assert is_lookalike_of_trusted_domain("micros0ft", "microsoft") is True

    # Exact match must return False
    assert is_lookalike_of_trusted_domain("paypal", "paypal") is False
    assert is_lookalike_of_trusted_domain("google", "google") is False

    # Significant length differences must return False (false positive safeguard)
    assert is_lookalike_of_trusted_domain("paypalservices", "paypal") is False
    assert is_lookalike_of_trusted_domain("pal", "paypal") is False

def test_parse_domain_multi_part_tld_offline():
    # Verifies offline Public Suffix List correctly handles multi-part ccTLDs
    parsed = parse_and_normalize_email_domain("billing@service.amazon.co.uk")
    assert parsed is not None
    assert parsed.registered_domain == "amazon.co.uk"
    assert parsed.domain == "amazon"
    assert parsed.suffix == "co.uk"
    assert parsed.subdomain == "service"
````

## File: tests/unit/test_train_url_model.py
````python
import csv
from pathlib import Path
import joblib
import numpy as np
import pytest

from app.ml.features import FEATURE_NAMES
from scripts.train_url_model import (
    load_and_validate_split,
    select_validation_threshold,
    train_and_export_pipeline,
)


def _create_mock_split(csv_path: Path, rows: list) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "normalized_url", "label", "domain_group"])
        for r in rows:
            writer.writerow(r)


def test_load_and_validate_split_missing_file_raises_error(tmp_path: Path):
    non_existent = tmp_path / "missing.csv"
    with pytest.raises(FileNotFoundError, match="Partition CSV file not found"):
        load_and_validate_split(non_existent)


def test_load_and_validate_split_invalid_header_raises_error(tmp_path: Path):
    bad_csv = tmp_path / "bad_header.csv"
    bad_csv.write_text("link,target\nhttps://example.com,0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain 'url' and 'label' header columns"):
        load_and_validate_split(bad_csv)


def test_load_and_validate_split_invalid_label_raises_error(tmp_path: Path):
    bad_csv = tmp_path / "bad_label.csv"
    _create_mock_split(
        bad_csv,
        [
            ["https://example1.com", "https://example1.com", "0", "domain:example1.com"],
            ["https://example2.com", "https://example2.com", "2", "domain:example2.com"],
        ],
    )
    with pytest.raises(ValueError, match="has invalid label '2'"):
        load_and_validate_split(bad_csv)


def test_load_and_validate_split_single_class_raises_error(tmp_path: Path):
    single_class_csv = tmp_path / "single_class.csv"
    _create_mock_split(
        single_class_csv,
        [
            ["https://example1.com", "https://example1.com", "0", "domain:example1.com"],
            ["https://example2.com", "https://example2.com", "0", "domain:example2.com"],
        ],
    )
    with pytest.raises(ValueError, match="must contain both classes"):
        load_and_validate_split(single_class_csv)


def test_load_and_validate_split_malformed_url_raises_error(tmp_path: Path):
    malformed_csv = tmp_path / "malformed.csv"
    _create_mock_split(
        malformed_csv,
        [
            ["https://example1.com", "https://example1.com", "0", "domain:example1.com"],
            ["javascript:alert(1)", "javascript:alert(1)", "1", "domain:bad.com"],
        ],
    )
    with pytest.raises(ValueError, match="could not be parsed for features"):
        load_and_validate_split(malformed_csv)


def test_select_validation_threshold_satisfies_target_fpr():
    # 100 negatives, 100 positives
    y_val = np.array([0] * 100 + [1] * 100)
    # Negatives get probabilities [0.00 .. 0.10], one negative at 0.05, one at 0.02
    # Positives get probabilities [0.80 .. 0.99]
    y_prob = np.concatenate([
        np.linspace(0.01, 0.04, 99),
        np.array([0.08]),  # exactly 1 FP if T <= 0.08 (1% FPR)
        np.linspace(0.80, 0.99, 100),
    ])

    # If target_fpr = 0.015 (1.5%), 1 FP / 100 = 1.0% is acceptable
    threshold, metrics = select_validation_threshold(y_val, y_prob, target_fpr=0.015)
    assert metrics["fpr"] <= 0.015
    assert threshold <= 0.08


def test_select_validation_threshold_fails_when_target_cannot_be_met():
    # 10 negatives, 10 positives
    y_val = np.array([0] * 10 + [1] * 10)
    # Negatives assigned high probabilities: even at T=0.9, all negatives predict 1 (100% FPR)
    y_prob = np.array([0.95] * 20)

    with pytest.raises(RuntimeError, match="Model failed to achieve target FPR <= 1.50%"):
        # Target FPR 1.5% impossible when minimum FPR is 100%
        select_validation_threshold(y_val, y_prob, target_fpr=0.015)


def test_train_and_export_pipeline_end_to_end_and_atomic_write(tmp_path: Path):
    train_csv = tmp_path / "train.csv"
    val_csv = tmp_path / "val.csv"
    artifact_path = tmp_path / "models" / "url_rf_model.joblib"

    # Synthetic training instances: 20 legitimate, 20 phishing
    train_rows = []
    for i in range(20):
        train_rows.append([f"https://legit-site-{i}.com/page", f"https://legit-site-{i}.com/page", "0", f"domain:legit-{i}.com"])
        train_rows.append([f"http://phish-attack-{i}.xyz/login/verify?id={i}", f"http://phish-attack-{i}.xyz/login/verify?id={i}", "1", f"domain:phish-{i}.xyz"])
    _create_mock_split(train_csv, train_rows)

    # Synthetic validation instances: 10 legitimate, 10 phishing
    val_rows = []
    for i in range(10):
        val_rows.append([f"https://val-legit-{i}.com/home", f"https://val-legit-{i}.com/home", "0", f"domain:val-legit-{i}.com"])
        val_rows.append([f"http://val-phish-{i}.xyz/auth/confirm", f"http://val-phish-{i}.xyz/auth/confirm", "1", f"domain:val-phish-{i}.xyz"])
    _create_mock_split(val_csv, val_rows)

    # Run pipeline with a generous target_fpr for small synthetic set
    meta = train_and_export_pipeline(
        train_csv=train_csv,
        val_csv=val_csv,
        artifact_path=artifact_path,
        random_seed=42,
        target_fpr=0.20,
    )

    assert artifact_path.exists()
    assert meta["train_sample_count"] == 40
    assert meta["val_sample_count"] == 20

    # Load and inspect artifact structure
    saved_artifact = joblib.load(artifact_path)
    assert "metadata" in saved_artifact
    assert "feature_schema" in saved_artifact
    assert "threshold" in saved_artifact
    assert "model" in saved_artifact

    # Verify exact feature schema order
    assert saved_artifact["feature_schema"]["feature_names"] == FEATURE_NAMES
    assert hasattr(saved_artifact["model"], "predict_proba")


def test_atomic_write_preserves_existing_artifact_on_failure(tmp_path: Path):
    artifact_path = tmp_path / "url_rf_model.joblib"
    artifact_path.write_text("PREVIOUS_VALID_ARTIFACT_DATA", encoding="utf-8")

    # Pass non-existent training CSV
    missing_train = tmp_path / "non_existent_train.csv"
    val_csv = tmp_path / "val.csv"

    with pytest.raises(FileNotFoundError):
        train_and_export_pipeline(
            train_csv=missing_train,
            val_csv=val_csv,
            artifact_path=artifact_path,
        )

    # Assert previous artifact was untouched
    assert artifact_path.read_text(encoding="utf-8") == "PREVIOUS_VALID_ARTIFACT_DATA"
````

## File: tests/unit/test_url_analyzer.py
````python
from app.detectors.url.analyzer import url_analyzer
from app.schemas.analysis import AnalysisRequest, FindingSeverity


def test_clean_legitimate_brand_urls_produce_no_findings():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Check these docs",
        body="See https://developer.apple.com/documentation and https://aws.amazon.com/console",
    )
    findings = url_analyzer.analyze(req)
    assert len(findings) == 0


def test_brand_in_subdomain_of_unrelated_domain_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Security Notice",
        body="Login at https://paypal.com.attacker-portal.net/login immediately.",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_BRAND_NAME_IN_UNRELATED_DOMAIN" in indicators
    f = next(f for f in findings if f.indicator == "URL_BRAND_NAME_IN_UNRELATED_DOMAIN")
    assert f.severity == FindingSeverity.HIGH


def test_brand_in_path_or_query_does_not_trigger_brand_domain_findings():
    # Brand appears in path and query, but host is unrelated news/github site
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="News & Code",
        body="Read https://technews.org/articles/paypal-report and https://github.com/apple/swift",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_BRAND_NAME_IN_UNRELATED_DOMAIN" not in indicators
    assert "URL_LOOKALIKE_DOMAIN" not in indicators


def test_lookalike_typosquatting_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Account Update",
        body="Visit https://paypa1.com/verify to update details.",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_LOOKALIKE_DOMAIN" in indicators
    f = next(f for f in findings if f.indicator == "URL_LOOKALIKE_DOMAIN")
    assert f.severity == FindingSeverity.HIGH


def test_userinfo_credential_embedded_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Invoice",
        body="Open http://google.com@attacker-site.com/invoice.pdf",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_USERINFO_CREDENTIAL_EMBEDDED" in indicators
    f = next(f for f in findings if f.indicator == "URL_USERINFO_CREDENTIAL_EMBEDDED")
    assert f.severity == FindingSeverity.HIGH


def test_ip_literal_host_public_vs_non_global():
    # Public IPv4 (93.184.216.34) and public IPv6 ([2606:2800:220:1:248:1893:25c8:1946])
    req_pub = AnalysisRequest(
        sender_email="user@example.com",
        subject="IP Host",
        body="Visit http://93.184.216.34/portal and http://[2606:2800:220:1:248:1893:25c8:1946]/portal",
    )
    findings_pub = url_analyzer.analyze(req_pub)
    pub_indicators = [f.indicator for f in findings_pub]
    assert "URL_IP_LITERAL_HOST" in pub_indicators
    f_pub = next(f for f in findings_pub if f.indicator == "URL_IP_LITERAL_HOST")
    assert f_pub.severity == FindingSeverity.MEDIUM

    # Non-global: RFC 5737 documentation IPv4 (198.51.100.24) and private IPv4 (192.168.1.1)
    req_priv = AnalysisRequest(
        sender_email="user@example.com",
        subject="Doc IP",
        body="Check http://198.51.100.24/test and http://192.168.1.1/admin",
    )
    findings_priv = url_analyzer.analyze(req_priv)
    priv_indicators = [f.indicator for f in findings_priv]
    assert "URL_NON_GLOBAL_IP_HOST" in priv_indicators
    assert "URL_IP_LITERAL_HOST" not in priv_indicators
    f_priv = next(f for f in findings_priv if f.indicator == "URL_NON_GLOBAL_IP_HOST")
    assert f_priv.severity == FindingSeverity.INFO


def test_insecure_http_on_credential_path_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Login link",
        body="Go to http://legacy-portal.org/auth/login.php to sign in.",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_INSECURE_HTTP_CREDENTIAL_PATH" in indicators
    f = next(f for f in findings if f.indicator == "URL_INSECURE_HTTP_CREDENTIAL_PATH")
    assert f.severity == FindingSeverity.LOW


def test_port_policy_8080_exempt_and_unusual_port_detected():
    # Port 8080 is standard under policy -> no finding
    req_8080 = AnalysisRequest(
        sender_email="user@example.com",
        subject="Web app",
        body="See http://staging.internal.com:8080/dashboard",
    )
    findings_8080 = url_analyzer.analyze(req_8080)
    assert not any(f.indicator == "URL_UNUSUAL_PORT" for f in findings_8080)

    # Port 8443 is non-standard -> triggers URL_UNUSUAL_PORT
    req_8443 = AnalysisRequest(
        sender_email="user@example.com",
        subject="Secure node",
        body="See https://staging.internal.com:8443/dashboard",
    )
    findings_8443 = url_analyzer.analyze(req_8443)
    assert any(f.indicator == "URL_UNUSUAL_PORT" for f in findings_8443)
    f = next(f for f in findings_8443 if f.indicator == "URL_UNUSUAL_PORT")
    assert f.severity == FindingSeverity.LOW


def test_suspicious_tld_and_punycode_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Deals",
        body="Get deals at http://free-promo.xyz/deal and http://xn--pple-43d.com/store",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_SUSPICIOUS_TLD" in indicators
    assert "URL_PUNYCODE_HOST" in indicators


def test_double_percent_encoding_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Encoded link",
        body="Check http://phish-target.com/%252e%252e/login",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_SUSPICIOUS_OBFUSCATION" in indicators
    f = next(f for f in findings if f.indicator == "URL_SUSPICIOUS_OBFUSCATION")
    assert f.severity == FindingSeverity.MEDIUM


def test_redirect_parameter_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="SSO Login",
        body="Login via https://sso.example.com/oauth?redirect_uri=https://app.example.com/callback",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_REDIRECT_PARAMETER_PRESENT" in indicators
    f = next(f for f in findings if f.indicator == "URL_REDIRECT_PARAMETER_PRESENT")
    assert f.severity == FindingSeverity.INFO


def test_finding_deduplication_across_multiple_urls():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Multiple Links",
        body=(
            "Click https://paypal.com.attacker.com/login and "
            "also https://paypal.com.attacker.com/settings or "
            "https://paypal.com.attacker.com/terms"
        ),
    )
    findings = url_analyzer.analyze(req)
    brand_sub_findings = [f for f in findings if f.indicator == "URL_BRAND_NAME_IN_UNRELATED_DOMAIN"]
    # Exactly one deduplicated finding for the hostname
    assert len(brand_sub_findings) == 1
````

## File: tests/unit/test_url_utils.py
````python
from app.detectors.url.url_utils import extract_urls, validate_and_normalize_url


def test_malformed_interleaved_anchors_extracts_both_valid_urls():
    # Exactly tests the user scenario: valid1 and valid2 around broken unclosed anchor
    html_body = "<a href=\"https://valid1.com\">click<a href='unclosed... <a href=\"https://valid2.com\">next</a>"
    parsed_urls, limit_findings = extract_urls(body=html_body)
    urls = [u.normalized_url for u in parsed_urls]
    assert "https://valid1.com" in urls
    assert "https://valid2.com" in urls
    assert len([u for u in urls if u == "https://valid1.com"]) == 1
    assert len([u for u in urls if u == "https://valid2.com"]) == 1


def test_unsupported_schemes_rejected():
    body = (
        "<a href='javascript:alert(1)'>JS</a>"
        "<a href='mailto:support@test.com'>Mail</a>"
        "<a href='tel:+123456789'>Tel</a>"
        "<a href='data:text/html,test'>Data</a>"
        "<a href='#local-anchor'>Fragment</a>"
    )
    parsed_urls, _ = extract_urls(body=body)
    assert len(parsed_urls) == 0


def test_scheme_less_strings_in_plain_text_ignored():
    body = "Visit google.com/search or portal.internal/login for info."
    parsed_urls, _ = extract_urls(body=body)
    assert len(parsed_urls) == 0


def test_authority_validation_malformed_ports():
    # Out of range port (> 65535)
    components, is_malformed = validate_and_normalize_url("http://example.com:99999/test")
    assert is_malformed is True
    assert components is None

    # Non-numeric port
    components, is_malformed = validate_and_normalize_url("http://example.com:abc/test")
    assert is_malformed is True
    assert components is None

    # Port 0 (invalid)
    components, is_malformed = validate_and_normalize_url("http://example.com:0/test")
    assert is_malformed is True
    assert components is None


def test_authority_validation_unclosed_ipv6():
    components, is_malformed = validate_and_normalize_url("http://[2606:2800:220:1/path")
    assert is_malformed is True
    assert components is None


def test_conservative_normalization_preserves_semantics():
    # Strips default port 80 on HTTP and root trailing slash
    c1, _ = validate_and_normalize_url("HTTP://EXAMPLE.COM:80/")
    assert c1.normalized_url == "http://example.com"

    # Strips default port 443 on HTTPS
    c2, _ = validate_and_normalize_url("HTTPS://EXAMPLE.COM:443/")
    assert c2.normalized_url == "https://example.com"

    # Retains port 8080 (standard alternate HTTP port)
    c3, _ = validate_and_normalize_url("http://example.com:8080/")
    assert c3.normalized_url == "http://example.com:8080"

    # Preserves directory trailing slash
    c4, _ = validate_and_normalize_url("https://example.com/dir/")
    assert c4.normalized_url == "https://example.com/dir/"

    # Preserves raw query percent-encoding
    c5, _ = validate_and_normalize_url("https://example.com/api?param=%2F%26%3D")
    assert c5.normalized_url == "https://example.com/api?param=%2F%26%3D"


def test_offline_psl_decomposition():
    c, _ = validate_and_normalize_url("https://auth.portal.amazon.co.uk/path")
    assert c.domain_label == "amazon"
    assert c.suffix == "co.uk"
    assert c.registered_domain == "amazon.co.uk"
    assert c.subdomain == "auth.portal"


def test_url_length_limit():
    long_url = "https://example.com/" + ("a" * 2050)
    parsed_urls, findings = extract_urls(body="", additional_urls=[long_url])
    assert len(parsed_urls) == 0
    assert any(f.indicator == "URL_EXCESSIVE_LENGTH" for f in findings)


def test_url_evaluation_cap():
    many_urls = [f"https://example.com/page{i}" for i in range(60)]
    parsed_urls, findings = extract_urls(body="", additional_urls=many_urls)
    assert len(parsed_urls) == 50
    assert any(f.indicator == "URL_EVALUATION_CAP_EXCEEDED" for f in findings)
````
