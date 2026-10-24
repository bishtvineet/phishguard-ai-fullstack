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