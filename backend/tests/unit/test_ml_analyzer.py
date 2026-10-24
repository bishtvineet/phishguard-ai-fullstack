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