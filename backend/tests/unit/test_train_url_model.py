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