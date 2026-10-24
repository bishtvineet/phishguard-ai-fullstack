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