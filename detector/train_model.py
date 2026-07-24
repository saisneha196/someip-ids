"""
XGBoost model training — trains a binary classifier on labeled traffic windows.

Reads traffic.jsonl → extract windowed features → train XGBoost → save model.

Usage:
    python -m detector.train_model [--log-path /logs/traffic.jsonl] [--output model/xgb_model.json]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detector.feature_extractor import (
    load_traffic_log,
    extract_windows,
    FEATURE_COLUMNS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TRAIN] %(message)s")
log = logging.getLogger("Train")


def train_model(
    log_path: str,
    output_path: str,
    window_seconds: float = 2.0,
    test_size: float = 0.2,
    random_state: int = 42,
) -> dict:
    """Train XGBoost classifier on labeled traffic data.

    Returns a dict of evaluation metrics.
    """
    log.info("Loading traffic log: %s", log_path)
    records = load_traffic_log(log_path)
    log.info("Loaded %d records", len(records))

    if not records:
        log.error("No records found. Run services + attacks first to generate traffic.")
        return {}

    log.info("Extracting features (window=%.1fs)...", window_seconds)
    df = extract_windows(records, window_seconds)
    log.info("Extracted %d windows", len(df))

    if df.empty:
        log.error("No windows extracted.")
        return {}

    # Check class balance
    n_normal = (df["label"] == 0).sum()
    n_attack = (df["label"] == 1).sum()
    log.info("Class distribution: normal=%d, attack=%d", n_normal, n_attack)

    if n_attack == 0:
        log.warning("No attack windows found — model will only see normal traffic!")
    if n_normal == 0:
        log.warning("No normal windows found — something may be wrong with labeling!")

    # Prepare features and labels
    X = df[FEATURE_COLUMNS].values
    y = df["label"].values

    # Train/test split
    if len(df) >= 10:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y if n_attack > 0 else None,
        )
    else:
        # Too few samples for split — use all for training
        X_train, X_test, y_train, y_test = X, X, y, y
        log.warning("Too few samples for train/test split — using all data for both")

    # Handle class imbalance
    scale_pos_weight = n_normal / max(n_attack, 1) if n_attack > 0 else 1.0

    # Train XGBoost
    log.info("Training XGBoost (scale_pos_weight=%.2f)...", scale_pos_weight)
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=scale_pos_weight,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=random_state,
        use_label_encoder=False,
    )
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "n_normal": int(n_normal),
        "n_attack": int(n_attack),
    }

    log.info("=== Evaluation Results ===")
    for k, v in metrics.items():
        log.info("  %s: %s", k, v)

    cm = confusion_matrix(y_test, y_pred)
    log.info("Confusion Matrix:\n%s", cm)

    # Feature importance
    importance = dict(zip(FEATURE_COLUMNS, model.feature_importances_))
    log.info("Feature Importance:")
    for feat, imp in sorted(importance.items(), key=lambda x: -x[1]):
        log.info("  %s: %.4f", feat, imp)
    metrics["feature_importance"] = importance

    # Save model
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(output_path))
    log.info("Model saved to: %s", output_path)

    # Also save metrics alongside model
    metrics_path = output_path.with_suffix(".metrics.json")
    with open(metrics_path, "w") as f:
        # Convert numpy types for JSON serialization
        clean_metrics = {}
        for k, v in metrics.items():
            if isinstance(v, dict):
                clean_metrics[k] = {kk: float(vv) for kk, vv in v.items()}
            else:
                clean_metrics[k] = v
        json.dump(clean_metrics, f, indent=2)
    log.info("Metrics saved to: %s", metrics_path)

    return metrics


def main():
    parser = argparse.ArgumentParser(description="Train XGBoost IDS model")
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    parser.add_argument("--output", default="detector/model/xgb_model.json")
    parser.add_argument("--window", type=float, default=2.0)
    args = parser.parse_args()

    train_model(args.log_path, args.output, args.window)


if __name__ == "__main__":
    main()
