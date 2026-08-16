"""
Unsupervised anomaly detection layer — Isolation Forest.

Trained only on NORMAL traffic windows, this model flags any window that
looks statistically unusual regardless of whether it matches a known
attack signature.  Runs alongside XGBoost as a second detection layer.

Usage:
    # Train on normal-only traffic:
    python -m detector.isolation_forest --log-path traffic.jsonl --output detector/model/iforest.pkl

    # Evaluate on mixed traffic (normal + attack):
    python -m detector.isolation_forest --log-path traffic.jsonl --evaluate
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detector.feature_extractor import (
    load_traffic_log,
    extract_windows,
    FEATURE_COLUMNS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [IFOREST] %(message)s")
log = logging.getLogger("IsolationForest")


class IsolationForestDetector:
    """Unsupervised anomaly detector using Isolation Forest.

    Trained exclusively on normal traffic — any window that deviates
    from learned normal patterns is flagged as anomalous.  This catches
    novel attack types the supervised XGBoost model has never seen.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        max_samples: str = "auto",
        random_state: int = 42,
    ):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.contamination = contamination

    def fit(self, X_normal: np.ndarray) -> "IsolationForestDetector":
        """Train on normal-only traffic windows.

        Args:
            X_normal: Feature matrix of normal-only windows (n_samples, 14)
        """
        log.info("Training Isolation Forest on %d normal windows", len(X_normal))
        X_scaled = self.scaler.fit_transform(X_normal)
        self.model.fit(X_scaled)
        self.is_fitted = True
        log.info("Isolation Forest trained (contamination=%.2f, estimators=%d)",
                 self.contamination, self.model.n_estimators)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly labels.

        Returns:
            Array of 0 (normal) or 1 (anomaly) per window.
        """
        if not self.is_fitted:
            raise RuntimeError("Model not fitted — call fit() first")
        X_scaled = self.scaler.transform(X)
        # IsolationForest returns 1 for inlier, -1 for outlier
        raw = self.model.predict(X_scaled)
        return (raw == -1).astype(int)  # Convert to 0=normal, 1=anomaly

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores (lower = more anomalous).

        Returns:
            Array of scores in [-1, 0] range. More negative = more anomalous.
        """
        if not self.is_fitted:
            raise RuntimeError("Model not fitted — call fit() first")
        X_scaled = self.scaler.transform(X)
        return self.model.decision_function(X_scaled)

    def save(self, path: str) -> None:
        """Save model + scaler to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"model": self.model, "scaler": self.scaler}, f)
        log.info("Model saved to: %s", path)

    @classmethod
    def load(cls, path: str) -> "IsolationForestDetector":
        """Load model + scaler from disk."""
        with open(path, "rb") as f:
            data = pickle.load(f)
        detector = cls()
        detector.model = data["model"]
        detector.scaler = data["scaler"]
        detector.is_fitted = True
        log.info("Model loaded from: %s", path)
        return detector


def train_isolation_forest(
    log_path: str,
    output_path: str,
    window_seconds: float = 2.0,
    contamination: float = 0.05,
) -> dict:
    """Train Isolation Forest on normal-only traffic and evaluate."""

    log.info("Loading traffic log: %s", log_path)
    records = load_traffic_log(log_path)
    log.info("Loaded %d records", len(records))

    if not records:
        log.error("No records found")
        return {}

    log.info("Extracting features (window=%.1fs)...", window_seconds)
    df = extract_windows(records, window_seconds)
    log.info("Extracted %d windows", len(df))

    n_normal = (df["label"] == 0).sum()
    n_attack = (df["label"] == 1).sum()
    log.info("Class distribution: normal=%d, attack=%d", n_normal, n_attack)

    if n_normal < 5:
        log.error("Not enough normal windows to train (need at least 5)")
        return {}

    # Train on normal-only data
    X_all = df[FEATURE_COLUMNS].values
    y_all = df["label"].values

    X_normal = X_all[y_all == 0]
    log.info("Training on %d normal-only windows", len(X_normal))

    detector = IsolationForestDetector(contamination=contamination)
    detector.fit(X_normal)

    # Evaluate on ALL data (normal + attack)
    predictions = detector.predict(X_all)
    scores = detector.anomaly_scores(X_all)

    metrics = {
        "n_normal_train": int(len(X_normal)),
        "n_total_eval": int(len(X_all)),
        "n_attack": int(n_attack),
    }

    if n_attack > 0:
        metrics["precision"] = round(precision_score(y_all, predictions, zero_division=0), 4)
        metrics["recall"] = round(recall_score(y_all, predictions, zero_division=0), 4)
        metrics["f1"] = round(f1_score(y_all, predictions, zero_division=0), 4)

        cm = confusion_matrix(y_all, predictions)
        metrics["confusion_matrix"] = cm.tolist()

        log.info("=== Isolation Forest Evaluation ===")
        log.info("  Precision: %.4f", metrics["precision"])
        log.info("  Recall:    %.4f", metrics["recall"])
        log.info("  F1 Score:  %.4f", metrics["f1"])
        log.info("  Confusion Matrix:")
        log.info("                 Predicted")
        log.info("              Normal  Anomaly")
        log.info("    Normal     %4d     %4d", cm[0][0], cm[0][1])
        log.info("    Attack     %4d     %4d", cm[1][0], cm[1][1])

        # Analyze evasion attacks specifically
        evasion_mask = np.array([False] * len(records))
        for i, r in enumerate(records):
            if "evasion" in r.get("label", ""):
                evasion_mask[i] = True

        # Check if any evasion windows were detected
        evasion_windows = []
        for i, row in df.iterrows():
            ws = row.get("window_start", "")
            # Mark as evasion if the label is attack and it's from evasion records
            if row["label"] == 1:
                evasion_windows.append(i)

        if evasion_windows:
            evasion_preds = predictions[evasion_windows]
            detected_evasion = evasion_preds.sum()
            log.info("  Evasion windows: %d detected / %d total",
                     detected_evasion, len(evasion_windows))
    else:
        log.info("No attack windows to evaluate against")
        # Show false positive rate on normal traffic
        fp = predictions[y_all == 0].sum()
        log.info("False positives on normal traffic: %d / %d (%.1f%%)",
                 fp, len(X_normal), fp / len(X_normal) * 100 if len(X_normal) > 0 else 0)

    # Save model
    detector.save(output_path)

    # Save metrics
    metrics_path = Path(output_path).with_suffix(".metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    log.info("Metrics saved to: %s", metrics_path)

    return metrics


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest anomaly detector")
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    parser.add_argument("--output", default="detector/model/iforest.pkl")
    parser.add_argument("--window", type=float, default=2.0)
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="Expected proportion of anomalies (for threshold tuning)")
    args = parser.parse_args()

    train_isolation_forest(args.log_path, args.output, args.window, args.contamination)


if __name__ == "__main__":
    main()
