"""
Real-time anomaly detector — tails traffic log, extracts features per window,
and scores with dual detection layers:
  1. XGBoost (supervised) — trained on labeled attack traffic
  2. Isolation Forest (unsupervised) — trained on normal-only traffic

An alert fires if EITHER model detects an anomaly.

Usage:
    python -m detector.detector [--model-path model/xgb_model.json] [--iforest-path model/iforest.pkl]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import List, Optional

import numpy as np
import xgboost as xgb

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detector.feature_extractor import (
    compute_window_features,
    FEATURE_COLUMNS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DETECTOR] %(message)s")
log = logging.getLogger("Detector")


class DetectorState:
    """Shared state between the scoring loop and the HTTP server."""

    def __init__(self):
        self.latest_score: float = 0.0
        self.latest_iforest_score: float = 0.0  # Isolation Forest score
        self.latest_features: dict = {}
        self.latest_timestamp: str = ""
        self.is_alert: bool = False
        self.alert_source: str = ""  # "xgboost", "iforest", "both"
        self.alert_history: List[dict] = []
        self.score_history: List[dict] = []
        self.lock = threading.Lock()

    def update(self, score: float, features: dict, is_alert: bool,
               iforest_score: float = 0.0, alert_source: str = ""):
        ts = datetime.now(timezone.utc).isoformat()
        with self.lock:
            self.latest_score = score
            self.latest_iforest_score = iforest_score
            self.latest_features = features
            self.latest_timestamp = ts
            self.is_alert = is_alert
            self.alert_source = alert_source
            self.score_history.append({
                "timestamp": ts, "score": score,
                "iforest_score": iforest_score,
                "alert": is_alert, "alert_source": alert_source,
            })
            if len(self.score_history) > 500:
                self.score_history = self.score_history[-500:]
            if is_alert:
                self.alert_history.append({"timestamp": ts, "score": score, "features": features})
                if len(self.alert_history) > 100:
                    self.alert_history = self.alert_history[-100:]

    def to_dict(self) -> dict:
        with self.lock:
            return {
                "latest_score": self.latest_score,
                "latest_iforest_score": self.latest_iforest_score,
                "latest_timestamp": self.latest_timestamp,
                "is_alert": self.is_alert,
                "alert_source": self.alert_source,
                "latest_features": self.latest_features,
                "score_history": list(self.score_history),
                "alert_count": len(self.alert_history),
            }


# Global state
state = DetectorState()


class DetectorHandler(BaseHTTPRequestHandler):
    """Simple HTTP API for the dashboard to poll."""

    def do_GET(self):
        if self.path == "/status":
            data = state.to_dict()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        elif self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging


def tail_log(log_path: str):
    """Generator that yields new lines from the traffic log file."""
    path = Path(log_path)

    # Wait for file to exist
    while not path.exists():
        time.sleep(1)

    with open(path, "r") as f:
        # Seek to end
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.1)


def scoring_loop(
    model: xgb.XGBClassifier,
    log_path: str,
    window_seconds: float = 2.0,
    threshold: float = 0.5,
    iforest=None,
):
    """Main scoring loop — collects messages, extracts features, scores with both models."""
    layers = ["XGBoost"]
    if iforest is not None:
        layers.append("Isolation Forest")
    log.info("Starting scoring loop (window=%.1fs, threshold=%.2f, layers=%s)",
             window_seconds, threshold, "+".join(layers))

    current_window: List[dict] = []
    window_start = time.time()

    for line in tail_log(log_path):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        current_window.append(record)

        # Check if window period has elapsed
        if time.time() - window_start >= window_seconds:
            if current_window:
                # Extract features
                features = compute_window_features(current_window, window_seconds)
                feature_vec = np.array([[features[col] for col in FEATURE_COLUMNS]])

                # --- Layer 1: XGBoost (supervised) ---
                xgb_prob = model.predict_proba(feature_vec)[0][1]
                xgb_alert = xgb_prob >= threshold

                # --- Layer 2: Isolation Forest (unsupervised) ---
                if_score = 0.0
                if_alert = False
                if iforest is not None:
                    if_pred = iforest.predict(feature_vec)
                    if_raw_score = iforest.anomaly_scores(feature_vec)
                    if_score = float(if_raw_score[0])
                    if_alert = bool(if_pred[0] == 1)

                # Combined alert: either model triggers
                is_alert = xgb_alert or if_alert
                alert_source = ""
                if xgb_alert and if_alert:
                    alert_source = "both"
                elif xgb_alert:
                    alert_source = "xgboost"
                elif if_alert:
                    alert_source = "iforest"

                state.update(xgb_prob, features, is_alert,
                             iforest_score=if_score, alert_source=alert_source)

                if is_alert:
                    log.warning(
                        "🚨 ALERT [%s]! XGB=%.3f IF=%.3f | msgs=%d rate=%.1f",
                        alert_source, xgb_prob, if_score,
                        features.get("msg_count", 0),
                        features.get("msg_rate", 0),
                    )
                else:
                    log.debug("Window OK: xgb=%.3f if=%.3f msgs=%d",
                              xgb_prob, if_score, features.get("msg_count", 0))

            # Reset window
            current_window = []
            window_start = time.time()


def write_alerts_loop(alerts_path: str = "/logs/alerts.jsonl"):
    """Periodically flush alerts to disk."""
    path = Path(alerts_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    last_count = 0

    while True:
        time.sleep(5)
        with state.lock:
            alerts = list(state.alert_history[last_count:])
            last_count = len(state.alert_history)

        if alerts:
            with open(path, "a") as f:
                for alert in alerts:
                    # Convert numpy types for serialization
                    clean_alert = {}
                    for k, v in alert.items():
                        if isinstance(v, dict):
                            clean_alert[k] = {kk: float(vv) if isinstance(vv, (np.floating, float)) else vv for kk, vv in v.items()}
                        elif isinstance(v, (np.floating,)):
                            clean_alert[k] = float(v)
                        else:
                            clean_alert[k] = v
                    f.write(json.dumps(clean_alert) + "\n")


def main():
    parser = argparse.ArgumentParser(description="SOME/IP Real-time Anomaly Detector")
    parser.add_argument("--model-path", default="detector/model/xgb_model.json")
    parser.add_argument("--iforest-path", default="detector/model/iforest.pkl",
                        help="Path to Isolation Forest model (optional)")
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    parser.add_argument("--window", type=float, default=2.0)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--http-port", type=int, default=5001)
    args = parser.parse_args()

    # Load XGBoost model
    model_path = Path(args.model_path)
    if not model_path.exists():
        log.warning("XGBoost model not found: %s — using dummy model", model_path)
        model = xgb.XGBClassifier(n_estimators=2, max_depth=1)
        X_dummy = np.random.rand(20, len(FEATURE_COLUMNS))
        y_dummy = np.array([0] * 10 + [1] * 10)
        model.fit(X_dummy, y_dummy, verbose=False)
        log.info("Created dummy XGBoost model — train with: python -m detector.train_model")
    else:
        model = xgb.XGBClassifier()
        model.load_model(str(model_path))
        log.info("Loaded XGBoost model from: %s", model_path)

    # Load Isolation Forest model (optional second layer)
    iforest = None
    iforest_path = Path(args.iforest_path)
    if iforest_path.exists():
        try:
            from detector.isolation_forest import IsolationForestDetector
            iforest = IsolationForestDetector.load(str(iforest_path))
            log.info("Loaded Isolation Forest model from: %s", iforest_path)
        except Exception as e:
            log.warning("Could not load Isolation Forest: %s", e)
    else:
        log.info("No Isolation Forest model found — running XGBoost-only mode")
        log.info("Train one with: python -m detector.isolation_forest")

    # Start HTTP server in background
    server = HTTPServer(("0.0.0.0", args.http_port), DetectorHandler)
    http_thread = threading.Thread(target=server.serve_forever, daemon=True)
    http_thread.start()
    log.info("HTTP API running on port %d", args.http_port)

    # Start alert writer in background
    alert_thread = threading.Thread(target=write_alerts_loop, daemon=True)
    alert_thread.start()

    # Run scoring loop (blocking)
    scoring_loop(model, args.log_path, args.window, args.threshold, iforest=iforest)


if __name__ == "__main__":
    main()
