"""
Real-time anomaly detector — tails traffic log, extracts features per window,
and scores with XGBoost model. Exposes results via a simple HTTP endpoint.

Usage:
    python -m detector.detector [--model-path model/xgb_model.json]
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
        self.latest_features: dict = {}
        self.latest_timestamp: str = ""
        self.is_alert: bool = False
        self.alert_history: List[dict] = []  # last N alerts
        self.score_history: List[dict] = []  # last N window scores
        self.lock = threading.Lock()

    def update(self, score: float, features: dict, is_alert: bool):
        ts = datetime.now(timezone.utc).isoformat()
        with self.lock:
            self.latest_score = score
            self.latest_features = features
            self.latest_timestamp = ts
            self.is_alert = is_alert
            self.score_history.append({"timestamp": ts, "score": score, "alert": is_alert})
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
                "latest_timestamp": self.latest_timestamp,
                "is_alert": self.is_alert,
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
):
    """Main scoring loop — collects messages, extracts features, scores."""
    log.info("Starting scoring loop (window=%.1fs, threshold=%.2f)", window_seconds, threshold)

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

                # Score
                prob = model.predict_proba(feature_vec)[0][1]
                is_alert = prob >= threshold

                state.update(prob, features, is_alert)

                if is_alert:
                    log.warning(
                        "🚨 ALERT! Score=%.3f (threshold=%.2f) | msgs=%d rate=%.1f",
                        prob, threshold,
                        features.get("msg_count", 0),
                        features.get("msg_rate", 0),
                    )
                else:
                    log.debug("Window OK: score=%.3f msgs=%d", prob, features.get("msg_count", 0))

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
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    parser.add_argument("--window", type=float, default=2.0)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--http-port", type=int, default=5001)
    args = parser.parse_args()

    # Load model
    model_path = Path(args.model_path)
    if not model_path.exists():
        log.warning("Model file not found: %s — using dummy model", model_path)
        # Create a simple dummy model for testing
        model = xgb.XGBClassifier(n_estimators=2, max_depth=1)
        # Train on minimal dummy data
        X_dummy = np.random.rand(20, len(FEATURE_COLUMNS))
        y_dummy = np.array([0] * 10 + [1] * 10)
        model.fit(X_dummy, y_dummy, verbose=False)
        log.info("Created dummy model — train a real one with: python -m detector.train_model")
    else:
        model = xgb.XGBClassifier()
        model.load_model(str(model_path))
        log.info("Loaded model from: %s", model_path)

    # Start HTTP server in background
    server = HTTPServer(("0.0.0.0", args.http_port), DetectorHandler)
    http_thread = threading.Thread(target=server.serve_forever, daemon=True)
    http_thread.start()
    log.info("HTTP API running on port %d", args.http_port)

    # Start alert writer in background
    alert_thread = threading.Thread(target=write_alerts_loop, daemon=True)
    alert_thread.start()

    # Run scoring loop (blocking)
    scoring_loop(model, args.log_path, args.window, args.threshold)


if __name__ == "__main__":
    main()
