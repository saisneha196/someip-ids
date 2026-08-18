"""
Local runner — starts the full IDS pipeline without Docker.

Runs these in parallel:
  1. Traffic simulator (generates normal + attack traffic to a local log file)
  2. Detector (XGBoost + IForest scoring loop with HTTP API on port 5001)
  3. Streamlit dashboard (http://localhost:8501)

Usage:
    python run_local.py
"""

import json
import os
import random
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proto.constants import (
    HVAC_SERVICE_ID, HVAC_METHODS,
    MEDIA_SERVICE_ID, MEDIA_METHODS,
    NAV_SERVICE_ID, NAV_METHODS,
)


LOG_DIR = Path(os.path.dirname(os.path.abspath(__file__))) / "local_logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_PATH = LOG_DIR / "traffic.jsonl"
ALERT_PATH = LOG_DIR / "alerts.jsonl"

# Clean previous run
LOG_PATH.write_text("")
ALERT_PATH.write_text("")

RUNNING = True


def signal_handler(sig, frame):
    global RUNNING
    print("\n🛑 Shutting down...")
    RUNNING = False
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# ======================================================================
# Traffic Simulator
# ======================================================================

def traffic_simulator():
    """Generates realistic traffic to the log file — normal + periodic attacks."""

    services = [
        (HVAC_SERVICE_ID, HVAC_METHODS, "172.20.0.10"),
        (MEDIA_SERVICE_ID, MEDIA_METHODS, "172.20.0.11"),
        (NAV_SERVICE_ID, NAV_METHODS, "172.20.0.12"),
    ]
    session_counter = 0
    cycle = 0

    print("📡 Traffic simulator started — writing to", LOG_PATH)

    while RUNNING:
        cycle += 1
        now = datetime.now(timezone.utc)

        # ---- Normal traffic (always) ----
        svc_id, methods, svc_ip = random.choice(services)
        method_name, method_id = random.choice(list(methods.items()))
        session_counter += 1

        # Request
        record = {
            "timestamp": now.isoformat(),
            "direction": "sent",
            "src_ip": "172.20.0.20",
            "dst_ip": svc_ip,
            "service_id": f"0x{svc_id:04X}",
            "method_id": f"0x{method_id:04X}",
            "client_id": "0x0010",
            "session_id": f"0x{session_counter & 0xFFFF:04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": random.randint(4, 16),
            "payload_hex": "",
            "label": "normal",
        }
        _write_record(record)

        # Response (slight delay)
        time.sleep(random.uniform(0.01, 0.03))
        now2 = datetime.now(timezone.utc)
        resp = {
            "timestamp": now2.isoformat(),
            "direction": "received",
            "src_ip": svc_ip,
            "dst_ip": "172.20.0.20",
            "service_id": f"0x{svc_id:04X}",
            "method_id": f"0x{method_id:04X}",
            "client_id": "0x0010",
            "session_id": f"0x{session_counter & 0xFFFF:04X}",
            "message_type": "RESPONSE",
            "return_code": "0x00",
            "payload_size": random.randint(4, 16),
            "payload_hex": "",
            "label": "normal",
        }
        _write_record(resp)

        # Occasional SD offer
        if random.random() < 0.1:
            sd = {
                "timestamp": now.isoformat(),
                "direction": "received",
                "src_ip": svc_ip,
                "dst_ip": "255.255.255.255",
                "service_id": "0xFFFF",
                "method_id": "0x8100",
                "client_id": "0x0000",
                "session_id": "0x0001",
                "message_type": "NOTIFICATION",
                "return_code": "0x00",
                "payload_size": 39,
                "payload_hex": "",
                "label": "normal",
            }
            _write_record(sd)

        # ---- Attack bursts every 20-30 seconds ----
        if cycle % 30 == 0 and cycle > 10:
            attack_type = random.choice(["flood", "replay", "spoofed_offer", "evasion_slow_flood"])
            print(f"  ⚡ Injecting {attack_type} attack at cycle {cycle}...")

            if attack_type == "flood":
                _inject_flood(50)
            elif attack_type == "replay":
                _inject_replay(8)
            elif attack_type == "spoofed_offer":
                _inject_spoofed_offers(5)
            elif attack_type == "evasion_slow_flood":
                _inject_evasion(12)

        time.sleep(random.uniform(0.3, 0.8))


def _write_record(record):
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def _inject_flood(count):
    for i in range(count):
        now = datetime.now(timezone.utc)
        r = {
            "timestamp": now.isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "172.20.0.10",
            "service_id": "0x1001",
            "method_id": f"0x{random.choice([0x0001, 0x0002]):04X}",
            "client_id": "0x00FF",
            "session_id": f"0x{random.randint(1, 0xFFFF):04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": random.randint(4, 32),
            "payload_hex": "",
            "label": "flood",
        }
        _write_record(r)
        time.sleep(0.005)


def _inject_replay(count):
    for i in range(count):
        now = datetime.now(timezone.utc)
        r = {
            "timestamp": now.isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "172.20.0.10",
            "service_id": "0x1001",
            "method_id": "0x0001",
            "client_id": "0x0010",
            "session_id": "0x0001",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": 6,
            "payload_hex": "000116410000",
            "label": "replay",
        }
        _write_record(r)
        time.sleep(0.1)


def _inject_spoofed_offers(count):
    for i in range(count):
        now = datetime.now(timezone.utc)
        r = {
            "timestamp": now.isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "255.255.255.255",
            "service_id": "0xFFFF",
            "method_id": "0x8100",
            "client_id": "0x0000",
            "session_id": f"0x{random.randint(1,100):04X}",
            "message_type": "NOTIFICATION",
            "return_code": "0x00",
            "payload_size": 55,
            "payload_hex": "",
            "label": "spoofed_offer",
        }
        _write_record(r)
        time.sleep(0.2)


def _inject_evasion(count):
    svc_ids = [0x1001, 0x2001, 0x3001]
    svc_ips = ["172.20.0.10", "172.20.0.11", "172.20.0.12"]
    session = random.randint(500, 900)
    for i in range(count):
        now = datetime.now(timezone.utc)
        idx = i % 3
        session += 1
        r = {
            "timestamp": now.isoformat(),
            "direction": "sent",
            "src_ip": "172.20.0.40",
            "dst_ip": svc_ips[idx],
            "service_id": f"0x{svc_ids[idx]:04X}",
            "method_id": f"0x{random.choice([0x0001, 0x0002]):04X}",
            "client_id": "0x0040",
            "session_id": f"0x{session:04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": random.randint(4, 12),
            "payload_hex": "",
            "label": "evasion_slow_flood",
        }
        _write_record(r)
        time.sleep(0.3)


# ======================================================================
# Detector (simplified — runs XGBoost inline)
# ======================================================================

def detector_loop():
    """Runs the scoring loop with HTTP API."""
    import numpy as np
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from detector.feature_extractor import compute_window_features, FEATURE_COLUMNS

    # Train a quick model on synthetic data
    try:
        import xgboost as xgb
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        # Generate training data
        print("🔬 Detector: training XGBoost + IForest models...")
        from detector.feature_extractor import extract_windows, load_traffic_log

        # Wait for enough data
        time.sleep(8)

        records = load_traffic_log(str(LOG_PATH))
        if len(records) < 10:
            time.sleep(5)
            records = load_traffic_log(str(LOG_PATH))

        df = extract_windows(records, window_seconds=2.0)
        if df.empty or len(df) < 4:
            print("🔬 Detector: not enough data yet, using dummy model")
            model = xgb.XGBClassifier(n_estimators=10, max_depth=3, use_label_encoder=False)
            X_dummy = np.random.rand(20, len(FEATURE_COLUMNS))
            y_dummy = np.array([0]*15 + [1]*5)
            model.fit(X_dummy, y_dummy, verbose=False)
            iforest_model = None
            scaler = None
        else:
            X = df[FEATURE_COLUMNS].values
            y = df["label"].values

            model = xgb.XGBClassifier(
                n_estimators=100, max_depth=6, learning_rate=0.1,
                objective="binary:logistic", eval_metric="logloss",
                random_state=42, use_label_encoder=False,
            )

            n_pos = max((y == 1).sum(), 1)
            n_neg = max((y == 0).sum(), 1)
            model.set_params(scale_pos_weight=n_neg / n_pos)
            model.fit(X, y, verbose=False)

            # Train IForest on normal-only
            X_normal = X[y == 0]
            if len(X_normal) > 3:
                scaler = StandardScaler()
                X_normal_scaled = scaler.fit_transform(X_normal)
                iforest_model = IsolationForest(
                    contamination=0.05, n_estimators=200, random_state=42
                )
                iforest_model.fit(X_normal_scaled)
                print(f"🔬 Detector: IForest trained on {len(X_normal)} normal windows")
            else:
                iforest_model = None
                scaler = None

            print(f"🔬 Detector: XGBoost trained on {len(df)} windows ({(y==0).sum()} normal, {(y==1).sum()} attack)")

    except ImportError:
        print("🔬 Detector: xgboost not installed, using random scores")
        model = None
        iforest_model = None
        scaler = None

    # Shared state
    state = {
        "latest_score": 0.0,
        "latest_iforest_score": 0.0,
        "latest_timestamp": "",
        "is_alert": False,
        "alert_source": "",
        "latest_features": {},
        "score_history": [],
        "alert_count": 0,
    }
    state_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/status":
                with state_lock:
                    data = dict(state)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(data, default=str).encode())
            elif self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            else:
                self.send_response(404)
                self.end_headers()
        def log_message(self, fmt, *args):
            pass

    server = HTTPServer(("0.0.0.0", 5001), Handler)
    http_thread = threading.Thread(target=server.serve_forever, daemon=True)
    http_thread.start()
    print("🔬 Detector: HTTP API running on http://localhost:5001")

    # Scoring loop
    window_seconds = 2.0
    threshold = 0.5
    window_buf = []
    window_start = time.time()
    last_pos = 0

    while RUNNING:
        try:
            if not LOG_PATH.exists():
                time.sleep(0.5)
                continue

            with open(LOG_PATH, "r") as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                last_pos = f.tell()

            for line in new_lines:
                try:
                    window_buf.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue

            if time.time() - window_start >= window_seconds:
                if window_buf:
                    features = compute_window_features(window_buf, window_seconds)
                    feature_vec = np.array([[features[col] for col in FEATURE_COLUMNS]])

                    # XGBoost score
                    if model:
                        xgb_prob = float(model.predict_proba(feature_vec)[0][1])
                    else:
                        xgb_prob = random.uniform(0, 0.3)

                    xgb_alert = xgb_prob >= threshold

                    # IForest score
                    if_score = 0.0
                    if_alert = False
                    if iforest_model and scaler:
                        vec_scaled = scaler.transform(feature_vec)
                        if_pred = iforest_model.predict(vec_scaled)
                        if_score = float(iforest_model.decision_function(vec_scaled)[0])
                        if_alert = bool(if_pred[0] == -1)

                    is_alert = xgb_alert or if_alert
                    alert_source = ""
                    if xgb_alert and if_alert:
                        alert_source = "both"
                    elif xgb_alert:
                        alert_source = "xgboost"
                    elif if_alert:
                        alert_source = "iforest"

                    ts = datetime.now(timezone.utc).isoformat()

                    with state_lock:
                        state["latest_score"] = xgb_prob
                        state["latest_iforest_score"] = if_score
                        state["latest_timestamp"] = ts
                        state["is_alert"] = is_alert
                        state["alert_source"] = alert_source
                        state["latest_features"] = {k: round(v, 4) if isinstance(v, float) else v for k, v in features.items()}
                        state["score_history"].append({
                            "timestamp": ts, "score": xgb_prob,
                            "iforest_score": if_score,
                            "alert": is_alert, "alert_source": alert_source,
                        })
                        if len(state["score_history"]) > 500:
                            state["score_history"] = state["score_history"][-500:]
                        if is_alert:
                            state["alert_count"] += 1

                    if is_alert:
                        print(f"  🚨 ALERT [{alert_source}] XGB={xgb_prob:.3f} IF={if_score:.3f} msgs={features.get('msg_count', 0)}")

                window_buf = []
                window_start = time.time()

            time.sleep(0.1)

        except Exception as e:
            print(f"  Detector error: {e}")
            time.sleep(1)


# ======================================================================
# Main
# ======================================================================

def main():
    print()
    print("█" * 60)
    print("█  SOME/IP IDS — Local Runner                          █")
    print("█" * 60)
    print()
    print(f"  📁 Traffic log:  {LOG_PATH}")
    print(f"  🔬 Detector API: http://localhost:5001/status")
    print(f"  📊 Dashboard:    http://localhost:8501")
    print(f"  Press Ctrl+C to stop")
    print()

    # Start traffic simulator
    sim_thread = threading.Thread(target=traffic_simulator, daemon=True)
    sim_thread.start()

    # Start detector
    det_thread = threading.Thread(target=detector_loop, daemon=True)
    det_thread.start()

    # Wait a moment for data to start flowing
    time.sleep(2)

    # Start Streamlit dashboard
    env = os.environ.copy()
    env["DETECTOR_URL"] = "http://localhost:5001"
    env["LOG_PATH"] = str(LOG_PATH)

    print("📊 Starting Streamlit dashboard...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "dashboard/app.py",
         "--server.port", "8501",
         "--server.headless", "true",
         "--browser.gatherUsageStats", "false"],
        env=env,
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )

    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("\n🛑 Stopped.")


if __name__ == "__main__":
    main()
