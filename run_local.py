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

        # ---- Attack bursts every ~20-30 seconds ----
        if cycle % 40 == 0 and cycle > 20:
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

def _generate_synthetic_attack_features(n_normal_windows: int, feature_columns: list) -> list:
    """Generate synthetic attack feature vectors to pre-seed the model.

    Creates realistic attack-like feature profiles for:
      - Flood attacks   (high msg_count, high burst rate, low entropy)
      - Replay attacks  (low unique_sessions, low entropy, repeated IDs)
      - Spoofed offers  (high sd_offer_count, high notification_ratio)
      - Evasion/slow    (moderate rate from unusual IPs)

    Returns a list of (feature_dict, label) tuples.
    """
    import numpy as np
    synthetic = []

    # --- Flood attack profiles (high volume bursts) ---
    for _ in range(max(n_normal_windows, 8)):
        synthetic.append(({
            "msg_count": np.random.uniform(30, 120),
            "msg_rate": np.random.uniform(6.0, 24.0),
            "unique_services": np.random.choice([1, 2]),
            "unique_methods": np.random.choice([1, 2]),
            "unique_sessions": np.random.uniform(15, 80),
            "session_id_entropy": np.random.uniform(3.5, 6.5),
            "sd_offer_count": 0,
            "sd_offer_rate": 0.0,
            "mean_payload_size": np.random.uniform(4, 32),
            "std_payload_size": np.random.uniform(0, 12),
            "request_response_ratio": np.random.uniform(5.0, 50.0),
            "notification_ratio": np.random.uniform(0, 0.05),
            "unique_src_ips": np.random.choice([1, 2]),
            "max_burst_rate": np.random.uniform(50.0, 500.0),
        }, 1))

    # --- Replay attack profiles (stale session IDs) ---
    for _ in range(max(n_normal_windows // 2, 5)):
        synthetic.append(({
            "msg_count": np.random.uniform(5, 20),
            "msg_rate": np.random.uniform(1.0, 4.0),
            "unique_services": 1,
            "unique_methods": 1,
            "unique_sessions": np.random.choice([1, 2]),  # Very few unique sessions
            "session_id_entropy": np.random.uniform(0.0, 0.5),  # Very low entropy
            "sd_offer_count": 0,
            "sd_offer_rate": 0.0,
            "mean_payload_size": 6,
            "std_payload_size": 0.0,
            "request_response_ratio": np.random.uniform(3.0, 20.0),
            "notification_ratio": 0.0,
            "unique_src_ips": 1,
            "max_burst_rate": np.random.uniform(5.0, 30.0),
        }, 1))

    # --- Spoofed SD offer profiles ---
    for _ in range(max(n_normal_windows // 2, 5)):
        synthetic.append(({
            "msg_count": np.random.uniform(3, 15),
            "msg_rate": np.random.uniform(0.6, 3.0),
            "unique_services": np.random.choice([1, 2]),
            "unique_methods": 1,
            "unique_sessions": np.random.uniform(1, 10),
            "session_id_entropy": np.random.uniform(0.5, 2.5),
            "sd_offer_count": np.random.uniform(3, 15),  # Many SD offers
            "sd_offer_rate": np.random.uniform(0.6, 3.0),
            "mean_payload_size": np.random.uniform(30, 60),
            "std_payload_size": np.random.uniform(0, 10),
            "request_response_ratio": np.random.uniform(0.0, 1.0),
            "notification_ratio": np.random.uniform(0.5, 1.0),  # High notification ratio
            "unique_src_ips": 1,
            "max_burst_rate": np.random.uniform(5.0, 30.0),
        }, 1))

    # --- Evasion / slow flood profiles ---
    for _ in range(max(n_normal_windows // 2, 5)):
        synthetic.append(({
            "msg_count": np.random.uniform(8, 25),
            "msg_rate": np.random.uniform(1.6, 5.0),
            "unique_services": np.random.choice([2, 3]),
            "unique_methods": np.random.choice([1, 2]),
            "unique_sessions": np.random.uniform(6, 20),
            "session_id_entropy": np.random.uniform(2.0, 4.0),
            "sd_offer_count": 0,
            "sd_offer_rate": 0.0,
            "mean_payload_size": np.random.uniform(4, 12),
            "std_payload_size": np.random.uniform(0, 5),
            "request_response_ratio": np.random.uniform(4.0, 25.0),  # Requests without responses
            "notification_ratio": 0.0,
            "unique_src_ips": np.random.choice([2, 3]),  # New source IPs
            "max_burst_rate": np.random.uniform(10.0, 40.0),
        }, 1))

    return synthetic


def _train_models(log_path, feature_columns, window_seconds=5.0):
    """Train XGBoost + IForest on accumulated log data with synthetic attack seeding.

    Returns (model, iforest_model, scaler, training_info_str).
    """
    import numpy as np
    import xgboost as xgb
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from detector.feature_extractor import extract_windows, load_traffic_log, FEATURE_COLUMNS

    records = load_traffic_log(str(log_path))
    if len(records) < 5:
        return None, None, None, "not enough records"

    df = extract_windows(records, window_seconds=window_seconds)
    if df.empty or len(df) < 4:
        return None, None, None, "not enough windows"

    X_real = df[FEATURE_COLUMNS].values
    y_real = df["label"].values
    n_real_normal = int((y_real == 0).sum())
    n_real_attack = int((y_real == 1).sum())

    # --- Fix 4: Pre-seed synthetic attack features ---
    # Always generate synthetic attacks so the model knows what to look for,
    # even when no real attacks have been seen yet
    synthetic_pairs = _generate_synthetic_attack_features(max(n_real_normal, 10), FEATURE_COLUMNS)
    X_synth = np.array([[p[0][col] for col in FEATURE_COLUMNS] for p in synthetic_pairs])
    y_synth = np.array([p[1] for p in synthetic_pairs])

    # Combine real + synthetic data
    X_combined = np.vstack([X_real, X_synth])
    y_combined = np.concatenate([y_real, y_synth])

    n_pos = max((y_combined == 1).sum(), 1)
    n_neg = max((y_combined == 0).sum(), 1)

    model = xgb.XGBClassifier(
        n_estimators=100, max_depth=6, learning_rate=0.1,
        scale_pos_weight=n_neg / n_pos,
        objective="binary:logistic", eval_metric="logloss",
        random_state=42, use_label_encoder=False,
    )
    model.fit(X_combined, y_combined, verbose=False)

    # --- Fix 3: Better IForest configuration ---
    # Train IForest on real normal-only data
    X_normal = X_real[y_real == 0]
    if len(X_normal) >= 10:  # Require ≥10 real normal windows (ideally ≥30)
        scaler = StandardScaler()
        X_normal_scaled = scaler.fit_transform(X_normal)
        iforest_model = IsolationForest(
            contamination=0.10,  # Raised from 0.01 — expect up to 10% anomalies
            n_estimators=200,
            random_state=42,
        )
        iforest_model.fit(X_normal_scaled)
    else:
        iforest_model = None
        scaler = None

    info = (f"{len(df)} windows ({n_real_normal} normal, {n_real_attack} attack) "
            f"+ {len(synthetic_pairs)} synthetic attack samples"
            + (f", IForest on {len(X_normal)} normal" if iforest_model else ", IForest skipped (need ≥10 normal)"))
    return model, iforest_model, scaler, info


def detector_loop():
    """Runs the scoring loop with HTTP API.

    Fixes applied:
      Fix 1: Delayed training — waits for attack data or 90s max
      Fix 2: Periodic retraining — retrains every 60s on accumulated log
      Fix 3: Better IForest — contamination=0.10, threshold=-0.02, ≥10 windows
      Fix 4: Synthetic attack seeding — generates attack profiles for initial training
      Bonus: Scoring window increased from 2s → 5s for stronger signal
    """
    import numpy as np
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from detector.feature_extractor import compute_window_features, FEATURE_COLUMNS

    model = None
    iforest_model = None
    scaler = None

    try:
        import xgboost as xgb
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        from detector.feature_extractor import extract_windows, load_traffic_log

        # --- Fix 1: Wait until attacks have been injected (or 90s max) ---
        print("🔬 Detector: waiting for training data (need attack samples)...")
        train_deadline = time.time() + 90  # Max wait: 90 seconds
        min_wait = 30  # Minimum wait to accumulate enough data
        time.sleep(min_wait)

        while time.time() < train_deadline and RUNNING:
            records = load_traffic_log(str(LOG_PATH))
            # Check if we have any attack-labeled records
            attack_labels = [r for r in records if r.get("label", "normal") != "normal"]
            n_records = len(records)
            n_attacks = len(attack_labels)
            if n_attacks > 0 and n_records >= 30:
                print(f"🔬 Detector: found {n_attacks} attack records in {n_records} total — training now")
                break
            time.sleep(5)
        else:
            records = load_traffic_log(str(LOG_PATH))
            print(f"🔬 Detector: training deadline reached with {len(records)} records (will use synthetic attacks)")

        # Initial training
        model, iforest_model, scaler, info = _train_models(LOG_PATH, FEATURE_COLUMNS, window_seconds=5.0)
        if model:
            print(f"🔬 Detector: INITIAL training complete — {info}")
        else:
            print(f"🔬 Detector: initial training skipped ({info}), will retry on next retrain cycle")

    except ImportError:
        print("🔬 Detector: xgboost not installed, using random scores")

    # Attack type display names
    ATTACK_TYPE_LABELS = {
        "flood": "🔴 Flood Attack",
        "replay": "🟠 Replay Attack",
        "spoofed_offer": "🟣 Spoofed Offer",
        "evasion_slow_flood": "💗 Evasion (Slow Flood)",
        "evasion_spaced_replay": "💗 Evasion (Spaced Replay)",
        "malformed_sd": "🟡 Malformed SD",
    }

    # Shared state
    state = {
        "latest_score": 0.0,
        "latest_iforest_score": 0.0,
        "latest_timestamp": "",
        "is_alert": False,
        "alert_source": "",
        "attack_type": "",
        "attack_types_in_window": {},
        "latest_features": {},
        "score_history": [],
        "alert_count": 0,
        "attack_type_counts": {"flood": 0, "replay": 0, "spoofed_offer": 0, "evasion_slow_flood": 0},
        # Per-service traffic stats (updated each window)
        "services": {
            "0x1001": {"name": "HVAC", "msg_count": 0, "attack_count": 0, "active": False, "under_attack": False},
            "0x2001": {"name": "Media", "msg_count": 0, "attack_count": 0, "active": False, "under_attack": False},
            "0x3001": {"name": "Navigation", "msg_count": 0, "attack_count": 0, "active": False, "under_attack": False},
        },
        "sd_active": False,
        "total_window_msgs": 0,
        "model_version": 1,
        "last_retrain": datetime.now(timezone.utc).isoformat(),
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

    # --- Fix 2: Periodic retraining in background thread ---
    RETRAIN_INTERVAL_SECONDS = 60  # Retrain every 60 seconds

    def _retrain_loop():
        nonlocal model, iforest_model, scaler
        while RUNNING:
            time.sleep(RETRAIN_INTERVAL_SECONDS)
            if not RUNNING:
                break
            try:
                new_model, new_if, new_scaler, info = _train_models(
                    LOG_PATH, FEATURE_COLUMNS, window_seconds=5.0
                )
                if new_model:
                    model = new_model
                    iforest_model = new_if
                    scaler = new_scaler
                    with state_lock:
                        state["model_version"] = state.get("model_version", 1) + 1
                        state["last_retrain"] = datetime.now(timezone.utc).isoformat()
                    print(f"  🔄 RETRAINED (v{state['model_version']}): {info}")
            except Exception as e:
                print(f"  ⚠ Retrain error: {e}")

    retrain_thread = threading.Thread(target=_retrain_loop, daemon=True)
    retrain_thread.start()

    # Scoring loop
    # Fix: increased window from 2s → 5s to capture more attack signal
    window_seconds = 5.0
    threshold = 0.5
    # --- Fix 3: Lower IForest threshold ---
    IF_SCORE_THRESHOLD = -0.02  # Lowered from -0.05 to catch more anomalies
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
                        if_score = float(iforest_model.decision_function(vec_scaled)[0])
                        if_alert = if_score < IF_SCORE_THRESHOLD

                    is_alert = xgb_alert or if_alert
                    alert_source = ""
                    if xgb_alert and if_alert:
                        alert_source = "both"
                    elif xgb_alert:
                        alert_source = "xgboost"
                    elif if_alert:
                        alert_source = "iforest"

                    ts = datetime.now(timezone.utc).isoformat()

                    # --- Classify attack type from window messages ---
                    attack_labels_in_window = {}
                    for msg in window_buf:
                        lbl = msg.get("label", "normal")
                        if lbl != "normal":
                            attack_labels_in_window[lbl] = attack_labels_in_window.get(lbl, 0) + 1

                    # Determine dominant attack type
                    if attack_labels_in_window:
                        dominant_attack = max(attack_labels_in_window, key=attack_labels_in_window.get)
                    else:
                        dominant_attack = ""

                    # Get display name
                    attack_type_display = ATTACK_TYPE_LABELS.get(dominant_attack, dominant_attack) if dominant_attack else ""

                    with state_lock:
                        state["latest_score"] = xgb_prob
                        state["latest_iforest_score"] = if_score
                        state["latest_timestamp"] = ts
                        state["is_alert"] = is_alert
                        state["alert_source"] = alert_source
                        state["attack_type"] = dominant_attack
                        state["attack_type_display"] = attack_type_display
                        state["attack_types_in_window"] = attack_labels_in_window
                        state["latest_features"] = {k: round(v, 4) if isinstance(v, float) else v for k, v in features.items()}
                        state["score_history"].append({
                            "timestamp": ts, "score": xgb_prob,
                            "iforest_score": if_score,
                            "alert": is_alert, "alert_source": alert_source,
                            "attack_type": dominant_attack,
                        })
                        if len(state["score_history"]) > 500:
                            state["score_history"] = state["score_history"][-500:]
                        if is_alert:
                            state["alert_count"] += 1
                            # Track cumulative attack type counts
                            if dominant_attack in state["attack_type_counts"]:
                                state["attack_type_counts"][dominant_attack] += 1

                        # Update per-service stats from this window
                        svc_counts = {"0x1001": 0, "0x2001": 0, "0x3001": 0}
                        svc_attacks = {"0x1001": 0, "0x2001": 0, "0x3001": 0}
                        sd_active = False
                        for msg in window_buf:
                            sid = msg.get("service_id", "")
                            lbl = msg.get("label", "normal")
                            if sid in svc_counts:
                                svc_counts[sid] += 1
                                if lbl != "normal":
                                    svc_attacks[sid] += 1
                            if sid == "0xFFFF":
                                sd_active = True
                        for sid in ["0x1001", "0x2001", "0x3001"]:
                            state["services"][sid]["msg_count"] = svc_counts[sid]
                            state["services"][sid]["attack_count"] = svc_attacks[sid]
                            state["services"][sid]["active"] = svc_counts[sid] > 0
                            state["services"][sid]["under_attack"] = svc_attacks[sid] > 0
                        state["sd_active"] = sd_active
                        state["total_window_msgs"] = len(window_buf)

                    if is_alert:
                        atk_str = f" | {attack_type_display}" if attack_type_display else ""
                        print(f"  🚨 ALERT [{alert_source}] XGB={xgb_prob:.3f} IF={if_score:.3f} msgs={features.get('msg_count', 0)}{atk_str}")

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
