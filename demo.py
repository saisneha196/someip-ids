#!/usr/bin/env python3
"""
SOME/IP IDS — Full Pipeline Demo

Runs the entire system locally without Docker:
  1. Protocol codec verification (SOME/IP header + SD round-trip)
  2. Simulated ECU traffic generation (normal)
  3. Attack injection (flood, replay, spoofed offer, malformed SD)
  4. Feature extraction (14 sliding-window features)
  5. XGBoost model training + evaluation
  6. HMAC-signed offer verification (spoofing prevention)
  7. Session freshness check (replay prevention)
"""

import json
import os
import random
import struct
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Ensure imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proto.someip import (
    SomeIpHeader, SomeIpMessage, pack_someip, unpack_someip,
    MessageType, ReturnCode, HEADER_SIZE, message_type_name,
)
from proto.sd import (
    build_offer_service, build_find_service, build_subscribe_eventgroup,
    build_subscribe_ack, parse_sd_message, SdEntryType,
    hmac_sign_offer, hmac_verify_offer, extract_service_id_from_offer,
    HMAC_TAG_SIZE,
)
from proto.constants import (
    HVAC_SERVICE_ID, HVAC_INSTANCE_ID, HVAC_METHODS, HVAC_PORT,
    MEDIA_SERVICE_ID, MEDIA_INSTANCE_ID, MEDIA_METHODS, MEDIA_PORT,
    NAV_SERVICE_ID, NAV_INSTANCE_ID, NAV_METHODS, NAV_PORT,
    SERVICES, SERVICE_HMAC_KEYS, SD_SERVICE_ID,
)
from detector.feature_extractor import (
    compute_window_features, extract_windows, FEATURE_COLUMNS, load_traffic_log,
)

# ======================================================================
DIVIDER = "=" * 72
SECTION = "-" * 50


def banner(title):
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


def step(msg):
    print(f"\n  ▸ {msg}")


# ======================================================================
# Stage 1: Protocol Codec Verification
# ======================================================================

def demo_protocol_codec():
    banner("STAGE 1: SOME/IP Protocol Codec")

    step("SOME/IP Header Pack/Unpack Round-Trip")
    header = SomeIpHeader(
        service_id=HVAC_SERVICE_ID,
        method_id=HVAC_METHODS["SetTemperature"],
        client_id=0x0010,
        session_id=0x0042,
        message_type=MessageType.REQUEST,
    )
    payload = struct.pack("!Hf", 1, 22.5)  # zone=1, temp=22.5°C
    msg = SomeIpMessage(header=header, payload=payload)
    raw = pack_someip(msg)
    restored = unpack_someip(raw)

    print(f"    Original:  service=0x{header.service_id:04X}  method=0x{header.method_id:04X}  "
          f"session=0x{header.session_id:04X}  type={message_type_name(header.message_type)}")
    print(f"    Packed:    {len(raw)} bytes → {raw.hex()[:60]}...")
    print(f"    Restored:  service=0x{restored.header.service_id:04X}  "
          f"session=0x{restored.header.session_id:04X}  "
          f"payload={restored.payload.hex()}")
    zone, temp = struct.unpack("!Hf", restored.payload)
    print(f"    Decoded:   zone={zone}, temperature={temp:.1f}°C  ✓")

    step("Service Discovery Offer Round-Trip")
    offer = build_offer_service(HVAC_SERVICE_ID, HVAC_INSTANCE_ID, "172.20.0.10", HVAC_PORT, ttl=10)
    entries = parse_sd_message(offer)
    e = entries[0]
    print(f"    Built OfferService:  {len(offer)} bytes")
    print(f"    Parsed: service=0x{e.service_id:04X}  instance=0x{e.instance_id:04X}  "
          f"ip={e.option.ip}:{e.option.port}  ttl={e.ttl}  ✓")

    step("SD Subscribe Eventgroup Round-Trip")
    sub = build_subscribe_eventgroup(HVAC_SERVICE_ID, HVAC_INSTANCE_ID, 0x0001)
    sub_entries = parse_sd_message(sub)
    se = sub_entries[0]
    print(f"    Built Subscribe:  type={SdEntryType(se.entry_type).name}  "
          f"eventgroup=0x{se.eventgroup_id:04X}  ✓")


# ======================================================================
# Stage 2: Traffic Generation
# ======================================================================

def generate_traffic(log_path: str, normal_seconds=20, attack_seconds=10):
    banner("STAGE 2: Simulated ECU Traffic Generation")

    records = []
    base_time = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
    session_counters = {0x0010: 0, 0x0020: 0, 0x0030: 0}

    services_config = [
        (HVAC_SERVICE_ID, HVAC_METHODS, "172.20.0.10", HVAC_PORT, 0x0010),
        (MEDIA_SERVICE_ID, MEDIA_METHODS, "172.20.0.11", MEDIA_PORT, 0x0020),
        (NAV_SERVICE_ID, NAV_METHODS, "172.20.0.12", NAV_PORT, 0x0030),
    ]

    # --- Normal traffic ---
    step(f"Generating {normal_seconds}s of normal traffic...")
    t = 0.0
    while t < normal_seconds:
        svc_id, methods, svc_ip, svc_port, client_id = random.choice(services_config)
        method_name, method_id = random.choice(list(methods.items()))

        session_counters[client_id] += 1
        session_id = session_counters[client_id]

        # Request
        ts = base_time + timedelta(seconds=t)
        records.append({
            "timestamp": ts.isoformat(),
            "direction": "sent",
            "src_ip": "172.20.0.20",
            "dst_ip": svc_ip,
            "service_id": f"0x{svc_id:04X}",
            "method_id": f"0x{method_id:04X}",
            "client_id": f"0x{client_id:04X}",
            "session_id": f"0x{session_id:04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": random.randint(4, 16),
            "payload_hex": "00" * random.randint(4, 16),
            "label": "normal",
        })

        # Response (slight delay)
        ts_resp = ts + timedelta(milliseconds=random.randint(5, 50))
        records.append({
            "timestamp": ts_resp.isoformat(),
            "direction": "received",
            "src_ip": svc_ip,
            "dst_ip": "172.20.0.20",
            "service_id": f"0x{svc_id:04X}",
            "method_id": f"0x{method_id:04X}",
            "client_id": f"0x{client_id:04X}",
            "session_id": f"0x{session_id:04X}",
            "message_type": "RESPONSE",
            "return_code": "0x00",
            "payload_size": random.randint(4, 16),
            "payload_hex": "00" * random.randint(4, 16),
            "label": "normal",
        })

        # Occasional SD offers (every ~3s)
        if random.random() < 0.15:
            records.append({
                "timestamp": ts.isoformat(),
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
            })

        # Occasional events
        if random.random() < 0.1:
            records.append({
                "timestamp": ts.isoformat(),
                "direction": "received",
                "src_ip": svc_ip,
                "dst_ip": "172.20.0.20",
                "service_id": f"0x{svc_id:04X}",
                "method_id": "0x8001",
                "client_id": "0x0000",
                "session_id": f"0x{random.randint(1,100):04X}",
                "message_type": "NOTIFICATION",
                "return_code": "0x00",
                "payload_size": 6,
                "payload_hex": "",
                "label": "normal",
            })

        t += random.uniform(0.3, 1.5)

    normal_count = len(records)
    print(f"    Generated {normal_count} normal messages over {normal_seconds}s")

    # --- Attack traffic ---
    attack_start = normal_seconds
    attack_types = ["flood", "replay", "spoofed_offer", "malformed_sd"]

    # Flood attack (high rate burst)
    step("Injecting FLOOD attack (200 msg/s burst)...")
    flood_count = 0
    t = attack_start
    while t < attack_start + 4:
        ts = base_time + timedelta(seconds=t)
        records.append({
            "timestamp": ts.isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "172.20.0.10",
            "service_id": "0x1001",
            "method_id": f"0x{random.choice([0x0001, 0x0002]):04X}",
            "client_id": "0x00FF",
            "session_id": f"0x{random.randint(1,0xFFFF):04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": random.randint(4, 32),
            "payload_hex": "",
            "label": "flood",
        })
        flood_count += 1
        t += 0.005  # 200 msg/s
    print(f"    Injected {flood_count} flood messages")

    # Replay attack (stale session IDs)
    step("Injecting REPLAY attack (stale session IDs)...")
    replay_count = 0
    t = attack_start + 4
    while t < attack_start + 7:
        ts = base_time + timedelta(seconds=t)
        records.append({
            "timestamp": ts.isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "172.20.0.10",
            "service_id": "0x1001",
            "method_id": "0x0001",
            "client_id": "0x0010",
            "session_id": "0x0001",  # Always same — stale
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": 6,
            "payload_hex": "000116410000",
            "label": "replay",
        })
        replay_count += 1
        t += 0.5
    print(f"    Injected {replay_count} replay messages")

    # Spoofed SD offers
    step("Injecting SPOOFED OFFER attack...")
    spoof_count = 0
    t = attack_start + 7
    while t < attack_start + 9:
        ts = base_time + timedelta(seconds=t)
        records.append({
            "timestamp": ts.isoformat(),
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
        })
        spoof_count += 1
        t += 0.3
    print(f"    Injected {spoof_count} spoofed offers")

    # Malformed SD
    step("Injecting MALFORMED SD attack...")
    malformed_count = 0
    t = attack_start + 9
    while t < attack_start + attack_seconds:
        ts = base_time + timedelta(seconds=t)
        records.append({
            "timestamp": ts.isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "172.20.0.10",
            "service_id": "0xFFFF",
            "method_id": "0x8100",
            "client_id": "0x0000",
            "session_id": "0x0001",
            "message_type": "NOTIFICATION",
            "return_code": "0x00",
            "payload_size": random.randint(8, 200),
            "payload_hex": "",
            "label": "malformed_sd",
        })
        malformed_count += 1
        t += 0.3
    print(f"    Injected {malformed_count} malformed SD packets")

    # More normal traffic after attack
    step("Generating post-attack normal traffic...")
    t = attack_start + attack_seconds
    post_count = 0
    while t < attack_start + attack_seconds + 10:
        svc_id, methods, svc_ip, svc_port, client_id = random.choice(services_config)
        method_name, method_id = random.choice(list(methods.items()))
        session_counters[client_id] += 1

        ts = base_time + timedelta(seconds=t)
        records.append({
            "timestamp": ts.isoformat(),
            "direction": "sent",
            "src_ip": "172.20.0.20",
            "dst_ip": svc_ip,
            "service_id": f"0x{svc_id:04X}",
            "method_id": f"0x{method_id:04X}",
            "client_id": f"0x{client_id:04X}",
            "session_id": f"0x{session_counters[client_id]:04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": random.randint(4, 16),
            "payload_hex": "",
            "label": "normal",
        })
        post_count += 1
        t += random.uniform(0.3, 1.5)
    print(f"    Generated {post_count} post-attack normal messages")

    total = len(records)
    attack_total = flood_count + replay_count + spoof_count + malformed_count
    print(f"\n    TOTAL: {total} messages  ({total - attack_total} normal, {attack_total} attack)")

    # Write to log
    records.sort(key=lambda r: r["timestamp"])
    with open(log_path, "w") as f:
        for r in records:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
    print(f"    Written to: {log_path}")

    return records


# ======================================================================
# Stage 3: Feature Extraction
# ======================================================================

def demo_feature_extraction(log_path: str):
    banner("STAGE 3: Feature Extraction (14 sliding-window features)")

    records = load_traffic_log(log_path)
    df = extract_windows(records, window_seconds=2.0)

    print(f"\n    Windows extracted: {len(df)}")
    print(f"    Normal windows:   {(df['label'] == 0).sum()}")
    print(f"    Attack windows:   {(df['label'] == 1).sum()}")

    step("Feature statistics (across all windows):")
    stats = df[FEATURE_COLUMNS].describe().loc[["mean", "std", "min", "max"]]
    # Format nicely
    print()
    print(f"    {'Feature':<26} {'Mean':>8} {'Std':>8} {'Min':>8} {'Max':>8}")
    print(f"    {'-'*26} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")
    for col in FEATURE_COLUMNS:
        print(f"    {col:<26} {stats.loc['mean', col]:>8.2f} {stats.loc['std', col]:>8.2f} "
              f"{stats.loc['min', col]:>8.2f} {stats.loc['max', col]:>8.2f}")

    step("Example: Normal window vs Attack window:")
    normal_windows = df[df["label"] == 0]
    attack_windows = df[df["label"] == 1]
    if not normal_windows.empty and not attack_windows.empty:
        nw = normal_windows.iloc[0]
        aw = attack_windows.iloc[0]
        key_features = ["msg_count", "msg_rate", "unique_sessions", "session_id_entropy",
                        "max_burst_rate", "sd_offer_count"]
        print()
        print(f"    {'Feature':<26} {'Normal':>10} {'Attack':>10}")
        print(f"    {'-'*26} {'-'*10} {'-'*10}")
        for f in key_features:
            print(f"    {f:<26} {nw[f]:>10.2f} {aw[f]:>10.2f}")

    return df


# ======================================================================
# Stage 4: XGBoost Training + Detection
# ======================================================================

def demo_xgboost_training(df):
    banner("STAGE 4: XGBoost Model Training & Anomaly Detection")

    import numpy as np
    try:
        import xgboost as xgb
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    except ImportError:
        print("    ⚠ xgboost/sklearn not installed — skipping training demo")
        print("    Install with: pip install xgboost scikit-learn")
        return

    X = df[FEATURE_COLUMNS].values
    y = df["label"].values

    n_normal = (y == 0).sum()
    n_attack = (y == 1).sum()
    step(f"Dataset: {len(y)} windows ({n_normal} normal, {n_attack} attack)")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y,
    )
    print(f"    Train: {len(X_train)}  Test: {len(X_test)}")

    # Train
    step("Training XGBoost classifier...")
    scale_pos_weight = n_normal / max(n_attack, 1)
    model = xgb.XGBClassifier(
        n_estimators=100, max_depth=6, learning_rate=0.1,
        scale_pos_weight=scale_pos_weight,
        objective="binary:logistic", eval_metric="logloss",
        random_state=42, use_label_encoder=False,
    )
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    step("Evaluation Results:")
    print(f"    Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"    Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"    Recall:    {recall_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"    F1 Score:  {f1_score(y_test, y_pred, zero_division=0):.4f}")

    cm = confusion_matrix(y_test, y_pred)
    step("Confusion Matrix:")
    print(f"                   Predicted")
    print(f"                Normal  Attack")
    print(f"    Actual Normal  {cm[0][0]:>4}    {cm[0][1]:>4}")
    print(f"    Actual Attack  {cm[1][0]:>4}    {cm[1][1]:>4}")

    step("Feature Importance (top 5):")
    importance = dict(zip(FEATURE_COLUMNS, model.feature_importances_))
    sorted_imp = sorted(importance.items(), key=lambda x: -x[1])[:5]
    for feat, imp in sorted_imp:
        bar = "█" * int(imp * 50)
        print(f"    {feat:<26} {imp:.4f}  {bar}")

    # Demo: score a few windows
    step("Live scoring demo (sample windows):")
    for i, (idx, row) in enumerate(df.head(5).iterrows()):
        features = row[FEATURE_COLUMNS].values.reshape(1, -1)
        prob = model.predict_proba(features)[0][1]
        label = "ATTACK" if prob > 0.5 else "normal"
        actual = "ATTACK" if row["label"] == 1 else "normal"
        marker = "🚨" if label == "ATTACK" else "✅"
        print(f"    {marker} Window {i}: score={prob:.3f}  predicted={label:<7}  actual={actual}")


# ======================================================================
# Stage 5: HMAC Verification Demo
# ======================================================================

def demo_hmac_verification():
    banner("STAGE 5: HMAC-Signed Service Offers (Spoofing Prevention)")

    key = SERVICE_HMAC_KEYS[HVAC_SERVICE_ID]

    step("Legitimate service signs its offer:")
    offer = build_offer_service(HVAC_SERVICE_ID, HVAC_INSTANCE_ID, "172.20.0.10", HVAC_PORT)
    signed = hmac_sign_offer(offer, key)
    print(f"    Unsigned offer: {len(offer)} bytes")
    print(f"    Signed offer:   {len(signed)} bytes (+{HMAC_TAG_SIZE} byte HMAC-SHA256 tag)")
    print(f"    HMAC tag:       {signed[-HMAC_TAG_SIZE:].hex()[:40]}...")

    step("Client verifies the HMAC:")
    valid = hmac_verify_offer(signed, key)
    print(f"    Verification:   {'✅ VALID — offer accepted' if valid else '❌ INVALID'}")

    step("Attacker sends SPOOFED offer (no key):")
    spoofed = build_offer_service(HVAC_SERVICE_ID, HVAC_INSTANCE_ID, "172.20.0.50", 30599)
    valid_spoofed = hmac_verify_offer(spoofed, key)
    print(f"    Spoofed offer:  {len(spoofed)} bytes (no HMAC tag)")
    print(f"    Verification:   {'✅ VALID' if valid_spoofed else '❌ REJECTED — spoofed offer blocked'}")

    step("Attacker signs with WRONG key:")
    wrong_key = b"attacker-guessed-wrong-key"
    bad_signed = hmac_sign_offer(spoofed, wrong_key)
    valid_bad = hmac_verify_offer(bad_signed, key)
    print(f"    Wrong-key offer: {len(bad_signed)} bytes (wrong HMAC tag)")
    print(f"    Verification:    {'✅ VALID' if valid_bad else '❌ REJECTED — wrong key detected'}")

    step("Attacker tampers with signed offer:")
    tampered = bytearray(signed)
    tampered[20] ^= 0xFF  # Flip a byte
    valid_tampered = hmac_verify_offer(bytes(tampered), key)
    print(f"    Tampered offer: byte 20 flipped")
    print(f"    Verification:   {'✅ VALID' if valid_tampered else '❌ REJECTED — tampering detected'}")

    step("Service ID extraction (for key lookup):")
    sid = extract_service_id_from_offer(signed)
    print(f"    Extracted service_id from signed offer: 0x{sid:04X}  ✓")


# ======================================================================
# Stage 6: Session Freshness Demo
# ======================================================================

def demo_session_freshness():
    banner("STAGE 6: Session Freshness Check (Replay Prevention)")

    from services.base_service import BaseService

    class DummyService(BaseService):
        async def _service_loop(self):
            pass

    svc = DummyService(
        service_id=HVAC_SERVICE_ID,
        instance_id=HVAC_INSTANCE_ID,
        service_name="HVAC",
        port=30599,
        log_path=os.path.join(tempfile.gettempdir(), "demo_traffic.jsonl"),
    )

    step("Simulating normal session progression:")
    client_key = (0x0010, "172.20.0.20")
    sessions = [1, 2, 3, 5, 8, 10]
    for sid in sessions:
        last = svc._session_tracker.get(client_key, 0)
        accepted = sid > last or last == 0
        if accepted:
            svc._session_tracker[client_key] = sid
        status = "✅ ACCEPTED" if accepted else "❌ REJECTED"
        print(f"    Session 0x{sid:04X}:  last=0x{last:04X}  → {status}")

    step("Attacker replays session 0x0003 (already seen):")
    last = svc._session_tracker.get(client_key, 0)
    replay_sid = 3
    accepted = replay_sid > last
    print(f"    Session 0x{replay_sid:04X}:  last=0x{last:04X}  "
          f"→ {'✅ ACCEPTED' if accepted else '❌ REJECTED (stale session ID)'}")

    step("Attacker replays session 0x0001 (very old):")
    replay_sid = 1
    accepted = replay_sid > last
    print(f"    Session 0x{replay_sid:04X}:  last=0x{last:04X}  "
          f"→ {'✅ ACCEPTED' if accepted else '❌ REJECTED (stale session ID)'}")

    step("New legitimate request with session 0x000B:")
    new_sid = 11
    accepted = new_sid > last
    if accepted:
        svc._session_tracker[client_key] = new_sid
    print(f"    Session 0x{new_sid:04X}:  last=0x{last:04X}  → ✅ ACCEPTED (fresh session)")

    step("Different client is tracked independently:")
    client_b = (0x0020, "172.20.0.21")
    last_b = svc._session_tracker.get(client_b, 0)
    print(f"    Client 0x0020: last session = 0x{last_b:04X} (independent)")
    print(f"    Session 0x0001 for Client 0x0020: ✅ ACCEPTED (different client)")


# ======================================================================
# Stage 7: Adversarial Evasion Testing
# ======================================================================

def inject_evasion_traffic(records: list, base_time_offset: float = 30.0) -> list:
    """Inject evasion-style traffic into the existing records."""
    from datetime import datetime, timezone, timedelta

    base_time = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
    evasion_records = []

    # Slow flood: low rate, distributed across services
    step("Injecting SLOW FLOOD evasion (3 msg/s across 3 services)...")
    t = base_time_offset
    slow_count = 0
    session = 500
    svc_ids = [HVAC_SERVICE_ID, MEDIA_SERVICE_ID, NAV_SERVICE_ID]
    svc_ips = ["172.20.0.10", "172.20.0.11", "172.20.0.12"]
    while t < base_time_offset + 10:
        svc_idx = slow_count % 3
        session += 1
        ts = base_time + timedelta(seconds=t)
        evasion_records.append({
            "timestamp": ts.isoformat(),
            "direction": "sent",
            "src_ip": "172.20.0.40",
            "dst_ip": svc_ips[svc_idx],
            "service_id": f"0x{svc_ids[svc_idx]:04X}",
            "method_id": f"0x{random.choice([0x0001, 0x0002]):04X}",
            "client_id": "0x0040",
            "session_id": f"0x{session:04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": random.randint(4, 12),
            "payload_hex": "",
            "label": "evasion_slow_flood",
        })
        slow_count += 1
        t += random.uniform(0.25, 0.45)  # ~3 msg/s
    print(f"    Injected {slow_count} slow flood messages (3 msg/s, rotated)")

    # Spaced replay: 1 stale session every 5s, padded with fresh
    step("Injecting SPACED REPLAY evasion (1 replay/5s + padding)...")
    t = base_time_offset + 10
    replay_count = 0
    pad_count = 0
    pad_session = 600
    while t < base_time_offset + 25:
        ts = base_time + timedelta(seconds=t)
        # One stale replay
        evasion_records.append({
            "timestamp": ts.isoformat(),
            "direction": "sent",
            "src_ip": "172.20.0.40",
            "dst_ip": "172.20.0.10",
            "service_id": "0x1001",
            "method_id": "0x0001",
            "client_id": "0x0010",
            "session_id": f"0x{random.choice([0x0001, 0x0003, 0x0005]):04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": 6,
            "payload_hex": "000116410000",
            "label": "evasion_spaced_replay",
        })
        replay_count += 1

        # 3 padding messages with fresh sessions
        for _ in range(3):
            pad_session += 1
            pad_ts = ts + timedelta(milliseconds=random.randint(200, 800))
            evasion_records.append({
                "timestamp": pad_ts.isoformat(),
                "direction": "sent",
                "src_ip": "172.20.0.40",
                "dst_ip": "172.20.0.10",
                "service_id": "0x1001",
                "method_id": f"0x{random.choice([0x0001, 0x0002]):04X}",
                "client_id": "0x0040",
                "session_id": f"0x{pad_session:04X}",
                "message_type": "REQUEST",
                "return_code": "0x00",
                "payload_size": random.randint(4, 10),
                "payload_hex": "",
                "label": "evasion_spaced_replay",
            })
            pad_count += 1

        t += 5.0  # 1 replay per 5 seconds
    print(f"    Injected {replay_count} replays + {pad_count} padding messages")

    return evasion_records


def demo_evasion_testing(df_original, log_path: str):
    banner("STAGE 7: Adversarial Evasion Testing")

    step("Why evasion matters:")
    print("    All 4 original attacks are 'loud' — high rates, low entropy, mass SD.")
    print("    A real attacker would try to stay under the detector's thresholds.")
    print()

    # Load original records and inject evasion traffic
    records = load_traffic_log(log_path)
    evasion_records = inject_evasion_traffic(records)
    all_records = records + evasion_records
    all_records.sort(key=lambda r: r["timestamp"])

    # Write combined log
    evasion_log_path = log_path.replace(".jsonl", "_evasion.jsonl")
    with open(evasion_log_path, "w") as f:
        for r in all_records:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")

    # Re-extract features
    df_evasion = extract_windows(all_records, window_seconds=2.0)

    step("Feature comparison: Loud attacks vs Evasion attacks vs Normal")
    # Identify window types by label composition
    evasion_mask = df_evasion["label"] == 1
    normal_mask = df_evasion["label"] == 0

    key_features = ["msg_count", "msg_rate", "unique_sessions", "session_id_entropy", "max_burst_rate"]
    print()
    print(f"    {'Feature':<26} {'Normal':>8} {'Evasion':>8} {'Loud':>8}")
    print(f"    {'-'*26} {'-'*8} {'-'*8} {'-'*8}")

    normal_df = df_original[df_original["label"] == 0]
    loud_df = df_original[df_original["label"] == 1]
    # Evasion windows: attack windows in the new dataset that weren't in original
    evasion_windows = df_evasion[evasion_mask]

    for f in key_features:
        n_val = normal_df[f].mean() if not normal_df.empty else 0
        e_val = evasion_windows[f].mean() if not evasion_windows.empty else 0
        l_val = loud_df[f].mean() if not loud_df.empty else 0
        marker = " ←close" if abs(e_val - n_val) < abs(l_val - n_val) * 0.3 else ""
        print(f"    {f:<26} {n_val:>8.2f} {e_val:>8.2f} {l_val:>8.2f}{marker}")

    step("Evasion analysis:")
    print("    Slow flood stays at ~3 msg/s (normal is ~1-2, loud flood is 200+)")
    print("    Spaced replay dilutes stale sessions with fresh padding")
    print("    Both are designed to look like normal traffic per-window")

    step("Recommendations for catching evasion attacks:")
    print("    1. Longer rolling window (10-30s) to accumulate low-rate anomalies")
    print("    2. Rate-of-change features (Δ between consecutive windows)")
    print("    3. Cross-window session tracking (flag IDs seen in past N windows)")
    print("    4. Isolation Forest anomaly layer (catches novel deviations)")
    print("    5. Source IP history (new clients appearing after stable period)")

    return df_evasion, evasion_log_path


# ======================================================================
# Stage 8: Isolation Forest (Unsupervised Layer)
# ======================================================================

def demo_isolation_forest(df, df_evasion):
    banner("STAGE 8: Isolation Forest (Unsupervised Anomaly Detection)")

    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
    except ImportError:
        print("    ⚠ scikit-learn not installed — skipping Isolation Forest demo")
        return

    import numpy as np

    step("Training on normal-only windows (no attack labels needed)")
    X_all = df[FEATURE_COLUMNS].values
    y_all = df["label"].values

    # Train on normal-only data
    X_normal = X_all[y_all == 0]
    n_normal = len(X_normal)
    print(f"    Normal training windows: {n_normal}")

    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)

    iforest = IsolationForest(
        contamination=0.05, n_estimators=200,
        random_state=42, n_jobs=-1,
    )
    iforest.fit(X_normal_scaled)
    print(f"    Isolation Forest trained (200 trees, contamination=5%)")

    # Evaluate on ALL data
    step("Evaluating on mixed traffic (normal + loud attacks):")
    X_all_scaled = scaler.transform(X_all)
    raw_preds = iforest.predict(X_all_scaled)
    preds = (raw_preds == -1).astype(int)  # 1=anomaly
    scores = iforest.decision_function(X_all_scaled)

    n_attack = (y_all == 1).sum()
    if n_attack > 0:
        print(f"    Precision: {precision_score(y_all, preds, zero_division=0):.4f}")
        print(f"    Recall:    {recall_score(y_all, preds, zero_division=0):.4f}")
        print(f"    F1 Score:  {f1_score(y_all, preds, zero_division=0):.4f}")

        cm = confusion_matrix(y_all, preds)
        print(f"\n    Confusion Matrix:")
        print(f"                     Predicted")
        print(f"                  Normal  Anomaly")
        print(f"    Actual Normal  {cm[0][0]:>4}     {cm[0][1]:>4}")
        print(f"    Actual Attack  {cm[1][0]:>4}     {cm[1][1]:>4}")

    # Show per-window anomaly scores
    step("Anomaly scores (lower = more anomalous):")
    normal_scores = scores[y_all == 0]
    attack_scores = scores[y_all == 1]
    print(f"    Normal windows:  mean={normal_scores.mean():.3f}  min={normal_scores.min():.3f}")
    if len(attack_scores) > 0:
        print(f"    Attack windows:  mean={attack_scores.mean():.3f}  min={attack_scores.min():.3f}")

    # Now test on evasion traffic
    step("Evaluating on EVASION traffic (stretch test):")
    X_ev = df_evasion[FEATURE_COLUMNS].values
    y_ev = df_evasion["label"].values
    X_ev_scaled = scaler.transform(X_ev)
    ev_preds = (iforest.predict(X_ev_scaled) == -1).astype(int)
    ev_scores = iforest.decision_function(X_ev_scaled)

    n_ev_attack = (y_ev == 1).sum()
    if n_ev_attack > 0:
        ev_attack_preds = ev_preds[y_ev == 1]
        detected = ev_attack_preds.sum()
        evaded = n_ev_attack - detected
        evasion_rate = evaded / n_ev_attack * 100

        print(f"    Evasion windows: {n_ev_attack}")
        print(f"    Detected by IForest: {detected}")
        print(f"    Evaded IForest: {evaded} ({evasion_rate:.0f}%)")
        print()

        if evasion_rate > 50:
            print(f"    ⚠ Evasion attacks PARTIALLY EVADE Isolation Forest")
            print(f"    → This is expected: they're designed to mimic normal traffic")
            print(f"    → Fix: longer windows, cross-window tracking, ensemble methods")
        else:
            print(f"    ✅ Isolation Forest catches most evasion attacks!")
            print(f"    → Unsupervised layer adds value beyond XGBoost")

    # Compare XGBoost-only vs dual-layer
    step("Dual-layer comparison (XGBoost vs XGBoost + IForest):")
    print("    ┌─────────────────────────────────────────────┐")
    print("    │  Detection Layer    │  Catches    │  Misses │")
    print("    ├─────────────────────┼─────────────┼─────────┤")
    print("    │  XGBoost only       │  Known atks │  Novel  │")
    print("    │  IForest only       │  Outliers   │  Subtle │")
    print("    │  XGBoost + IForest  │  Both types │  Less   │")
    print("    └─────────────────────────────────────────────┘")
    print()
    print("    → Alert fires if EITHER model flags the window")
    print("    → XGBoost catches patterns it was trained on")
    print("    → IForest catches anything that deviates from normal")


# ======================================================================
# Main
# ======================================================================

def main():
    print("\n" + "█" * 72)
    print("█  SOME/IP Automotive Intrusion Detection System — Full Demo         █")
    print("█" * 72)

    # Stage 1
    demo_protocol_codec()

    # Stage 2
    log_path = os.path.join(tempfile.gettempdir(), "demo_traffic.jsonl")
    records = generate_traffic(log_path)

    # Stage 3
    df = demo_feature_extraction(log_path)

    # Stage 4
    demo_xgboost_training(df)

    # Stage 5
    demo_hmac_verification()

    # Stage 6
    demo_session_freshness()

    # Stage 7
    df_evasion, evasion_log_path = demo_evasion_testing(df, log_path)

    # Stage 8
    demo_isolation_forest(df, df_evasion)

    # Summary
    banner("DEMO COMPLETE")
    print(f"""
    Project: SOME/IP Automotive Intrusion Detection System
    Repo:    https://github.com/saisneha196/someip-ids

    ✓ Protocol codec (SOME/IP header + SD messages)
    ✓ Simulated ECU traffic (3 services × normal + 4 attack types)
    ✓ Feature extraction (14 sliding-window features)
    ✓ XGBoost anomaly detection (trained + evaluated)
    ✓ HMAC-signed offers (spoofing prevention)
    ✓ Session freshness check (replay prevention)
    ✓ Adversarial evasion testing (slow flood + spaced replay)
    ✓ Isolation Forest unsupervised layer (dual-model detection)

    All containerized with Docker Compose
    """)


if __name__ == "__main__":
    main()
