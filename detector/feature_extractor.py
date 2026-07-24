"""
Feature extractor — sliding-window feature computation from SOME/IP traffic logs.

Reads traffic.jsonl and produces per-window feature vectors suitable for
XGBoost training and real-time scoring.

Each window (default 2 seconds) becomes one row with 14 numeric features:
    msg_count, msg_rate, unique_services, unique_methods, unique_sessions,
    session_id_entropy, sd_offer_count, sd_offer_rate, mean_payload_size,
    std_payload_size, request_response_ratio, notification_ratio,
    unique_src_ips, max_burst_rate
"""

from __future__ import annotations

import json
import math
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# Feature column names in output order
FEATURE_COLUMNS = [
    "msg_count",
    "msg_rate",
    "unique_services",
    "unique_methods",
    "unique_sessions",
    "session_id_entropy",
    "sd_offer_count",
    "sd_offer_rate",
    "mean_payload_size",
    "std_payload_size",
    "request_response_ratio",
    "notification_ratio",
    "unique_src_ips",
    "max_burst_rate",
]


def _parse_timestamp(ts: str) -> float:
    """Parse ISO-8601 timestamp to epoch seconds."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, AttributeError):
        return 0.0


def _shannon_entropy(values: List[str]) -> float:
    """Compute Shannon entropy of a list of categorical values."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def load_traffic_log(log_path: str) -> List[dict]:
    """Load all records from a JSON-lines traffic log."""
    records = []
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def compute_window_features(records: List[dict], window_seconds: float = 2.0) -> dict:
    """Compute feature vector for a single time window of traffic records.

    Returns a dict with all FEATURE_COLUMNS as keys.
    """
    n = len(records)
    if n == 0:
        return {col: 0.0 for col in FEATURE_COLUMNS}

    # Basic counts
    msg_count = n
    msg_rate = n / window_seconds

    # Unique IDs
    service_ids = [r.get("service_id", "") for r in records]
    method_ids = [r.get("method_id", "") for r in records]
    session_ids = [r.get("session_id", "") for r in records]
    src_ips = [r.get("src_ip", "") for r in records]

    unique_services = len(set(service_ids))
    unique_methods = len(set(method_ids))
    unique_sessions = len(set(session_ids))
    unique_src_ips = len(set(src_ips))

    # Entropy
    session_id_entropy = _shannon_entropy(session_ids)

    # SD Offer messages
    sd_offers = [r for r in records if r.get("service_id") == "0xFFFF" and r.get("message_type") == "NOTIFICATION"]
    sd_offer_count = len(sd_offers)
    sd_offer_rate = sd_offer_count / window_seconds

    # Payload sizes
    payload_sizes = [r.get("payload_size", 0) for r in records]
    mean_payload_size = np.mean(payload_sizes) if payload_sizes else 0.0
    std_payload_size = np.std(payload_sizes) if len(payload_sizes) > 1 else 0.0

    # Message type ratios
    msg_types = [r.get("message_type", "") for r in records]
    type_counts = Counter(msg_types)
    requests = type_counts.get("REQUEST", 0)
    responses = type_counts.get("RESPONSE", 0)
    notifications = type_counts.get("NOTIFICATION", 0)

    request_response_ratio = requests / max(responses, 1)
    notification_ratio = notifications / max(n, 1)

    # Max burst rate (in 100ms sub-windows)
    if n > 1:
        timestamps = sorted(_parse_timestamp(r.get("timestamp", "")) for r in records)
        # Count messages in 100ms buckets
        if timestamps[-1] > timestamps[0]:
            bucket_size = 0.1  # 100ms
            t_start = timestamps[0]
            buckets = Counter()
            for t in timestamps:
                bucket_idx = int((t - t_start) / bucket_size)
                buckets[bucket_idx] += 1
            max_burst_rate = max(buckets.values()) / bucket_size if buckets else 0.0
        else:
            max_burst_rate = msg_rate
    else:
        max_burst_rate = msg_rate

    return {
        "msg_count": msg_count,
        "msg_rate": msg_rate,
        "unique_services": unique_services,
        "unique_methods": unique_methods,
        "unique_sessions": unique_sessions,
        "session_id_entropy": round(session_id_entropy, 4),
        "sd_offer_count": sd_offer_count,
        "sd_offer_rate": round(sd_offer_rate, 4),
        "mean_payload_size": round(float(mean_payload_size), 2),
        "std_payload_size": round(float(std_payload_size), 2),
        "request_response_ratio": round(request_response_ratio, 4),
        "notification_ratio": round(notification_ratio, 4),
        "unique_src_ips": unique_src_ips,
        "max_burst_rate": round(max_burst_rate, 2),
    }


def extract_windows(
    records: List[dict],
    window_seconds: float = 2.0,
) -> pd.DataFrame:
    """Slice traffic records into time windows and compute features for each.

    Returns a DataFrame with FEATURE_COLUMNS + 'label' + 'window_start'.
    """
    if not records:
        return pd.DataFrame(columns=FEATURE_COLUMNS + ["label", "window_start"])

    # Sort by timestamp
    for r in records:
        r["_ts"] = _parse_timestamp(r.get("timestamp", ""))
    records.sort(key=lambda r: r["_ts"])

    t_start = records[0]["_ts"]
    t_end = records[-1]["_ts"]

    rows = []
    window_start = t_start

    while window_start < t_end:
        window_end = window_start + window_seconds
        window_records = [
            r for r in records
            if window_start <= r["_ts"] < window_end
        ]

        features = compute_window_features(window_records, window_seconds)

        # Determine label: attack if ANY record in window has a non-normal label
        labels = set(r.get("label", "normal") for r in window_records)
        label = 0 if labels == {"normal"} or not labels else 1

        features["label"] = label
        features["window_start"] = datetime.fromtimestamp(
            window_start, tz=timezone.utc
        ).isoformat()

        rows.append(features)
        window_start = window_end

    # Clean up
    for r in records:
        r.pop("_ts", None)

    return pd.DataFrame(rows)


if __name__ == "__main__":
    # Quick test — process a traffic log from command line
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    parser.add_argument("--window", type=float, default=2.0)
    args = parser.parse_args()

    records = load_traffic_log(args.log_path)
    df = extract_windows(records, args.window)
    print(f"Extracted {len(df)} windows from {len(records)} messages")
    print(f"Attack windows: {df['label'].sum()}")
    print(f"\nFeature statistics:")
    print(df[FEATURE_COLUMNS].describe().to_string())
