"""
SOME/IP IDS Dashboard — Streamlit live visualization with attack controls.

Features:
  1. Live Traffic Feed — scrolling table of recent messages, color-coded by service
  2. Anomaly Score Graph — time-series of per-window anomaly probability
  3. Alert Banner — red full-width banner when anomaly detected
  4. Attack Launcher — sidebar buttons to trigger attacks on demand

Auto-refreshes every 2 seconds.
"""

from __future__ import annotations

import json
import os
import random
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
import requests

from dashboard.topology import get_topology_html

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DETECTOR_URL = os.environ.get("DETECTOR_URL", "http://localhost:5001")
LOG_PATH = os.environ.get("LOG_PATH", str(
    Path(os.path.dirname(os.path.abspath(__file__))).parent / "local_logs" / "traffic.jsonl"
))
REFRESH_INTERVAL = 2  # seconds
MAX_TRAFFIC_ROWS = 100
ANOMALY_THRESHOLD = 0.5

# Service color mapping
SERVICE_COLORS = {
    "0x1001": "#FF6B6B",  # HVAC — coral red
    "0x2001": "#4ECDC4",  # Media — teal
    "0x3001": "#45B7D1",  # Navigation — sky blue
    "0xFFFF": "#96CEB4",  # SD — sage green
}

SERVICE_NAMES = {
    "0x1001": "🌡 HVAC",
    "0x2001": "🎵 Media",
    "0x3001": "🗺 Navigation",
    "0xFFFF": "📡 Service Discovery",
}

LABEL_COLORS = {
    "normal": "#2ECC71",
    "flood": "#E74C3C",
    "replay": "#E67E22",
    "spoofed_offer": "#9B59B6",
    "malformed_sd": "#F39C12",
    "evasion_slow_flood": "#FF6B9D",
    "evasion_spaced_replay": "#C44DFF",
}


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SOME/IP IDS Dashboard",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    .stApp {
        font-family: 'Inter', sans-serif;
    }

    .alert-banner {
        background: linear-gradient(135deg, #E74C3C 0%, #C0392B 100%);
        color: white;
        padding: 20px 30px;
        border-radius: 12px;
        font-size: 1.3em;
        font-weight: 600;
        text-align: center;
        margin-bottom: 20px;
        animation: pulse 1.5s ease-in-out infinite;
        box-shadow: 0 4px 20px rgba(231, 76, 60, 0.4);
    }

    .safe-banner {
        background: linear-gradient(135deg, #2ECC71 0%, #27AE60 100%);
        color: white;
        padding: 16px 30px;
        border-radius: 12px;
        font-size: 1.1em;
        font-weight: 500;
        text-align: center;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(46, 204, 113, 0.3);
    }

    @keyframes pulse {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.01); opacity: 0.9; }
    }

    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid #2a2a4a;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }

    .attack-btn {
        font-size: 1.1em;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Attack injection functions (write directly to the traffic log)
# ---------------------------------------------------------------------------

def _write_record(record):
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def inject_flood(count=50):
    for i in range(count):
        _write_record({
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
        })
    return count


def inject_replay(count=8):
    for i in range(count):
        _write_record({
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
        })
    return count


def inject_spoofed_offer(count=5):
    for i in range(count):
        _write_record({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "255.255.255.255",
            "service_id": "0xFFFF",
            "method_id": "0x8100",
            "client_id": "0x0000",
            "session_id": f"0x{random.randint(1, 100):04X}",
            "message_type": "NOTIFICATION",
            "return_code": "0x00",
            "payload_size": 55,
            "payload_hex": "",
            "label": "spoofed_offer",
        })
    return count


def inject_evasion(count=12):
    svc_ids = [0x1001, 0x2001, 0x3001]
    svc_ips = ["172.20.0.10", "172.20.0.11", "172.20.0.12"]
    session = random.randint(500, 900)
    for i in range(count):
        idx = i % 3
        session += 1
        _write_record({
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
        })
    return count


# ---------------------------------------------------------------------------
# Sidebar — Attack Launcher
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## ⚔ Attack Launcher")
    st.markdown("*Trigger attacks and watch the dashboard react*")
    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        if st.button("🔴 Flood", use_container_width=True, help="50 rapid requests at 200 msg/s"):
            n = inject_flood(50)
            st.toast(f"🔴 Flood attack launched! ({n} messages)", icon="💥")

        if st.button("🟣 Spoofed Offer", use_container_width=True, help="5 fake SD service offers"):
            n = inject_spoofed_offer(5)
            st.toast(f"🟣 Spoofed offers sent! ({n} messages)", icon="📡")

    with col_b:
        if st.button("🟠 Replay", use_container_width=True, help="8 replayed stale sessions"):
            n = inject_replay(8)
            st.toast(f"🟠 Replay attack launched! ({n} messages)", icon="🔁")

        if st.button("💗 Evasion", use_container_width=True, help="12 slow stealthy requests"):
            n = inject_evasion(12)
            st.toast(f"💗 Evasion attack sent! ({n} messages)", icon="🥷")

    st.divider()

    if st.button("💣 Launch ALL Attacks", use_container_width=True, type="primary"):
        inject_flood(50)
        inject_replay(8)
        inject_spoofed_offer(5)
        inject_evasion(12)
        st.toast("💣 All 4 attacks launched!", icon="🚨")

    st.divider()

    # Attack intensity slider
    st.markdown("### ⚙ Settings")
    flood_size = st.slider("Flood intensity", 10, 200, 50, help="Number of flood messages")
    auto_attack = st.toggle("Auto-attack mode", value=False, help="Inject attacks automatically every 30s")

    if auto_attack:
        st.warning("Auto-attack ON — attacks every ~30s")

    st.divider()
    st.markdown("### 📖 Attack Types")
    st.markdown("""
    - 🔴 **Flood** — overwhelm a service with rapid requests
    - 🟠 **Replay** — resend captured packets with stale session IDs
    - 🟣 **Spoofed Offer** — broadcast fake service announcements
    - 💗 **Evasion** — slow, stealthy requests designed to evade detection
    """)


# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

@st.cache_data(ttl=REFRESH_INTERVAL)
def load_recent_traffic(log_path: str, max_rows: int = MAX_TRAFFIC_ROWS) -> pd.DataFrame:
    """Load the most recent traffic entries from the log file."""
    records = []
    try:
        path = Path(log_path)
        if not path.exists():
            return pd.DataFrame()

        with open(path, "r") as f:
            lines = deque(f, maxlen=max_rows)

        for line in lines:
            try:
                records.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    except Exception as e:
        st.error(f"Error reading traffic log: {e}")

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    return df


def fetch_detector_status() -> Optional[dict]:
    """Fetch latest status from the detector HTTP API."""
    try:
        resp = requests.get(f"{DETECTOR_URL}/status", timeout=2)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Dashboard layout
# ---------------------------------------------------------------------------

# Header
st.markdown("# 🛡 SOME/IP Intrusion Detection System")
st.markdown("*Real-time automotive network traffic monitoring & anomaly detection*")
st.divider()

# Fetch data
traffic_df = load_recent_traffic(LOG_PATH)
detector_status = fetch_detector_status()

# ---------------------------------------------------------------------------
# Alert Banner
# ---------------------------------------------------------------------------

if detector_status and detector_status.get("is_alert"):
    score = detector_status.get("latest_score", 0)
    if_score = detector_status.get("latest_iforest_score", 0)
    source = detector_status.get("alert_source", "")
    source_label = {"xgboost": "XGBoost", "iforest": "Isolation Forest", "both": "XGBoost + IForest"}.get(source, source)
    st.markdown(
        f'<div class="alert-banner">🚨 ANOMALY DETECTED [{source_label}] — '
        f'XGB: {score:.3f} | IForest: {if_score:.3f} — '
        f'{detector_status.get("latest_timestamp", "")}</div>',
        unsafe_allow_html=True,
    )
elif detector_status:
    score = detector_status.get("latest_score", 0)
    if_score = detector_status.get("latest_iforest_score", 0)
    st.markdown(
        f'<div class="safe-banner">✅ Network Normal — XGB: {score:.3f} | IForest: {if_score:.3f}</div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="safe-banner">⏳ Waiting for detector connection...</div>',
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Metrics Row
# ---------------------------------------------------------------------------

col1, col2, col3, col4, col5 = st.columns(5)

if not traffic_df.empty:
    with col1:
        st.metric("📨 Total Messages", len(traffic_df))
    with col2:
        n_services = traffic_df["service_id"].nunique() if "service_id" in traffic_df.columns else 0
        st.metric("🔌 Active Services", n_services)
    with col3:
        n_attacks = (traffic_df["label"] != "normal").sum() if "label" in traffic_df.columns else 0
        st.metric("⚠ Attack Messages", n_attacks)
    with col4:
        alert_count = detector_status.get("alert_count", 0) if detector_status else 0
        st.metric("🚨 Alerts Fired", alert_count)
    with col5:
        if detector_status:
            st.metric("📊 Anomaly Score", f"{detector_status.get('latest_score', 0):.3f}")
        else:
            st.metric("📊 Anomaly Score", "N/A")

st.divider()

# ---------------------------------------------------------------------------
# Main Content — Two columns
# ---------------------------------------------------------------------------

left_col, right_col = st.columns([3, 2])

# ---------------------------------------------------------------------------
# Left: Anomaly Score Time Series
# ---------------------------------------------------------------------------

with left_col:
    st.subheader("📈 Anomaly Score Over Time")

    if detector_status and detector_status.get("score_history"):
        score_df = pd.DataFrame(detector_status["score_history"])
        score_df["timestamp"] = pd.to_datetime(score_df["timestamp"])

        fig = go.Figure()

        # Score line
        fig.add_trace(go.Scatter(
            x=score_df["timestamp"],
            y=score_df["score"],
            mode="lines+markers",
            name="XGBoost Score",
            line=dict(color="#3498DB", width=2),
            marker=dict(
                size=6,
                color=score_df["alert"].map({True: "#E74C3C", False: "#3498DB"}),
            ),
            fill="tozeroy",
            fillcolor="rgba(52, 152, 219, 0.1)",
        ))

        # IForest score line (if available)
        if "iforest_score" in score_df.columns:
            fig.add_trace(go.Scatter(
                x=score_df["timestamp"],
                y=score_df["iforest_score"].clip(lower=-0.2),
                mode="lines",
                name="IForest Score",
                line=dict(color="#9B59B6", width=1.5, dash="dot"),
                opacity=0.7,
            ))

        # Threshold line
        fig.add_hline(
            y=ANOMALY_THRESHOLD,
            line_dash="dash",
            line_color="#E74C3C",
            annotation_text=f"Threshold ({ANOMALY_THRESHOLD})",
            annotation_position="top right",
        )

        fig.update_layout(
            height=350,
            margin=dict(l=20, r=20, t=30, b=20),
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(showgrid=True, gridcolor="rgba(128,128,128,0.1)"),
            yaxis=dict(showgrid=True, gridcolor="rgba(128,128,128,0.1)", range=[-0.2, 1]),
            font=dict(family="Inter"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Waiting for detector scores...")

# ---------------------------------------------------------------------------
# Right: Network Topology (replaces donut chart)
# ---------------------------------------------------------------------------

with right_col:
    st.subheader("🔗 Network Topology")
    topology_html = get_topology_html(DETECTOR_URL)
    components.html(topology_html, height=420, scrolling=False)

st.divider()

# ---------------------------------------------------------------------------
# Bottom: Live Traffic Feed
# ---------------------------------------------------------------------------

st.subheader("📋 Live Traffic Feed")

if not traffic_df.empty:
    # Prepare display columns
    display_cols = ["timestamp", "direction", "service_id", "method_id",
                    "message_type", "session_id", "payload_size", "label"]
    available_cols = [c for c in display_cols if c in traffic_df.columns]
    display_df = traffic_df[available_cols].copy()

    # Map service IDs to names
    if "service_id" in display_df.columns:
        display_df["service"] = display_df["service_id"].map(
            lambda x: SERVICE_NAMES.get(x, x)
        )

    # Color-code by label
    def style_row(row):
        label = row.get("label", "normal")
        color = LABEL_COLORS.get(label, "#2ECC71")
        return [f"color: {color}"] * len(row)

    styled = display_df.tail(50).style.apply(style_row, axis=1)
    st.dataframe(styled, use_container_width=True, height=400)
else:
    st.info("📡 Waiting for traffic data... Run: `python run_local.py`")

# ---------------------------------------------------------------------------
# Auto-refresh
# ---------------------------------------------------------------------------

time.sleep(REFRESH_INTERVAL)
st.rerun()
