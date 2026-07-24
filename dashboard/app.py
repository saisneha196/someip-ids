"""
SOME/IP IDS Dashboard — Streamlit live visualization.

Three-panel layout:
  1. Live Traffic Feed — scrolling table of recent messages, color-coded by service
  2. Anomaly Score Graph — time-series of per-window anomaly probability
  3. Alert Banner — red full-width banner when anomaly detected

Auto-refreshes every 2 seconds.
"""

from __future__ import annotations

import json
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DETECTOR_URL = os.environ.get("DETECTOR_URL", "http://detector:5001")
LOG_PATH = os.environ.get("LOG_PATH", "/logs/traffic.jsonl")
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
}


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SOME/IP IDS Dashboard",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom CSS for dark, premium look
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

    .stDataFrame {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)


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

        # Read last N lines efficiently
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
    st.markdown(
        f'<div class="alert-banner">🚨 ANOMALY DETECTED — Score: {score:.3f} '
        f'(Threshold: {ANOMALY_THRESHOLD}) — {detector_status.get("latest_timestamp", "")}</div>',
        unsafe_allow_html=True,
    )
elif detector_status:
    score = detector_status.get("latest_score", 0)
    st.markdown(
        f'<div class="safe-banner">✅ Network Normal — Anomaly Score: {score:.3f}</div>',
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
            name="Anomaly Score",
            line=dict(color="#3498DB", width=2),
            marker=dict(
                size=6,
                color=score_df["alert"].map({True: "#E74C3C", False: "#3498DB"}),
            ),
            fill="tozeroy",
            fillcolor="rgba(52, 152, 219, 0.1)",
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
            yaxis=dict(showgrid=True, gridcolor="rgba(128,128,128,0.1)", range=[0, 1]),
            font=dict(family="Inter"),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Waiting for detector scores...")

# ---------------------------------------------------------------------------
# Right: Traffic Distribution
# ---------------------------------------------------------------------------

with right_col:
    st.subheader("🔄 Traffic Distribution")

    if not traffic_df.empty and "service_id" in traffic_df.columns:
        svc_counts = traffic_df["service_id"].value_counts()
        svc_labels = [SERVICE_NAMES.get(sid, sid) for sid in svc_counts.index]
        svc_colors = [SERVICE_COLORS.get(sid, "#95A5A6") for sid in svc_counts.index]

        fig = go.Figure(data=[go.Pie(
            labels=svc_labels,
            values=svc_counts.values,
            hole=0.5,
            marker=dict(colors=svc_colors),
            textinfo="label+percent",
            textfont_size=12,
        )])
        fig.update_layout(
            height=350,
            margin=dict(l=20, r=20, t=30, b=20),
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter"),
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No traffic data yet...")

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
    st.info("📡 Waiting for traffic data... Start services with `docker compose up`")

# ---------------------------------------------------------------------------
# Auto-refresh
# ---------------------------------------------------------------------------

time.sleep(REFRESH_INTERVAL)
st.rerun()
