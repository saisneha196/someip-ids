# SOME/IP Automotive Intrusion Detection System

[![CI](https://github.com/saisneha196/someip-ids/actions/workflows/ci.yml/badge.svg)](https://github.com/saisneha196/someip-ids/actions)

> **"Fake ECUs talk to each other normally, I attack them on purpose, everything gets logged, and a model learns to spot the attacks live on a dashboard — all running locally or in Docker with automated tests behind it."**

A full-stack intrusion detection pipeline for automotive SOME/IP networks: simulated ECU traffic generation, 4 attack types, dual-model anomaly detection (XGBoost + Isolation Forest) with live retraining, and a real-time Streamlit dashboard with interactive attack controls.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SOME/IP IDS Pipeline                         │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────────┐                 │
│   │   HVAC   │  │  Media   │  │  Navigation  │  ECU Services   │
│   │  0x1001  │  │  0x2001  │  │    0x3001    │  (Simulated)    │
│   └────┬─────┘  └────┬─────┘  └──────┬───────┘                 │
│        │              │               │                          │
│        │    Normal + Attack Traffic   │                          │
│        ▼              ▼               ▼                          │
│   ┌────────────────────────────────────────┐                    │
│   │        Traffic Simulator              │  Logs to JSONL      │
│   │   Normal traffic + 4 attack types     │  every 0.3-0.8s    │
│   └────────────────┬───────────────────────┘                    │
│                    │                                             │
│                    ▼  traffic.jsonl                              │
│   ┌────────────────────────────────────────┐                    │
│   │    Dual-Model Anomaly Detector        │  5s windows         │
│   │  XGBoost (supervised) + IForest       │  Retrains every 60s │
│   │  + Synthetic attack pre-seeding       │  HTTP API :5001     │
│   └────────────────┬───────────────────────┘                    │
│                    │                                             │
│                    ▼                                             │
│   ┌────────────────────────────────────────┐                    │
│   │       Streamlit Dashboard :8501       │  Live graphs        │
│   │  XGBoost + IForest scores • Topology  │  Alert banners      │
│   │  Traffic feed • Attack launcher       │  Auto-refresh 2s    │
│   └────────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- **Python 3.11+**
- Install dependencies:

```bash
pip install -r requirements.txt
```

### Run the Full Pipeline (Recommended)

```bash
python run_local.py
```

This single command starts **everything** in parallel:

| Component | What it does | URL |
|:---|:---|:---|
| Traffic Simulator | Generates normal + attack traffic to `local_logs/traffic.jsonl` | — |
| Detector | XGBoost + IForest scoring with HTTP API | http://localhost:5001/status |
| Dashboard | Live Streamlit visualization with attack controls | http://localhost:8501 |

Press **Ctrl+C** to stop all components.

### Run the Offline Demo

```bash
python demo.py
```

Runs all 8 stages sequentially in the terminal (no dashboard):
1. Protocol codec verification
2. Traffic generation (normal + attacks)
3. Feature extraction (14 features)
4. XGBoost training + evaluation
5. HMAC verification
6. Session freshness check
7. Adversarial evasion testing
8. Isolation Forest evaluation

### Run with Docker

```bash
docker compose up --build
```

Open http://localhost:8501 for the dashboard.

---

## Detection System

### Dual-Model Architecture

The detector uses two complementary models that run in parallel on every scoring window:

| Model | Type | What it catches | Alert condition |
|:---|:---|:---|:---|
| **XGBoost** | Supervised | Known attack patterns (flood, replay, spoof, evasion) | Score ≥ 0.5 |
| **Isolation Forest** | Unsupervised | Any deviation from learned "normal" | Score < -0.02 |

An alert fires if **either** model flags the window → `alert_source` shows `xgboost`, `iforest`, or `both`.

### Key Detection Features

The detector addresses several design challenges:

- **Synthetic attack seeding** — Before any real attacks arrive, the model is pre-trained on ~25+ synthetic attack feature profiles (flood, replay, spoof, evasion) so it can detect attacks from the first window
- **Live retraining** — Model retrains every 60 seconds on the full accumulated traffic log, improving accuracy over time
- **Delayed training** — Waits up to 90 seconds at startup for real attack data to appear before initial training
- **5-second scoring windows** — Wider than typical 2s windows to capture enough attack signal per scoring cycle

### 14 Features Per Window

| Feature | What it captures |
|:---|:---|
| `msg_count` | Total messages in window |
| `msg_rate` | Messages per second |
| `unique_services` | Number of distinct service IDs |
| `unique_methods` | Number of distinct method IDs |
| `unique_sessions` | Session ID diversity |
| `session_id_entropy` | Shannon entropy (replay detection) |
| `sd_offer_count` | SD Offer messages (spoofing detection) |
| `sd_offer_rate` | SD Offers per second |
| `mean_payload_size` | Average payload bytes |
| `std_payload_size` | Payload size variation |
| `request_response_ratio` | Unanswered request detection |
| `notification_ratio` | Event traffic fraction |
| `unique_src_ips` | Source IP diversity |
| `max_burst_rate` | Peak instantaneous rate (100ms buckets) |

---

## Attack Types

The simulator injects 4 types of attacks automatically:

| Attack | Technique | Injected count | Detection signal |
|:---|:---|:---|:---|
| 🔴 **Flood** | 50 rapid requests at ~200 msg/s | 50 msgs/burst | High msg_count, max_burst_rate |
| 🟠 **Replay** | Stale session IDs (always 0x0001) | 8 msgs/burst | Low unique_sessions, low entropy |
| 🟣 **Spoofed Offer** | Fake SD service announcements | 5 msgs/burst | High sd_offer_count, notification_ratio |
| 💗 **Evasion** | Slow flood across 3 services | 12 msgs/burst | Unusual src_ip, request_response_ratio |

The dashboard sidebar also has buttons to **manually trigger** any attack type on demand.

---

## Dashboard

The Streamlit dashboard at http://localhost:8501 includes:

- **Alert banner** — Green (normal) / Red (attack detected) with model source
- **Metrics row** — Total messages, active services, attack count, alerts fired
- **XGBoost score graph** — Time series with 0.5 threshold line
- **Isolation Forest score graph** — Time series with -0.02 threshold line
- **Network topology** — Interactive visualization of ECU connections
- **Live traffic feed** — Color-coded scrolling table of recent messages
- **Attack launcher sidebar** — Buttons to inject flood, replay, spoof, evasion attacks

---

## Project Structure

```
someip-ids/
├── run_local.py           # ⭐ Main entry point — runs full pipeline locally
├── demo.py                # Offline demo — all 8 stages in terminal
├── proto/                 # SOME/IP protocol library (pure Python)
│   ├── someip.py          # 16-byte header codec
│   ├── sd.py              # Service Discovery + HMAC signing
│   └── constants.py       # Service/method/event IDs + HMAC keys
├── services/              # Simulated ECU services
│   ├── base_service.py    # Abstract base (session tracking, logging)
│   ├── hvac.py            # HVAC: SetTemperature, GetTemperature
│   ├── media.py           # Media: Play, Pause, NextTrack
│   └── navigation.py      # Navigation: SetDestination
├── client/                # Head-unit client
│   ├── discovery.py       # SD listener + service registry
│   ├── head_unit.py       # Method caller + event subscriber
│   └── traffic_logger.py  # JSON-lines traffic logging
├── attacks/               # Attack scripts (for Docker mode)
│   ├── replay.py          # Message replay
│   ├── flood.py           # Request flooding
│   ├── spoofed_offer.py   # Fake SD Offers
│   └── malformed_sd.py    # Invalid SD packets
├── detector/              # ML-based anomaly detection
│   ├── feature_extractor.py # 14 sliding-window features
│   ├── detector.py        # Real-time scoring loop (Docker mode)
│   ├── isolation_forest.py # IForest training utilities
│   ├── train_model.py     # XGBoost training pipeline
│   └── model/             # Saved model artifacts
├── dashboard/             # Streamlit visualization
│   ├── app.py             # Live dashboard + attack launcher
│   └── topology.py        # Network topology canvas
├── local_logs/            # Runtime traffic + alert logs
├── tests/                 # Automated tests
├── docker-compose.yml     # Container orchestration
├── requirements.txt       # Python dependencies
└── .github/workflows/     # CI pipeline
```

## SOME/IP Protocol

This project implements a faithful subset of the AUTOSAR SOME/IP specification:

### Message Header (16 bytes)
| Offset | Size | Field |
|:---|:---|:---|
| 0 | 16b | Service ID |
| 2 | 16b | Method/Event ID |
| 4 | 32b | Length |
| 8 | 16b | Client ID |
| 10 | 16b | Session ID |
| 12 | 8b | Protocol Version (0x01) |
| 13 | 8b | Interface Version |
| 14 | 8b | Message Type |
| 15 | 8b | Return Code |

### Service Discovery
- **OfferService** — ECU announces availability (broadcast)
- **FindService** — Client queries for a service
- **SubscribeEventgroup** — Client subscribes to events
- **SubscribeEventgroupAck** — Server confirms subscription
- **HMAC signing** — Offers are signed with per-service HMAC-SHA256 keys

---

## Detector HTTP API

When running, the detector exposes a REST API on port 5001:

| Endpoint | Response |
|:---|:---|
| `GET /status` | Full detector state (scores, alerts, features, service stats, model version) |
| `GET /health` | `OK` |

Example:
```bash
curl http://localhost:5001/status | python -m json.tool
```

---

## Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Just protocol tests
python -m pytest tests/test_proto.py -v

# Just detector tests
python -m pytest tests/test_detector.py -v
```

---

## Limitations & Future Work

> This project proves the **pipeline** works — simulated ECU → attack → detect → visualize. It does **not** prove the detector would catch a real, unseen attacker on production hardware.

**What a production version would need:**
- Real ECU traffic captures (CAN/SOME/IP gateway logs from actual vehicles)
- Broader attack coverage (fuzzing, protocol-level exploits, MITM)
- Latency constraints for embedded deployment (SOME/IP runs on ARM ECUs)
- AUTOSAR-compliant vsomeip integration instead of pure Python
- Adversarial robustness testing (attacks designed to evade the detector)

## License

MIT
