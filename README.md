# SOME/IP Automotive Intrusion Detection System

[![CI](https://github.com/your-repo/someip-ids/actions/workflows/ci.yml/badge.svg)](https://github.com/your-repo/someip-ids/actions)

> **"Fake ECUs talk to each other normally, I attack them on purpose, everything gets logged, and a model learns to spot the attacks live on a dashboard — all running in Docker with automated tests behind it."**

A full-stack intrusion detection pipeline for automotive SOME/IP networks: simulated ECU services on a Docker network, attack injection, XGBoost-based anomaly detection, and a live Streamlit dashboard — all containerized with CI/CD.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Docker Bridge Network                        │
│                     (172.20.0.0/24)                              │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────────┐                 │
│   │   HVAC   │  │  Media   │  │  Navigation  │  ECU Services   │
│   │ :30501   │  │ :30502   │  │   :30503     │  (SD Offer)     │
│   └────┬─────┘  └────┬─────┘  └──────┬───────┘                 │
│        │              │               │                          │
│        │    SD Offers (broadcast)      │                          │
│        ▼              ▼               ▼                          │
│   ┌────────────────────────────────────────┐                    │
│   │         Head-Unit Client               │  Discovers via SD  │
│   │   Calls methods, subscribes events     │  Logs everything   │
│   └────────────────┬───────────────────────┘                    │
│                    │                                             │
│                    ▼  traffic.jsonl                              │
│   ┌────────────────────────────────────────┐                    │
│   │       Feature Extractor + XGBoost      │  2s windows        │
│   │           Anomaly Detector             │  Scores & alerts   │
│   └────────────────┬───────────────────────┘                    │
│                    │                                             │
│                    ▼                                             │
│   ┌────────────────────────────────────────┐                    │
│   │       Streamlit Dashboard :8501        │  Live graphs       │
│   │   Traffic feed • Score graph • Alerts  │  Red banners       │
│   └────────────────────────────────────────┘                    │
│                                                                  │
│   ┌────────────────────────────────────────┐                    │
│   │          Attack Scripts                │  Runs separately   │
│   │   Replay • Flood • Spoof • Malformed  │                    │
│   └────────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Docker Desktop (with Docker Compose v2)
- Python 3.11+ (for running attacks and training locally)

### 1. Start the Vehicle Network

```bash
docker compose up --build
```

This starts HVAC, Media, and Navigation ECU services, plus the head-unit client. You'll see:
- Services broadcasting SD Offer messages every 3 seconds
- Client discovering services and calling methods
- Traffic being logged to the shared `traffic.jsonl`

### 2. Watch the Traffic

```bash
# Follow client interactions
docker compose logs -f client

# Tail the raw traffic log
docker compose exec client tail -f /logs/traffic.jsonl | python -m json.tool
```

### 3. Launch Attacks

In a separate terminal:

```bash
# Flood the HVAC service
docker compose exec client python -m attacks.flood --target-service HVAC --duration 10

# Replay captured messages
docker compose exec client python -m attacks.replay --target-service HVAC --count 10

# Spoof a service offer
docker compose exec client python -m attacks.spoofed_offer --service HVAC --duration 15

# Send malformed SD packets
docker compose exec client python -m attacks.malformed_sd --count 20
```

### 4. Train the Detector

After running normal traffic + attacks for a few minutes:

```bash
pip install xgboost scikit-learn pandas numpy
python -m detector.train_model --log-path logs/traffic.jsonl
```

### 5. Start the Dashboard

Uncomment the `dashboard` and `detector` services in `docker-compose.yml`, then:

```bash
docker compose up --build dashboard detector
```

Open http://localhost:8501 to see the live dashboard.

---

## Project Structure

```
someip-ids/
├── proto/              # SOME/IP protocol library (pure Python)
│   ├── someip.py       # 16-byte header codec
│   ├── sd.py           # Service Discovery messages
│   └── constants.py    # Service/method/event IDs
├── services/           # Simulated ECU services
│   ├── base_service.py # Abstract service base class
│   ├── hvac.py         # HVAC: SetTemperature, GetTemperature
│   ├── media.py        # Media: Play, Pause, NextTrack
│   └── navigation.py   # Navigation: SetDestination
├── client/             # Head-unit client
│   ├── discovery.py    # SD listener + service registry
│   ├── head_unit.py    # Method caller + event subscriber
│   └── traffic_logger.py # JSON-lines traffic logging
├── attacks/            # Attack scripts
│   ├── replay.py       # Message replay (stale session IDs)
│   ├── flood.py        # High-rate request flooding
│   ├── spoofed_offer.py # Fake SD Offer impersonation
│   └── malformed_sd.py # Invalid/garbage SD packets
├── detector/           # ML-based anomaly detection
│   ├── feature_extractor.py # Sliding-window features
│   ├── train_model.py  # XGBoost training pipeline
│   ├── detector.py     # Real-time scoring loop
│   └── model/          # Saved model artifacts
├── dashboard/          # Streamlit visualization
│   └── app.py          # Live 3-panel dashboard
├── tests/              # Automated tests
├── docker-compose.yml  # Container orchestration
└── .github/workflows/  # CI pipeline
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
- **OfferService** — ECU announces availability (broadcast, every 3s)
- **FindService** — Client queries for a service
- **SubscribeEventgroup** — Client subscribes to events
- **SubscribeEventgroupAck** — Server confirms subscription

## Detection Features

14 features extracted per 2-second window:

| Feature | What it captures |
|:---|:---|
| `msg_count` | Total messages |
| `msg_rate` | Messages per second |
| `unique_services` | Number of distinct services |
| `unique_methods` | Number of distinct methods |
| `unique_sessions` | Session ID diversity |
| `session_id_entropy` | Shannon entropy (replay detection) |
| `sd_offer_count` | SD Offer messages (spoofing detection) |
| `sd_offer_rate` | SD Offers per second |
| `mean_payload_size` | Average payload bytes |
| `std_payload_size` | Payload size variation |
| `request_response_ratio` | Unanswered request detection |
| `notification_ratio` | Event traffic fraction |
| `unique_src_ips` | Source IP diversity |
| `max_burst_rate` | Peak instantaneous rate |

## Limitations & Future Work

> This project proves the **pipeline** works — simulated ECU → attack → detect → visualize. It does **not** prove the detector would catch a real, unseen attacker on production hardware.

**What a production version would need:**
- Real ECU traffic captures (CAN/SOME/IP gateway logs from actual vehicles)
- Broader attack coverage (fuzzing, protocol-level exploits, MITM)
- Latency constraints for embedded deployment (SOME/IP runs on ARM ECUs)
- AUTOSAR-compliant vsomeip integration instead of pure Python
- Adversarial robustness testing (attacks designed to evade the detector)

## Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Just protocol tests
python -m pytest tests/test_proto.py -v

# Just detector tests
python -m pytest tests/test_detector.py -v
```

## License

MIT
