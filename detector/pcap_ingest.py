"""
PCAP ingestion module — converts standard pcap/pcapng captures into
the same internal record format used by traffic_logger.py.

Uses scapy to parse raw packets and extract SOME/IP header fields.
This proves the detection pipeline isn't hard-wired to our own logging
format — it can operate on any standard Wireshark/tshark capture.

Usage:
    # Convert a pcap to our internal JSON-lines format:
    python -m detector.pcap_ingest --input capture.pcap --output traffic_from_pcap.jsonl

    # Feed directly into feature extraction:
    python -m detector.pcap_ingest --input capture.pcap | python -m detector.feature_extractor

Requirements:
    pip install scapy
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from proto.someip import (
    SomeIpHeader,
    MessageType,
    ReturnCode,
    HEADER_SIZE,
    message_type_name,
    unpack_someip,
)
from proto.constants import SD_SERVICE_ID, SD_METHOD_ID

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PCAP_INGEST] %(message)s")
log = logging.getLogger("PcapIngest")


def parse_someip_from_bytes(raw_payload: bytes) -> Optional[dict]:
    """Parse raw UDP payload bytes as a SOME/IP message.

    Returns an internal record dict matching traffic_logger.py schema,
    or None if the payload isn't a valid SOME/IP message.
    """
    if len(raw_payload) < HEADER_SIZE:
        return None

    try:
        msg = unpack_someip(raw_payload)
    except ValueError:
        return None

    h = msg.header

    # Basic sanity: protocol version should be 0x01
    if h.protocol_version != 0x01:
        return None

    return {
        "service_id": f"0x{h.service_id:04X}",
        "method_id": f"0x{h.method_id:04X}",
        "client_id": f"0x{h.client_id:04X}",
        "session_id": f"0x{h.session_id:04X}",
        "message_type": message_type_name(h.message_type),
        "return_code": f"0x{h.return_code:02X}",
        "payload_size": len(msg.payload),
        "payload_hex": msg.payload.hex() if len(msg.payload) <= 256 else msg.payload[:256].hex() + "...",
    }


def ingest_pcap(pcap_path: str, label: str = "normal") -> List[dict]:
    """Read a pcap/pcapng file and extract all SOME/IP messages.

    Returns a list of internal record dicts compatible with
    feature_extractor.py.

    Uses scapy for parsing — falls back to raw UDP payload extraction
    if the SOME/IP dissector layer isn't available.
    """
    try:
        from scapy.all import rdpcap, UDP, IP, Raw
    except ImportError:
        log.error(
            "scapy is required for PCAP ingestion. Install with: pip install scapy"
        )
        return []

    log.info("Reading pcap: %s", pcap_path)
    packets = rdpcap(pcap_path)
    log.info("Loaded %d packets from pcap", len(packets))

    records = []
    someip_count = 0
    skipped = 0

    for pkt in packets:
        # We only care about UDP packets (SOME/IP runs over UDP)
        if not pkt.haslayer(UDP):
            skipped += 1
            continue

        udp = pkt[UDP]

        # Extract the raw UDP payload
        if pkt.haslayer(Raw):
            raw_payload = bytes(pkt[Raw].load)
        else:
            # Some packets may have the payload directly accessible
            raw_payload = bytes(udp.payload)

        if len(raw_payload) < HEADER_SIZE:
            skipped += 1
            continue

        # Try to parse as SOME/IP
        record = parse_someip_from_bytes(raw_payload)
        if record is None:
            skipped += 1
            continue

        # Add packet-level metadata
        timestamp = float(pkt.time)
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        record["timestamp"] = dt.isoformat()

        # Extract IP addresses
        if pkt.haslayer(IP):
            record["src_ip"] = pkt[IP].src
            record["dst_ip"] = pkt[IP].dst
        else:
            record["src_ip"] = ""
            record["dst_ip"] = ""

        record["direction"] = "captured"  # from pcap, direction is ambiguous
        record["label"] = label

        records.append(record)
        someip_count += 1

    log.info(
        "Extracted %d SOME/IP messages (skipped %d non-SOME/IP packets)",
        someip_count, skipped,
    )
    return records


def write_records(records: List[dict], output_path: str) -> None:
    """Write records to a JSON-lines file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for record in records:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
    log.info("Wrote %d records to %s", len(records), output_path)


def ingest_pcap_with_labels(
    pcap_path: str,
    attack_start: Optional[float] = None,
    attack_end: Optional[float] = None,
    attack_label: str = "attack",
) -> List[dict]:
    """Ingest a pcap with time-based labeling.

    If attack_start/attack_end are provided (as epoch seconds),
    records within that range are labeled with attack_label,
    others as "normal".
    """
    records = ingest_pcap(pcap_path, label="normal")

    if attack_start is not None and attack_end is not None:
        labeled_attack = 0
        for record in records:
            ts = datetime.fromisoformat(
                record["timestamp"].replace("Z", "+00:00")
            ).timestamp()
            if attack_start <= ts <= attack_end:
                record["label"] = attack_label
                labeled_attack += 1
        log.info(
            "Labeled %d records as '%s' (%.1fs - %.1fs)",
            labeled_attack, attack_label, attack_start, attack_end,
        )

    return records


def validate_against_feature_extractor(records: List[dict]) -> bool:
    """Verify that pcap-derived records work with the feature extractor."""
    from detector.feature_extractor import compute_window_features, FEATURE_COLUMNS

    if not records:
        log.warning("No records to validate")
        return False

    features = compute_window_features(records, window_seconds=2.0)
    missing = [col for col in FEATURE_COLUMNS if col not in features]
    if missing:
        log.error("Missing features: %s", missing)
        return False

    log.info("Feature extraction validation PASSED")
    log.info("  msg_count=%d, msg_rate=%.1f, unique_services=%d",
             features["msg_count"], features["msg_rate"], features["unique_services"])
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Convert pcap/pcapng files to SOME/IP traffic records"
    )
    parser.add_argument("--input", "-i", required=True, help="Input pcap/pcapng file")
    parser.add_argument("--output", "-o", default=None,
                        help="Output JSON-lines file (default: stdout)")
    parser.add_argument("--label", default="normal",
                        help="Default label for all records")
    parser.add_argument("--attack-start", type=float, default=None,
                        help="Attack start time (epoch seconds)")
    parser.add_argument("--attack-end", type=float, default=None,
                        help="Attack end time (epoch seconds)")
    parser.add_argument("--attack-label", default="attack",
                        help="Label for attack-period records")
    parser.add_argument("--validate", action="store_true",
                        help="Validate records against feature extractor")
    args = parser.parse_args()

    if not Path(args.input).exists():
        log.error("Input file not found: %s", args.input)
        sys.exit(1)

    if args.attack_start is not None:
        records = ingest_pcap_with_labels(
            args.input, args.attack_start, args.attack_end, args.attack_label
        )
    else:
        records = ingest_pcap(args.input, label=args.label)

    if not records:
        log.warning("No SOME/IP records extracted from pcap")
        sys.exit(1)

    if args.validate:
        validate_against_feature_extractor(records)

    if args.output:
        write_records(records, args.output)
    else:
        for record in records:
            print(json.dumps(record, separators=(",", ":")))


if __name__ == "__main__":
    main()
