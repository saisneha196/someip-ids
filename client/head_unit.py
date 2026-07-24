"""
Head-unit client simulator.

Discovers all services via SD, subscribes to their event groups,
and interacts with them on realistic intervals:
  - HVAC:  adjust temperature every 5-10s
  - Media: play/pause/skip every 15-30s
  - Navigation: set destination every 60-90s

Every message sent and received is logged via TrafficLogger.
"""

from __future__ import annotations

import asyncio
import logging
import random
import signal
import socket
import struct
import sys
import time
from typing import Dict, Optional, Tuple

from proto.someip import (
    SomeIpHeader,
    SomeIpMessage,
    MessageType,
    ReturnCode,
    pack_someip,
    unpack_someip,
    HEADER_SIZE,
    message_type_name,
)
from proto.sd import build_subscribe_eventgroup
from proto.constants import (
    HVAC_SERVICE_ID, HVAC_METHODS, HVAC_EVENTGROUPS,
    MEDIA_SERVICE_ID, MEDIA_METHODS, MEDIA_EVENTGROUPS,
    NAV_SERVICE_ID, NAV_METHODS, NAV_EVENTGROUPS,
    SERVICES, SD_PORT,
)
from client.discovery import ServiceDiscovery, ServiceEndpoint
from client.traffic_logger import get_logger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("HeadUnit")

DESTINATIONS = [
    "Home", "Office", "Airport", "Shopping Mall",
    "Hospital", "University", "Gas Station", "Restaurant",
]


class HeadUnit:
    """Simulated head-unit client that interacts with all ECU services."""

    def __init__(self, log_path: str = "/logs/traffic.jsonl"):
        self.traffic_logger = get_logger(log_path)
        self.sd = ServiceDiscovery(
            listen_port=SD_PORT,
            on_service_found=self._on_service_found,
        )
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(2.0)
        # Bind to a specific client port for receiving responses/events
        self._sock.bind(("0.0.0.0", 30600))

        self._session_counter = 0
        self._client_id = 0x0010
        self._running = False
        self._subscribed: set[int] = set()

        # Track own IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self._own_ip = s.getsockname()[0]
            s.close()
        except Exception:
            self._own_ip = "127.0.0.1"

    def _next_session(self) -> int:
        self._session_counter = (self._session_counter % 0xFFFF) + 1
        return self._session_counter

    def _on_service_found(self, endpoint: ServiceEndpoint) -> None:
        """Callback when SD discovers a new service."""
        log.info(
            "Service found: 0x%04X at %s:%d — will subscribe",
            endpoint.service_id, endpoint.ip, endpoint.port,
        )

    # ------------------------------------------------------------------
    # Sending helpers
    # ------------------------------------------------------------------

    def _send_request(
        self,
        service_id: int,
        method_id: int,
        payload: bytes = b"",
    ) -> Optional[SomeIpMessage]:
        """Send a REQUEST and wait for RESPONSE (with timeout)."""
        endpoint = self.sd.get_endpoint(service_id)
        if endpoint is None:
            log.warning("Service 0x%04X not discovered yet", service_id)
            return None

        session = self._next_session()
        header = SomeIpHeader(
            service_id=service_id,
            method_id=method_id,
            client_id=self._client_id,
            session_id=session,
            message_type=MessageType.REQUEST,
        )
        msg_bytes = pack_someip(SomeIpMessage(header=header, payload=payload))
        addr = (endpoint.ip, endpoint.port)

        self._sock.sendto(msg_bytes, addr)
        self.traffic_logger.log(
            header, payload, direction="sent",
            src_ip=self._own_ip, dst_ip=endpoint.ip,
        )
        svc_name = SERVICES.get(service_id, {}).get("name", "?")
        log.info("→ %s method 0x%04X (session=0x%04X)", svc_name, method_id, session)

        # Wait for response
        try:
            resp_data, resp_addr = self._sock.recvfrom(65535)
            resp_msg = unpack_someip(resp_data)
            self.traffic_logger.log(
                resp_msg.header, resp_msg.payload, direction="received",
                src_ip=resp_addr[0], dst_ip=self._own_ip,
            )
            log.info(
                "← %s response (type=%s, rc=0x%02X)",
                svc_name,
                message_type_name(resp_msg.header.message_type),
                resp_msg.header.return_code,
            )
            return resp_msg
        except socket.timeout:
            log.warning("← %s response TIMEOUT", svc_name)
            return None

    def _subscribe_all(self) -> None:
        """Subscribe to all event groups of all discovered services."""
        for service_id, meta in SERVICES.items():
            if service_id in self._subscribed:
                continue
            endpoint = self.sd.get_endpoint(service_id)
            if endpoint is None:
                continue

            for eg_name, eg_id in meta["eventgroups"].items():
                sub_msg = build_subscribe_eventgroup(
                    service_id, meta["instance_id"], eg_id,
                )
                self._sock.sendto(sub_msg, (endpoint.ip, endpoint.port))
                log.info(
                    "SUBSCRIBE %s.%s (0x%04X.0x%04X)",
                    meta["name"], eg_name, service_id, eg_id,
                )
            self._subscribed.add(service_id)

    # ------------------------------------------------------------------
    # Service interaction loops
    # ------------------------------------------------------------------

    async def _interact_hvac(self) -> None:
        """Periodically adjust HVAC temperature."""
        while self._running:
            await asyncio.sleep(random.uniform(5, 10))
            if not self.sd.get_endpoint(HVAC_SERVICE_ID):
                continue

            zone = random.randint(1, 4)
            temp = round(random.uniform(18.0, 28.0), 1)
            payload = struct.pack("!Hf", zone, temp)
            self._send_request(
                HVAC_SERVICE_ID, HVAC_METHODS["SetTemperature"], payload
            )

            # Also occasionally read temperature
            if random.random() < 0.3:
                await asyncio.sleep(1)
                get_payload = struct.pack("!H", zone)
                resp = self._send_request(
                    HVAC_SERVICE_ID, HVAC_METHODS["GetTemperature"], get_payload
                )
                if resp and resp.payload:
                    temp_val = struct.unpack("!f", resp.payload[:4])[0]
                    log.info("HVAC zone %d temperature: %.1f°C", zone, temp_val)

    async def _interact_media(self) -> None:
        """Periodically play/pause/skip media."""
        while self._running:
            await asyncio.sleep(random.uniform(15, 30))
            if not self.sd.get_endpoint(MEDIA_SERVICE_ID):
                continue

            action = random.choice(["Play", "Pause", "NextTrack"])
            self._send_request(MEDIA_SERVICE_ID, MEDIA_METHODS[action])

    async def _interact_nav(self) -> None:
        """Periodically set navigation destination."""
        while self._running:
            await asyncio.sleep(random.uniform(60, 90))
            if not self.sd.get_endpoint(NAV_SERVICE_ID):
                continue

            dest = random.choice(DESTINATIONS)
            dest_bytes = dest.encode("utf-8")
            payload = struct.pack("!H", len(dest_bytes)) + dest_bytes
            self._send_request(
                NAV_SERVICE_ID, NAV_METHODS["SetDestination"], payload
            )

    async def _event_listener(self) -> None:
        """Listen for incoming events (NOTIFICATION messages)."""
        loop = asyncio.get_event_loop()
        # Create a second socket dedicated to receiving events
        event_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        event_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        event_sock.settimeout(1.0)
        event_sock.bind(("0.0.0.0", 30601))

        while self._running:
            try:
                data, addr = await loop.run_in_executor(
                    None, lambda: event_sock.recvfrom(65535)
                )
                msg = unpack_someip(data)
                self.traffic_logger.log(
                    msg.header, msg.payload, direction="received",
                    src_ip=addr[0], dst_ip=self._own_ip,
                )
                if msg.header.message_type == MessageType.NOTIFICATION:
                    svc_name = SERVICES.get(msg.header.service_id, {}).get("name", "?")
                    log.info(
                        "📡 EVENT from %s: method=0x%04X, %d bytes",
                        svc_name, msg.header.method_id, len(msg.payload),
                    )
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    log.debug("Event listener: %s", e)

        event_sock.close()

    async def _subscription_loop(self) -> None:
        """Keep trying to subscribe until all services are found."""
        while self._running:
            self._subscribe_all()
            if self.sd.all_discovered(list(SERVICES.keys())):
                log.info("All services discovered and subscribed!")
                # Re-subscribe periodically to maintain TTL
                while self._running:
                    await asyncio.sleep(8)
                    self._subscribed.clear()
                    self._subscribe_all()
            await asyncio.sleep(2)

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start all client loops."""
        self._running = True
        log.info("Head unit starting — discovering services...")

        try:
            await asyncio.gather(
                self.sd.listen(),
                self._subscription_loop(),
                self._interact_hvac(),
                self._interact_media(),
                self._interact_nav(),
                self._event_listener(),
            )
        except asyncio.CancelledError:
            log.info("Head unit shutting down")
        finally:
            self._running = False
            self.sd.stop()
            self._sock.close()


def main():
    import os
    log_path = os.environ.get("LOG_PATH", "/logs/traffic.jsonl")
    head_unit = HeadUnit(log_path=log_path)

    loop = asyncio.new_event_loop()

    def _shutdown():
        head_unit._running = False
        head_unit.sd.stop()
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    try:
        loop.run_until_complete(head_unit.run())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    main()
