"""
Abstract base service for simulated ECU containers.

Handles:
  - Binding a UDP socket on a configured port
  - Periodic SD OfferService broadcasts
  - Incoming SOME/IP request dispatch to registered method handlers
  - Event subscription tracking + notification push
  - Traffic logging of every sent/received message
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import socket
import struct
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from proto.someip import (
    SomeIpHeader,
    SomeIpMessage,
    MessageType,
    ReturnCode,
    pack_someip,
    unpack_someip,
    HEADER_SIZE,
)
from proto.sd import (
    SdEntryType,
    build_offer_service,
    build_subscribe_ack,
    parse_sd_message,
)
from proto.constants import SD_SERVICE_ID, SD_METHOD_ID, SD_PORT
from client.traffic_logger import get_logger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


@dataclass
class Subscriber:
    """A client that has subscribed to an event group."""
    address: Tuple[str, int]  # (ip, port)
    eventgroup_id: int
    client_id: int


class BaseService(ABC):
    """Abstract simulated ECU service."""

    def __init__(
        self,
        service_id: int,
        instance_id: int,
        service_name: str,
        bind_ip: str = "0.0.0.0",
        port: int = 30501,
        sd_broadcast_ip: str = "255.255.255.255",
        sd_port: int = SD_PORT,
        offer_interval: float = 3.0,
        log_path: str = "/logs/traffic.jsonl",
    ):
        self.service_id = service_id
        self.instance_id = instance_id
        self.service_name = service_name
        self.bind_ip = bind_ip
        self.port = port
        self.sd_broadcast_ip = sd_broadcast_ip
        self.sd_port = sd_port
        self.offer_interval = offer_interval

        self.logger = get_logger(log_path)
        self.log = logging.getLogger(service_name)

        # Method dispatch table:  method_id → handler(payload, client_addr) → response_payload
        self._method_handlers: Dict[int, Callable] = {}

        # Event subscribers:  eventgroup_id → set of Subscriber
        self._subscribers: Dict[int, List[Subscriber]] = {}

        # Session counter for outgoing messages
        self._session_counter = 0

        # Will be set during run()
        self._sock: Optional[socket.socket] = None
        self._own_ip: str = ""
        self._running = False

    # ------------------------------------------------------------------
    # Registration API for subclasses
    # ------------------------------------------------------------------

    def register_method(self, method_id: int, handler: Callable) -> None:
        """Register a method handler. Handler signature:
        ``handler(payload: bytes, client_addr: tuple) -> bytes``
        """
        self._method_handlers[method_id] = handler

    def _next_session(self) -> int:
        self._session_counter = (self._session_counter % 0xFFFF) + 1
        return self._session_counter

    # ------------------------------------------------------------------
    # Event notification
    # ------------------------------------------------------------------

    def notify_event(
        self,
        eventgroup_id: int,
        event_id: int,
        payload: bytes,
    ) -> None:
        """Push a NOTIFICATION to all subscribers of the given event group."""
        subscribers = self._subscribers.get(eventgroup_id, [])
        if not subscribers:
            return

        header = SomeIpHeader(
            service_id=self.service_id,
            method_id=event_id | 0x8000,  # MSB=1 marks an event
            client_id=0x0000,
            session_id=self._next_session(),
            message_type=MessageType.NOTIFICATION,
            return_code=ReturnCode.E_OK,
        )
        msg_bytes = pack_someip(SomeIpMessage(header=header, payload=payload))

        for sub in subscribers:
            try:
                self._sock.sendto(msg_bytes, sub.address)
                self.logger.log(
                    header, payload, direction="sent",
                    src_ip=self._own_ip, dst_ip=sub.address[0],
                )
                self.log.debug(
                    "EVENT 0x%04X → %s:%d", event_id, sub.address[0], sub.address[1]
                )
            except Exception as e:
                self.log.warning("Failed to send event to %s: %s", sub.address, e)

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    def _handle_incoming(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Dispatch an incoming UDP datagram."""
        try:
            msg = unpack_someip(data)
        except ValueError as e:
            self.log.warning("Malformed SOME/IP from %s: %s", addr, e)
            return

        h = msg.header

        # Log incoming
        self.logger.log(
            h, msg.payload, direction="received",
            src_ip=addr[0], dst_ip=self._own_ip,
        )

        # --- SD message? ---
        if h.service_id == SD_SERVICE_ID and h.method_id == SD_METHOD_ID:
            self._handle_sd(data, addr)
            return

        # --- Method request? ---
        if h.message_type == MessageType.REQUEST:
            handler = self._method_handlers.get(h.method_id)
            if handler is None:
                self.log.warning(
                    "Unknown method 0x%04X from %s", h.method_id, addr
                )
                self._send_error(h, addr, ReturnCode.E_UNKNOWN_METHOD)
                return

            try:
                response_payload = handler(msg.payload, addr)
            except Exception as e:
                self.log.error("Handler error for 0x%04X: %s", h.method_id, e)
                self._send_error(h, addr, ReturnCode.E_NOT_OK)
                return

            # Send response
            resp_header = SomeIpHeader(
                service_id=h.service_id,
                method_id=h.method_id,
                client_id=h.client_id,
                session_id=h.session_id,
                message_type=MessageType.RESPONSE,
                return_code=ReturnCode.E_OK,
            )
            resp_bytes = pack_someip(
                SomeIpMessage(header=resp_header, payload=response_payload)
            )
            self._sock.sendto(resp_bytes, addr)
            self.logger.log(
                resp_header, response_payload, direction="sent",
                src_ip=self._own_ip, dst_ip=addr[0],
            )

    def _send_error(
        self, req_header: SomeIpHeader, addr: Tuple[str, int], code: int
    ) -> None:
        err_header = SomeIpHeader(
            service_id=req_header.service_id,
            method_id=req_header.method_id,
            client_id=req_header.client_id,
            session_id=req_header.session_id,
            message_type=MessageType.ERROR,
            return_code=code,
        )
        self._sock.sendto(pack_someip(SomeIpMessage(header=err_header)), addr)

    def _handle_sd(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Process incoming SD messages — handle SubscribeEventgroup."""
        entries = parse_sd_message(data)
        for entry in entries:
            if (
                entry.entry_type == SdEntryType.SUBSCRIBE_EVENTGROUP
                and entry.service_id == self.service_id
            ):
                self.log.info(
                    "SUBSCRIBE eventgroup 0x%04X from %s",
                    entry.eventgroup_id, addr,
                )
                sub = Subscriber(
                    address=addr,
                    eventgroup_id=entry.eventgroup_id,
                    client_id=0,
                )
                subs = self._subscribers.setdefault(entry.eventgroup_id, [])
                # Avoid duplicates
                if not any(s.address == addr for s in subs):
                    subs.append(sub)

                # Send SubscribeAck
                ack = build_subscribe_ack(
                    self.service_id, self.instance_id, entry.eventgroup_id,
                )
                self._sock.sendto(ack, addr)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _get_own_ip(self) -> str:
        """Determine own IP by connecting to an external address (no actual traffic)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    async def _offer_loop(self) -> None:
        """Periodically broadcast SD Offer Service."""
        while self._running:
            offer = build_offer_service(
                self.service_id,
                self.instance_id,
                self._own_ip,
                self.port,
            )
            try:
                self._sock.sendto(offer, (self.sd_broadcast_ip, self.sd_port))
                self.log.info(
                    "OFFER service 0x%04X at %s:%d",
                    self.service_id, self._own_ip, self.port,
                )
            except Exception as e:
                self.log.warning("Offer broadcast failed: %s", e)
            await asyncio.sleep(self.offer_interval)

    async def _receive_loop(self) -> None:
        """Receive incoming UDP datagrams on the service port."""
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, addr = await loop.run_in_executor(
                    None, lambda: self._sock.recvfrom(65535)
                )
                self._handle_incoming(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    self.log.error("Receive error: %s", e)

    @abstractmethod
    async def _service_loop(self) -> None:
        """Subclass-specific periodic behavior (state changes, events)."""
        ...

    async def run(self) -> None:
        """Main entry point — start offering, receiving, and running."""
        self._own_ip = self._get_own_ip()
        self.log.info("Starting %s at %s:%d", self.service_name, self._own_ip, self.port)

        # Create and bind UDP socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.settimeout(0.5)
        self._sock.bind((self.bind_ip, self.port))

        self._running = True

        # Run all loops concurrently
        try:
            await asyncio.gather(
                self._offer_loop(),
                self._receive_loop(),
                self._service_loop(),
            )
        except asyncio.CancelledError:
            self.log.info("Service shutting down")
        finally:
            self._running = False
            self._sock.close()


def run_service(service: BaseService) -> None:
    """Convenience: run a service with proper signal handling."""
    loop = asyncio.new_event_loop()

    def _shutdown():
        service._running = False
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    try:
        loop.run_until_complete(service.run())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.close()
