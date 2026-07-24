"""
Service Discovery listener — client side.

Listens for SD OfferService broadcasts and maintains a live
service registry mapping service_id → (ip, port).

Works on Docker bridge networks by listening for broadcast
UDP on the SD port (30490).
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from proto.someip import unpack_someip, HEADER_SIZE
from proto.sd import SdEntryType, parse_sd_message
from proto.constants import SD_PORT, SD_MULTICAST_GROUP, SERVICES

log = logging.getLogger("Discovery")


@dataclass
class ServiceEndpoint:
    """Discovered service endpoint."""
    service_id: int
    instance_id: int
    ip: str
    port: int
    major_version: int = 1
    ttl: int = 10
    discovered_at: float = field(default_factory=time.time)


class ServiceDiscovery:
    """Listens for SD Offer messages and maintains a registry of discovered services."""

    def __init__(
        self,
        listen_port: int = SD_PORT,
        on_service_found: Optional[Callable[[ServiceEndpoint], None]] = None,
    ):
        self.listen_port = listen_port
        self.on_service_found = on_service_found

        # Registry:  service_id → ServiceEndpoint
        self.registry: Dict[int, ServiceEndpoint] = {}
        self._lock = threading.Lock()
        self._running = False
        self._sock: Optional[socket.socket] = None

    def get_endpoint(self, service_id: int) -> Optional[ServiceEndpoint]:
        """Look up a discovered service by ID."""
        with self._lock:
            return self.registry.get(service_id)

    def all_discovered(self, expected_ids: List[int]) -> bool:
        """Check if all expected services have been discovered."""
        with self._lock:
            return all(sid in self.registry for sid in expected_ids)

    async def listen(self) -> None:
        """Main discovery loop — receive and parse SD broadcasts."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.settimeout(1.0)
        self._sock.bind(("0.0.0.0", self.listen_port))

        # Try to join multicast group (may fail on some Docker setups — that's ok)
        try:
            mreq = struct.pack(
                "4sl",
                socket.inet_aton(SD_MULTICAST_GROUP),
                socket.INADDR_ANY,
            )
            self._sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq
            )
            log.info("Joined multicast group %s", SD_MULTICAST_GROUP)
        except Exception as e:
            log.info("Multicast join skipped (using broadcast): %s", e)

        self._running = True
        log.info("Listening for SD offers on port %d", self.listen_port)

        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, addr = await loop.run_in_executor(
                    None, lambda: self._sock.recvfrom(65535)
                )
                self._process_sd(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    log.warning("SD receive error: %s", e)

    def _process_sd(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Parse SD message and update registry."""
        entries = parse_sd_message(data)
        for entry in entries:
            if entry.entry_type == SdEntryType.OFFER_SERVICE and entry.ttl > 0:
                # Extract endpoint from the entry's option
                if entry.option is not None:
                    ip = entry.option.ip
                    port = entry.option.port
                else:
                    # Fallback to sender's address
                    ip = addr[0]
                    port = addr[1]

                endpoint = ServiceEndpoint(
                    service_id=entry.service_id,
                    instance_id=entry.instance_id,
                    ip=ip,
                    port=port,
                    major_version=entry.major_version,
                    ttl=entry.ttl,
                )

                is_new = False
                with self._lock:
                    if entry.service_id not in self.registry:
                        is_new = True
                    self.registry[entry.service_id] = endpoint

                svc_name = SERVICES.get(entry.service_id, {}).get("name", f"0x{entry.service_id:04X}")
                if is_new:
                    log.info(
                        "DISCOVERED %s (0x%04X) at %s:%d",
                        svc_name, entry.service_id, ip, port,
                    )
                    if self.on_service_found:
                        self.on_service_found(endpoint)
                else:
                    log.debug("Refreshed %s offer (TTL=%d)", svc_name, entry.ttl)

            elif entry.entry_type == SdEntryType.OFFER_SERVICE and entry.ttl == 0:
                # StopOffer
                with self._lock:
                    self.registry.pop(entry.service_id, None)
                log.info("Service 0x%04X stopped offering", entry.service_id)

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()
