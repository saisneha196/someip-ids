"""
Navigation simulated ECU service.

State:
  - current_destination: str
  - route_status: str  ("idle", "calculating", "active")
  - eta_minutes: int

Methods:
  - SetDestination(dest_str: utf-8) → ()

Events:
  - RouteUpdated (eventgroup 0x0001, event 0x0001)
    Payload: status(uint8) + eta_minutes(uint16) + dest_name(utf-8, length-prefixed)
"""

from __future__ import annotations

import asyncio
import random
import struct

from services.base_service import BaseService, run_service
from proto.constants import (
    NAV_SERVICE_ID,
    NAV_INSTANCE_ID,
    NAV_METHODS,
    NAV_EVENTGROUPS,
    NAV_PORT,
)


SAMPLE_DESTINATIONS = [
    "Home",
    "Office",
    "Airport",
    "Shopping Mall",
    "Hospital",
    "University",
    "Gas Station",
    "Restaurant",
]


class NavigationService(BaseService):
    """Simulated navigation ECU."""

    def __init__(self, **kwargs):
        super().__init__(
            service_id=NAV_SERVICE_ID,
            instance_id=NAV_INSTANCE_ID,
            service_name="Navigation",
            port=NAV_PORT,
            **kwargs,
        )
        self.current_destination = ""
        self.route_status = 0  # 0=idle, 1=calculating, 2=active
        self.eta_minutes = 0

        self.register_method(
            NAV_METHODS["SetDestination"], self._handle_set_destination
        )

    def _route_payload(self) -> bytes:
        dest_bytes = self.current_destination.encode("utf-8")
        return (
            struct.pack("!BHH", self.route_status, self.eta_minutes, len(dest_bytes))
            + dest_bytes
        )

    def _handle_set_destination(self, payload: bytes, addr) -> bytes:
        if len(payload) < 2:
            return b"\x00"
        name_len = struct.unpack("!H", payload[:2])[0]
        dest = payload[2 : 2 + name_len].decode("utf-8", errors="replace")

        self.current_destination = dest
        self.route_status = 1  # calculating
        self.eta_minutes = random.randint(5, 120)
        self.log.info("SetDestination: '%s' — calculating route (ETA: %d min)", dest, self.eta_minutes)

        # Immediately fire RouteUpdated with "calculating" status
        self.notify_event(
            NAV_EVENTGROUPS["RouteUpdated"],
            0x0001,
            self._route_payload(),
        )

        # Schedule transition to "active" after a short delay
        asyncio.get_event_loop().call_later(2.0, self._activate_route)

        return b"\x01"

    def _activate_route(self) -> None:
        if self.route_status == 1:
            self.route_status = 2  # active
            self.log.info("Route active: '%s' ETA %d min", self.current_destination, self.eta_minutes)
            self.notify_event(
                NAV_EVENTGROUPS["RouteUpdated"],
                0x0001,
                self._route_payload(),
            )

    async def _service_loop(self) -> None:
        """Simulate ETA countdown while route is active."""
        while self._running:
            await asyncio.sleep(random.uniform(15, 30))
            if self.route_status == 2 and self.eta_minutes > 0:
                self.eta_minutes = max(0, self.eta_minutes - random.randint(1, 5))
                self.log.debug("ETA update: %d min", self.eta_minutes)
                self.notify_event(
                    NAV_EVENTGROUPS["RouteUpdated"],
                    0x0001,
                    self._route_payload(),
                )
                if self.eta_minutes == 0:
                    self.route_status = 0
                    self.log.info("Arrived at '%s'!", self.current_destination)


if __name__ == "__main__":
    run_service(NavigationService())
