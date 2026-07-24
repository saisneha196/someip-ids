"""
HVAC (Heating, Ventilation, Air Conditioning) simulated ECU service.

State:
  - zones: dict mapping zone_id (int) to temperature (float, °C)

Methods:
  - SetTemperature(zone: uint16, value: float32) → ()
  - GetTemperature(zone: uint16) → (value: float32)

Events:
  - TemperatureChanged (eventgroup 0x0001, event 0x0001)
    Payload: zone(uint16) + temperature(float32)
"""

from __future__ import annotations

import asyncio
import random
import struct

from services.base_service import BaseService, run_service
from proto.constants import (
    HVAC_SERVICE_ID,
    HVAC_INSTANCE_ID,
    HVAC_METHODS,
    HVAC_EVENTGROUPS,
    HVAC_PORT,
)


class HvacService(BaseService):
    """Simulated HVAC ECU."""

    def __init__(self, **kwargs):
        super().__init__(
            service_id=HVAC_SERVICE_ID,
            instance_id=HVAC_INSTANCE_ID,
            service_name="HVAC",
            port=HVAC_PORT,
            **kwargs,
        )

        # Internal state: 4 climate zones, default 22°C
        self.zones: dict[int, float] = {z: 22.0 for z in range(1, 5)}

        # Register method handlers
        self.register_method(
            HVAC_METHODS["SetTemperature"], self._handle_set_temperature
        )
        self.register_method(
            HVAC_METHODS["GetTemperature"], self._handle_get_temperature
        )

    def _handle_set_temperature(self, payload: bytes, addr) -> bytes:
        """SetTemperature(zone: u16, value: f32) → empty response."""
        if len(payload) < 6:
            return b""
        zone, value = struct.unpack("!Hf", payload[:6])
        old_value = self.zones.get(zone, 22.0)
        self.zones[zone] = round(value, 1)
        self.log.info("SetTemperature zone=%d: %.1f → %.1f", zone, old_value, value)

        # Fire TemperatureChanged event
        event_payload = struct.pack("!Hf", zone, self.zones[zone])
        self.notify_event(
            HVAC_EVENTGROUPS["TemperatureChanged"],
            0x0001,  # event ID
            event_payload,
        )
        return b""

    def _handle_get_temperature(self, payload: bytes, addr) -> bytes:
        """GetTemperature(zone: u16) → (value: f32)."""
        if len(payload) < 2:
            return struct.pack("!f", 22.0)
        zone = struct.unpack("!H", payload[:2])[0]
        temp = self.zones.get(zone, 22.0)
        return struct.pack("!f", temp)

    async def _service_loop(self) -> None:
        """Simulate ambient temperature drift every 10-20s."""
        while self._running:
            await asyncio.sleep(random.uniform(10, 20))
            zone = random.choice(list(self.zones.keys()))
            drift = random.uniform(-0.5, 0.5)
            self.zones[zone] = round(self.zones[zone] + drift, 1)
            self.log.debug("Ambient drift: zone %d → %.1f°C", zone, self.zones[zone])

            # Fire event for the drift
            event_payload = struct.pack("!Hf", zone, self.zones[zone])
            self.notify_event(
                HVAC_EVENTGROUPS["TemperatureChanged"],
                0x0001,
                event_payload,
            )


if __name__ == "__main__":
    run_service(HvacService())
