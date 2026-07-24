"""
Media / Infotainment simulated ECU service.

State:
  - track_index: int (0-based)
  - playing: bool
  - playlist: list of track names

Methods:
  - Play()   → starts playback
  - Pause()  → pauses playback
  - NextTrack() → advances to next track

Events:
  - TrackChanged (eventgroup 0x0001, event 0x0001)
    Payload: track_index(uint16) + track_name(utf-8, length-prefixed)
"""

from __future__ import annotations

import asyncio
import random
import struct

from services.base_service import BaseService, run_service
from proto.constants import (
    MEDIA_SERVICE_ID,
    MEDIA_INSTANCE_ID,
    MEDIA_METHODS,
    MEDIA_EVENTGROUPS,
    MEDIA_PORT,
)


PLAYLIST = [
    "Highway Star - Deep Purple",
    "Comfortably Numb - Pink Floyd",
    "Bohemian Rhapsody - Queen",
    "Hotel California - Eagles",
    "Stairway to Heaven - Led Zeppelin",
    "Back in Black - AC/DC",
    "Smells Like Teen Spirit - Nirvana",
    "Sweet Child O Mine - Guns N Roses",
]


class MediaService(BaseService):
    """Simulated media / infotainment ECU."""

    def __init__(self, **kwargs):
        super().__init__(
            service_id=MEDIA_SERVICE_ID,
            instance_id=MEDIA_INSTANCE_ID,
            service_name="Media",
            port=MEDIA_PORT,
            **kwargs,
        )
        self.track_index = 0
        self.playing = False
        self.playlist = list(PLAYLIST)

        self.register_method(MEDIA_METHODS["Play"], self._handle_play)
        self.register_method(MEDIA_METHODS["Pause"], self._handle_pause)
        self.register_method(MEDIA_METHODS["NextTrack"], self._handle_next)

    def _track_payload(self) -> bytes:
        """Build the TrackChanged event payload."""
        name = self.playlist[self.track_index].encode("utf-8")
        return struct.pack("!HH", self.track_index, len(name)) + name

    def _handle_play(self, payload: bytes, addr) -> bytes:
        self.playing = True
        self.log.info("▶ Play — track %d: %s", self.track_index, self.playlist[self.track_index])
        return b"\x01"  # 1 = success

    def _handle_pause(self, payload: bytes, addr) -> bytes:
        self.playing = False
        self.log.info("⏸ Pause")
        return b"\x01"

    def _handle_next(self, payload: bytes, addr) -> bytes:
        self.track_index = (self.track_index + 1) % len(self.playlist)
        self.log.info("⏭ NextTrack → %d: %s", self.track_index, self.playlist[self.track_index])

        self.notify_event(
            MEDIA_EVENTGROUPS["TrackChanged"],
            0x0001,
            self._track_payload(),
        )
        return struct.pack("!H", self.track_index)

    async def _service_loop(self) -> None:
        """Auto-advance track every 30-60s while playing."""
        while self._running:
            await asyncio.sleep(random.uniform(30, 60))
            if self.playing:
                self.track_index = (self.track_index + 1) % len(self.playlist)
                self.log.info(
                    "Auto-advance → track %d: %s",
                    self.track_index, self.playlist[self.track_index],
                )
                self.notify_event(
                    MEDIA_EVENTGROUPS["TrackChanged"],
                    0x0001,
                    self._track_payload(),
                )


if __name__ == "__main__":
    run_service(MediaService())
