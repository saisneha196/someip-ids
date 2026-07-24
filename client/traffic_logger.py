"""
Traffic logger — writes every SOME/IP message to a shared JSON-lines file.

Each line is a self-contained JSON object with all header fields,
payload metadata, and a label for supervised training.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from proto.someip import SomeIpHeader, message_type_name


class TrafficLogger:
    """Thread-safe, append-only JSON-lines logger for SOME/IP traffic."""

    def __init__(self, log_path: str = "/logs/traffic.jsonl"):
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._file = open(self._log_path, "a", buffering=1)  # line-buffered

    def log(
        self,
        header: SomeIpHeader,
        payload: bytes,
        direction: str,
        src_ip: str = "",
        dst_ip: str = "",
        label: str = "normal",
    ) -> None:
        """Append a single traffic record."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": direction,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service_id": f"0x{header.service_id:04X}",
            "method_id": f"0x{header.method_id:04X}",
            "client_id": f"0x{header.client_id:04X}",
            "session_id": f"0x{header.session_id:04X}",
            "message_type": message_type_name(header.message_type),
            "return_code": f"0x{header.return_code:02X}",
            "payload_size": len(payload),
            "payload_hex": payload.hex() if len(payload) <= 256 else payload[:256].hex() + "...",
            "label": label,
        }
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            self._file.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._file.close()


# Module-level singleton for convenience
_default_logger: Optional[TrafficLogger] = None
_init_lock = threading.Lock()


def get_logger(log_path: str = "/logs/traffic.jsonl") -> TrafficLogger:
    """Get or create the module-level TrafficLogger singleton."""
    global _default_logger
    with _init_lock:
        if _default_logger is None:
            _default_logger = TrafficLogger(log_path)
    return _default_logger
