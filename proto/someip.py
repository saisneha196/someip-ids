"""
SOME/IP message header codec — pure Python, per AUTOSAR SOME/IP spec R22-11.

Header layout (16 bytes, network / big-endian byte order):

    Offset  Size   Field
    ------  -----  ---------------------------
     0      16b    Service ID
     2      16b    Method ID  (MSB=1 → event)
     4      32b    Length     (8 + payload len)
     8      16b    Client ID
    10      16b    Session ID
    12       8b    Protocol Version  (0x01)
    13       8b    Interface Version
    14       8b    Message Type
    15       8b    Return Code
    16..     var    Payload
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class MessageType(IntEnum):
    """SOME/IP message types (AUTOSAR Table 4.2)."""
    REQUEST = 0x00
    REQUEST_NO_RETURN = 0x01
    NOTIFICATION = 0x02
    RESPONSE = 0x80
    ERROR = 0x81
    TP_REQUEST = 0x20
    TP_REQUEST_NO_RETURN = 0x21
    TP_NOTIFICATION = 0x22
    TP_RESPONSE = 0xA0
    TP_ERROR = 0xA1


class ReturnCode(IntEnum):
    """SOME/IP return codes (AUTOSAR Table 4.6, subset)."""
    E_OK = 0x00
    E_NOT_OK = 0x01
    E_UNKNOWN_SERVICE = 0x02
    E_UNKNOWN_METHOD = 0x03
    E_NOT_READY = 0x04
    E_NOT_REACHABLE = 0x05
    E_TIMEOUT = 0x06
    E_WRONG_PROTOCOL_VERSION = 0x07
    E_WRONG_INTERFACE_VERSION = 0x08
    E_MALFORMED_MESSAGE = 0x09
    E_WRONG_MESSAGE_TYPE = 0x0A


# ---------------------------------------------------------------------------
# Header format string — all big-endian
# ---------------------------------------------------------------------------
#   H = uint16  (Service ID)
#   H = uint16  (Method ID)
#   I = uint32  (Length)
#   H = uint16  (Client ID)
#   H = uint16  (Session ID)
#   B = uint8   (Protocol Version)
#   B = uint8   (Interface Version)
#   B = uint8   (Message Type)
#   B = uint8   (Return Code)
_HEADER_FMT = "!HHIHHBBBB"
HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # == 16


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SomeIpHeader:
    """Parsed SOME/IP header fields."""
    service_id: int
    method_id: int
    client_id: int = 0x0000
    session_id: int = 0x0001
    protocol_version: int = 0x01
    interface_version: int = 0x01
    message_type: int = MessageType.REQUEST
    return_code: int = ReturnCode.E_OK


@dataclass
class SomeIpMessage:
    """Complete SOME/IP message = header + payload."""
    header: SomeIpHeader
    payload: bytes = b""


# ---------------------------------------------------------------------------
# Pack / unpack
# ---------------------------------------------------------------------------

def pack_someip(msg: SomeIpMessage) -> bytes:
    """Serialize a SomeIpMessage into raw bytes ready for the wire.

    The *Length* field is computed automatically as
    ``8 + len(payload)`` (covers Request-ID through end of payload).
    """
    h = msg.header
    length = 8 + len(msg.payload)  # client(2)+session(2)+proto(1)+iface(1)+type(1)+rc(1) + payload
    header_bytes = struct.pack(
        _HEADER_FMT,
        h.service_id,
        h.method_id,
        length,
        h.client_id,
        h.session_id,
        h.protocol_version,
        h.interface_version,
        h.message_type,
        h.return_code,
    )
    return header_bytes + msg.payload


def unpack_someip(data: bytes) -> SomeIpMessage:
    """Deserialize raw bytes into a SomeIpMessage.

    Raises ``ValueError`` if the buffer is shorter than the 16-byte
    header or if the declared length exceeds available data.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"Buffer too short for SOME/IP header: {len(data)} < {HEADER_SIZE}"
        )

    (
        service_id,
        method_id,
        length,
        client_id,
        session_id,
        protocol_version,
        interface_version,
        message_type,
        return_code,
    ) = struct.unpack(_HEADER_FMT, data[:HEADER_SIZE])

    payload_length = length - 8
    if payload_length < 0:
        raise ValueError(f"Invalid SOME/IP length field: {length}")

    payload = data[HEADER_SIZE : HEADER_SIZE + payload_length]

    header = SomeIpHeader(
        service_id=service_id,
        method_id=method_id,
        client_id=client_id,
        session_id=session_id,
        protocol_version=protocol_version,
        interface_version=interface_version,
        message_type=message_type,
        return_code=return_code,
    )
    return SomeIpMessage(header=header, payload=payload)


def message_type_name(mt: int) -> str:
    """Human-readable name for a message-type byte."""
    try:
        return MessageType(mt).name
    except ValueError:
        return f"UNKNOWN(0x{mt:02X})"
