"""
SOME/IP Service Discovery (SOME/IP-SD) message builder and parser.

SD messages ride inside a normal SOME/IP frame with the well-known
identifiers:
    Service ID  = 0xFFFF
    Method ID   = 0x8100
    Message Type = NOTIFICATION (0x02)
    Client ID   = 0x0000

The SD payload structure:

    Offset  Size   Field
    ------  -----  --------------------------------
     0       8b    Flags  (bit 7 = Reboot flag)
     1      24b    Reserved (0x000000)
     4      32b    Length of Entries Array (in bytes)
     8      var    Entries Array
     8+E    32b    Length of Options Array (in bytes)
    12+E    var    Options Array

Each *Service Entry* is 16 bytes:
     0       8b    Type  (0x01 = FindService, 0x06 = OfferService)
     1       8b    Index 1st Options
     2       4b    Index 2nd Options
     2.5     4b    # of Opt 1  |  # of Opt 2  (packed nibbles)
     3       8b    (cont. from above — combined byte)
     4      16b    Service ID
     6      16b    Instance ID
     8       8b    Major Version
     9      24b    TTL (seconds, 0 = StopOffer)
    12      32b    Minor Version

Each *Eventgroup Entry* is 16 bytes (Type = 0x06 Subscribe, 0x07 SubscribeAck):
     Same layout but last 4 bytes differ:
    12      12b    Reserved
    12.5     4b    Counter
    14      16b    Eventgroup ID

IPv4 Endpoint Option (12 bytes):
     0      16b    Length of option (excl. this field) = 0x0009
     2       8b    Type = 0x04 (IPv4 Endpoint)
     3       8b    Reserved
     4      32b    IPv4 address
     8       8b    L4 Protocol (0x11 = UDP, 0x06 = TCP)
     9      16b    Port number
    (total = 12 bytes, but 'Length' field says 9 because it excludes
     the 2-byte length + 1-byte type prefix.)
"""

from __future__ import annotations

import hmac
import hashlib
import struct
import socket
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional

from .someip import (
    SomeIpHeader,
    SomeIpMessage,
    MessageType,
    ReturnCode,
    pack_someip,
    unpack_someip,
    HEADER_SIZE,
)
from .constants import SD_SERVICE_ID, SD_METHOD_ID


# ---------------------------------------------------------------------------
# SD entry types
# ---------------------------------------------------------------------------

class SdEntryType(IntEnum):
    FIND_SERVICE = 0x00
    OFFER_SERVICE = 0x01
    SUBSCRIBE_EVENTGROUP = 0x06
    SUBSCRIBE_EVENTGROUP_ACK = 0x07


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SdIpv4Option:
    """IPv4 Endpoint option carried in the SD Options array."""
    ip: str
    port: int
    protocol: int = 0x11  # 0x11=UDP, 0x06=TCP


@dataclass
class SdEntry:
    """A single SD entry (service or eventgroup)."""
    entry_type: int
    service_id: int
    instance_id: int
    major_version: int = 1
    ttl: int = 10
    minor_version: int = 0
    eventgroup_id: int = 0  # only for subscribe entries
    option: Optional[SdIpv4Option] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pack_service_entry(
    entry_type: int,
    service_id: int,
    instance_id: int,
    major_version: int,
    ttl: int,
    minor_version: int,
    opt_index: int = 0,
    num_opts: int = 0,
) -> bytes:
    """Pack a 16-byte Type-1 SD service entry."""
    # Byte 0: type
    # Byte 1: index 1st options run
    # Byte 2: index 2nd options run (hi nibble) | # of opt 1 (lo nibble)
    # Byte 3: # of opt 2 (hi nibble) | 0 (lo nibble)  — we keep it simple
    idx2_numopt1 = (0 << 4) | (num_opts & 0x0F)
    numopt2 = 0

    # major_version(8b) + TTL(24b) = one 32-bit word
    ver_ttl = ((major_version & 0xFF) << 24) | (ttl & 0x00FFFFFF)

    entry = struct.pack(
        "!BBBBHHII",
        entry_type,
        opt_index,        # index 1st options
        idx2_numopt1,     # index 2nd (hi) | #opt1 (lo)
        numopt2,          # #opt2
        service_id,
        instance_id,
        ver_ttl,          # major_version(8) + TTL(24)
        minor_version,
    )
    return entry  # 16 bytes


def _pack_eventgroup_entry(
    entry_type: int,
    service_id: int,
    instance_id: int,
    major_version: int,
    ttl: int,
    eventgroup_id: int,
    opt_index: int = 0,
    num_opts: int = 0,
) -> bytes:
    """Pack a 16-byte Type-2 SD eventgroup entry."""
    idx2_numopt1 = (0 << 4) | (num_opts & 0x0F)
    numopt2 = 0

    # major_version(8b) + TTL(24b) = one 32-bit word
    ver_ttl = ((major_version & 0xFF) << 24) | (ttl & 0x00FFFFFF)

    # First 12 bytes match service entry layout
    # Last 4 bytes: reserved(12b) + counter(4b) + eventgroup_id(16b)
    entry = struct.pack(
        "!BBBBHHIHH",
        entry_type,
        opt_index,
        idx2_numopt1,
        numopt2,
        service_id,
        instance_id,
        ver_ttl,           # major_version(8) + TTL(24)
        0x0000,            # reserved + counter
        eventgroup_id,
    )
    return entry  # 16 bytes


def _pack_ipv4_option(opt: SdIpv4Option) -> bytes:
    """Pack a 12-byte IPv4 Endpoint option."""
    ip_bytes = socket.inet_aton(opt.ip)
    return struct.pack(
        "!HBB4sBH",
        0x0009,        # length (excl. length field itself = 9)
        0x04,          # type = IPv4 Endpoint
        0x00,          # reserved
        ip_bytes,
        opt.protocol,
        opt.port,
    )


def _build_sd_message(
    entries_data: bytes,
    options_data: bytes,
    reboot_flag: bool = True,
    session_id: int = 1,
) -> bytes:
    """Wrap entries + options in a full SOME/IP-SD frame."""
    # SD payload: flags(1) + reserved(3) + entries_len(4) + entries + options_len(4) + options
    flags = 0x80 if reboot_flag else 0x00
    sd_payload = struct.pack("!B3x", flags)
    sd_payload += struct.pack("!I", len(entries_data))
    sd_payload += entries_data
    sd_payload += struct.pack("!I", len(options_data))
    sd_payload += options_data

    header = SomeIpHeader(
        service_id=SD_SERVICE_ID,
        method_id=SD_METHOD_ID,
        client_id=0x0000,
        session_id=session_id,
        protocol_version=0x01,
        interface_version=0x01,
        message_type=MessageType.NOTIFICATION,
        return_code=ReturnCode.E_OK,
    )
    return pack_someip(SomeIpMessage(header=header, payload=sd_payload))


# Session counter (module-level, auto-incremented)
_sd_session_counter = 0


def _next_sd_session() -> int:
    global _sd_session_counter
    _sd_session_counter = (_sd_session_counter % 0xFFFF) + 1
    return _sd_session_counter


# ---------------------------------------------------------------------------
# Public API — builders
# ---------------------------------------------------------------------------

def build_offer_service(
    service_id: int,
    instance_id: int,
    ip: str,
    port: int,
    ttl: int = 10,
    major_version: int = 1,
    minor_version: int = 0,
) -> bytes:
    """Build a complete SOME/IP-SD OfferService message."""
    option = _pack_ipv4_option(SdIpv4Option(ip=ip, port=port))
    entry = _pack_service_entry(
        entry_type=SdEntryType.OFFER_SERVICE,
        service_id=service_id,
        instance_id=instance_id,
        major_version=major_version,
        ttl=ttl,
        minor_version=minor_version,
        opt_index=0,
        num_opts=1,
    )
    return _build_sd_message(entry, option, session_id=_next_sd_session())


def build_stop_offer(
    service_id: int,
    instance_id: int,
    ip: str,
    port: int,
) -> bytes:
    """Build an OfferService with TTL=0 (StopOffer)."""
    return build_offer_service(service_id, instance_id, ip, port, ttl=0)


def build_find_service(
    service_id: int,
    instance_id: int = 0xFFFF,
) -> bytes:
    """Build a FindService SD message (client looking for a service)."""
    entry = _pack_service_entry(
        entry_type=SdEntryType.FIND_SERVICE,
        service_id=service_id,
        instance_id=instance_id,
        major_version=0xFF,
        ttl=3,
        minor_version=0xFFFFFFFF,
        opt_index=0,
        num_opts=0,
    )
    return _build_sd_message(entry, b"", session_id=_next_sd_session())


def build_subscribe_eventgroup(
    service_id: int,
    instance_id: int,
    eventgroup_id: int,
    ttl: int = 10,
) -> bytes:
    """Build a SubscribeEventgroup SD message."""
    entry = _pack_eventgroup_entry(
        entry_type=SdEntryType.SUBSCRIBE_EVENTGROUP,
        service_id=service_id,
        instance_id=instance_id,
        major_version=1,
        ttl=ttl,
        eventgroup_id=eventgroup_id,
    )
    return _build_sd_message(entry, b"", session_id=_next_sd_session())


def build_subscribe_ack(
    service_id: int,
    instance_id: int,
    eventgroup_id: int,
    ttl: int = 10,
) -> bytes:
    """Build a SubscribeEventgroupAck SD message."""
    entry = _pack_eventgroup_entry(
        entry_type=SdEntryType.SUBSCRIBE_EVENTGROUP_ACK,
        service_id=service_id,
        instance_id=instance_id,
        major_version=1,
        ttl=ttl,
        eventgroup_id=eventgroup_id,
    )
    return _build_sd_message(entry, b"", session_id=_next_sd_session())


# ---------------------------------------------------------------------------
# Public API — parser
# ---------------------------------------------------------------------------

def parse_sd_message(data: bytes) -> List[SdEntry]:
    """Parse a raw SOME/IP-SD frame into a list of SdEntry objects.

    *data* should be the complete SOME/IP message (including the 16-byte
    SOME/IP header).  Returns an empty list if the message is not a valid
    SD frame.
    """
    try:
        msg = unpack_someip(data)
    except ValueError:
        return []

    h = msg.header
    if h.service_id != SD_SERVICE_ID or h.method_id != SD_METHOD_ID:
        return []

    payload = msg.payload
    if len(payload) < 12:
        return []

    # Parse SD header
    flags = payload[0]
    entries_len = struct.unpack("!I", payload[4:8])[0]
    entries_data = payload[8 : 8 + entries_len]
    options_offset = 8 + entries_len
    if options_offset + 4 > len(payload):
        return []
    options_len = struct.unpack("!I", payload[options_offset : options_offset + 4])[0]
    options_data = payload[options_offset + 4 : options_offset + 4 + options_len]

    # Parse options (we only handle IPv4 Endpoint for now)
    # Option layout: length(2) + type(1) + reserved(1) + option-specific data
    # The 'length' field value includes everything after the length field itself
    # (i.e., type + reserved + option data).  Total bytes = 2 + opt_len.
    options: list[Optional[SdIpv4Option]] = []
    pos = 0
    while pos + 4 <= len(options_data):  # minimum: length(2) + type(1) + reserved(1)
        opt_len = struct.unpack("!H", options_data[pos : pos + 2])[0]
        opt_type = options_data[pos + 2]
        total_opt_size = 2 + opt_len  # length field(2) + opt_len bytes
        if pos + total_opt_size > len(options_data):
            break  # truncated option
        if opt_type == 0x04 and opt_len >= 9:  # IPv4 Endpoint
            ip = socket.inet_ntoa(options_data[pos + 4 : pos + 8])
            proto = options_data[pos + 8]
            port = struct.unpack("!H", options_data[pos + 9 : pos + 11])[0]
            options.append(SdIpv4Option(ip=ip, port=port, protocol=proto))
        else:
            options.append(None)
        pos += total_opt_size

    # Parse entries (each is 16 bytes)
    results: list[SdEntry] = []
    pos = 0
    while pos + 16 <= len(entries_data):
        etype = entries_data[pos]
        opt_idx = entries_data[pos + 1]
        num_opts = entries_data[pos + 2] & 0x0F

        service_id = struct.unpack("!H", entries_data[pos + 4 : pos + 6])[0]
        instance_id = struct.unpack("!H", entries_data[pos + 6 : pos + 8])[0]
        major_ver = entries_data[pos + 8]
        ttl = struct.unpack("!I", b"\x00" + entries_data[pos + 9 : pos + 12])[0]

        # Determine if this is a service entry or eventgroup entry
        if etype in (SdEntryType.FIND_SERVICE, SdEntryType.OFFER_SERVICE):
            minor_ver = struct.unpack("!I", entries_data[pos + 12 : pos + 16])[0]
            entry = SdEntry(
                entry_type=etype,
                service_id=service_id,
                instance_id=instance_id,
                major_version=major_ver,
                ttl=ttl,
                minor_version=minor_ver,
            )
        else:
            eventgroup_id = struct.unpack("!H", entries_data[pos + 14 : pos + 16])[0]
            entry = SdEntry(
                entry_type=etype,
                service_id=service_id,
                instance_id=instance_id,
                major_version=major_ver,
                ttl=ttl,
                eventgroup_id=eventgroup_id,
            )

        # Attach option if referenced
        if num_opts > 0 and opt_idx < len(options):
            entry.option = options[opt_idx]

        results.append(entry)
        pos += 16

    return results


# ---------------------------------------------------------------------------
# HMAC Authentication for SD Offers (Spoofing Prevention)
# ---------------------------------------------------------------------------

HMAC_TAG_SIZE = 32  # SHA-256 HMAC = 32 bytes


def hmac_sign_offer(offer_msg: bytes, key: bytes) -> bytes:
    """Append an HMAC-SHA256 tag to an SD Offer message.

    The HMAC covers the entire SOME/IP frame (header + SD payload).
    The signed message is: original_frame || hmac_tag (32 bytes).

    This simulates what AUTOSAR SecOC does at the PDU level.
    """
    tag = hmac.new(key, offer_msg, hashlib.sha256).digest()
    return offer_msg + tag


def hmac_verify_offer(signed_msg: bytes, key: bytes) -> bool:
    """Verify the HMAC-SHA256 tag on a signed SD Offer message.

    Returns True if the tag is valid, False otherwise.
    Expects the format: original_frame || hmac_tag (32 bytes).
    """
    if len(signed_msg) < HEADER_SIZE + HMAC_TAG_SIZE:
        return False

    frame = signed_msg[:-HMAC_TAG_SIZE]
    received_tag = signed_msg[-HMAC_TAG_SIZE:]
    expected_tag = hmac.new(key, frame, hashlib.sha256).digest()
    return hmac.compare_digest(received_tag, expected_tag)


def extract_service_id_from_offer(data: bytes) -> Optional[int]:
    """Extract the service_id from an SD Offer's entry section.

    Used by the HMAC verifier to look up the correct key before
    parsing the full message.  Handles both signed and unsigned offers
    by trying the full data first, then stripped.
    """
    def _try_extract(frame: bytes) -> Optional[int]:
        try:
            msg = unpack_someip(frame)
        except ValueError:
            return None
        if msg.header.service_id != SD_SERVICE_ID:
            return None
        payload = msg.payload
        if len(payload) < 24:  # flags(4) + entries_len(4) + 16-byte entry minimum
            return None
        entries_len = struct.unpack("!I", payload[4:8])[0]
        if entries_len < 16:
            return None
        # Service ID is at offset 4 within the first entry (starts at payload[8])
        service_id = struct.unpack("!H", payload[12:14])[0]
        return service_id

    # Try the full data first (unsigned offer)
    result = _try_extract(data)
    if result is not None:
        return result

    # Try stripping HMAC tag (signed offer)
    if len(data) > HEADER_SIZE + HMAC_TAG_SIZE:
        return _try_extract(data[:-HMAC_TAG_SIZE])

    return None
