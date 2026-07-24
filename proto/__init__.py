"""
SOME/IP Protocol Library — pure Python implementation.

Provides SOME/IP message header packing/unpacking and
Service Discovery (SD) message construction/parsing,
all built on struct + raw UDP sockets.
"""

from .someip import (
    SomeIpHeader,
    SomeIpMessage,
    MessageType,
    ReturnCode,
    pack_someip,
    unpack_someip,
)
from .sd import (
    SdEntry,
    SdEntryType,
    SdIpv4Option,
    build_offer_service,
    build_stop_offer,
    build_find_service,
    build_subscribe_eventgroup,
    build_subscribe_ack,
    parse_sd_message,
)
from .constants import (
    HVAC_SERVICE_ID,
    MEDIA_SERVICE_ID,
    NAV_SERVICE_ID,
    SD_SERVICE_ID,
    SD_METHOD_ID,
    SD_MULTICAST_GROUP,
    SD_PORT,
    SERVICES,
)

__all__ = [
    # someip
    "SomeIpHeader", "SomeIpMessage", "MessageType", "ReturnCode",
    "pack_someip", "unpack_someip",
    # sd
    "SdEntry", "SdEntryType", "SdIpv4Option",
    "build_offer_service", "build_stop_offer", "build_find_service",
    "build_subscribe_eventgroup", "build_subscribe_ack", "parse_sd_message",
    # constants
    "HVAC_SERVICE_ID", "MEDIA_SERVICE_ID", "NAV_SERVICE_ID",
    "SD_SERVICE_ID", "SD_METHOD_ID", "SD_MULTICAST_GROUP", "SD_PORT",
    "SERVICES",
]
