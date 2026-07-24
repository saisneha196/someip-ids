"""
Unit tests for the SOME/IP protocol library (proto/).

Tests:
  - SOME/IP header pack → unpack round-trip
  - Message type and return code enums
  - SD OfferService build → parse round-trip
  - SD FindService, SubscribeEventgroup
  - Edge cases: malformed data, short buffers
"""

import struct
import pytest
import sys
import os

# Add project root to path so proto/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

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
from proto.sd import (
    SdEntryType,
    build_offer_service,
    build_stop_offer,
    build_find_service,
    build_subscribe_eventgroup,
    build_subscribe_ack,
    parse_sd_message,
)
from proto.constants import (
    HVAC_SERVICE_ID,
    HVAC_INSTANCE_ID,
    SD_SERVICE_ID,
    SD_METHOD_ID,
)


# ======================================================================
# SOME/IP Header Tests
# ======================================================================

class TestSomeIpHeader:
    """Pack/unpack round-trip tests for the 16-byte SOME/IP header."""

    def test_header_size(self):
        """Header struct should be exactly 16 bytes."""
        assert HEADER_SIZE == 16

    def test_round_trip_no_payload(self):
        """Pack → unpack with empty payload preserves all fields."""
        header = SomeIpHeader(
            service_id=0x1001,
            method_id=0x0001,
            client_id=0x0010,
            session_id=0x0042,
            protocol_version=0x01,
            interface_version=0x02,
            message_type=MessageType.REQUEST,
            return_code=ReturnCode.E_OK,
        )
        msg = SomeIpMessage(header=header, payload=b"")
        raw = pack_someip(msg)

        assert len(raw) == 16  # header only, no payload

        unpacked = unpack_someip(raw)
        h = unpacked.header
        assert h.service_id == 0x1001
        assert h.method_id == 0x0001
        assert h.client_id == 0x0010
        assert h.session_id == 0x0042
        assert h.protocol_version == 0x01
        assert h.interface_version == 0x02
        assert h.message_type == MessageType.REQUEST
        assert h.return_code == ReturnCode.E_OK
        assert unpacked.payload == b""

    def test_round_trip_with_payload(self):
        """Pack → unpack with payload data."""
        payload = struct.pack("!Hf", 1, 22.5)  # zone=1, temp=22.5
        header = SomeIpHeader(
            service_id=0x1001,
            method_id=0x0001,
            client_id=0x0010,
            session_id=0x0001,
        )
        msg = SomeIpMessage(header=header, payload=payload)
        raw = pack_someip(msg)

        assert len(raw) == 16 + len(payload)

        unpacked = unpack_someip(raw)
        assert unpacked.header.service_id == 0x1001
        assert unpacked.payload == payload

        # Verify payload contents
        zone, temp = struct.unpack("!Hf", unpacked.payload)
        assert zone == 1
        assert abs(temp - 22.5) < 0.01

    def test_length_field_is_correct(self):
        """The Length field should equal 8 + payload size."""
        payload = b"\xDE\xAD\xBE\xEF"
        msg = SomeIpMessage(
            header=SomeIpHeader(service_id=0xAAAA, method_id=0xBBBB),
            payload=payload,
        )
        raw = pack_someip(msg)

        # Length is at bytes 4-7
        length = struct.unpack("!I", raw[4:8])[0]
        assert length == 8 + len(payload)

    def test_response_message_type(self):
        """Response message type round-trips correctly."""
        header = SomeIpHeader(
            service_id=0x1001,
            method_id=0x0001,
            message_type=MessageType.RESPONSE,
            return_code=ReturnCode.E_OK,
        )
        msg = SomeIpMessage(header=header)
        unpacked = unpack_someip(pack_someip(msg))
        assert unpacked.header.message_type == MessageType.RESPONSE

    def test_notification_message_type(self):
        """Notification (event) message type round-trips correctly."""
        header = SomeIpHeader(
            service_id=0x1001,
            method_id=0x8001,  # MSB=1 for events
            message_type=MessageType.NOTIFICATION,
        )
        msg = SomeIpMessage(header=header)
        unpacked = unpack_someip(pack_someip(msg))
        assert unpacked.header.message_type == MessageType.NOTIFICATION
        assert unpacked.header.method_id == 0x8001

    def test_error_on_short_buffer(self):
        """Unpacking fewer than 16 bytes should raise ValueError."""
        with pytest.raises(ValueError, match="too short"):
            unpack_someip(b"\x00" * 15)

    def test_error_on_invalid_length(self):
        """Length field < 8 should raise ValueError."""
        # Craft a header with length = 3 (invalid, must be >= 8)
        raw = struct.pack("!HHIHHBBBB", 0x1001, 0x0001, 3, 0, 1, 1, 1, 0, 0)
        with pytest.raises(ValueError, match="Invalid"):
            unpack_someip(raw)

    def test_message_type_name(self):
        assert message_type_name(0x00) == "REQUEST"
        assert message_type_name(0x80) == "RESPONSE"
        assert message_type_name(0x02) == "NOTIFICATION"
        assert "UNKNOWN" in message_type_name(0xFF)


# ======================================================================
# Service Discovery Tests
# ======================================================================

class TestServiceDiscovery:
    """Build → parse round-trip tests for SD messages."""

    def test_offer_service_round_trip(self):
        """Build OfferService → parse back the entry."""
        raw = build_offer_service(
            service_id=HVAC_SERVICE_ID,
            instance_id=HVAC_INSTANCE_ID,
            ip="172.20.0.10",
            port=30501,
            ttl=10,
        )
        # Should start with a valid SOME/IP header
        assert len(raw) >= HEADER_SIZE

        # Verify SD service/method IDs in the header
        unpacked = unpack_someip(raw)
        assert unpacked.header.service_id == SD_SERVICE_ID
        assert unpacked.header.method_id == SD_METHOD_ID
        assert unpacked.header.message_type == MessageType.NOTIFICATION

        # Parse the SD entries
        entries = parse_sd_message(raw)
        assert len(entries) == 1

        entry = entries[0]
        assert entry.entry_type == SdEntryType.OFFER_SERVICE
        assert entry.service_id == HVAC_SERVICE_ID
        assert entry.instance_id == HVAC_INSTANCE_ID
        assert entry.ttl == 10
        assert entry.option is not None
        assert entry.option.ip == "172.20.0.10"
        assert entry.option.port == 30501

    def test_stop_offer(self):
        """StopOffer is an OfferService with TTL=0."""
        raw = build_stop_offer(
            service_id=HVAC_SERVICE_ID,
            instance_id=HVAC_INSTANCE_ID,
            ip="172.20.0.10",
            port=30501,
        )
        entries = parse_sd_message(raw)
        assert len(entries) == 1
        assert entries[0].ttl == 0

    def test_find_service(self):
        """FindService message parses correctly."""
        raw = build_find_service(service_id=HVAC_SERVICE_ID)
        entries = parse_sd_message(raw)
        assert len(entries) == 1
        assert entries[0].entry_type == SdEntryType.FIND_SERVICE
        assert entries[0].service_id == HVAC_SERVICE_ID

    def test_subscribe_eventgroup(self):
        """SubscribeEventgroup message parses correctly."""
        raw = build_subscribe_eventgroup(
            service_id=HVAC_SERVICE_ID,
            instance_id=HVAC_INSTANCE_ID,
            eventgroup_id=0x0001,
        )
        entries = parse_sd_message(raw)
        assert len(entries) == 1
        assert entries[0].entry_type == SdEntryType.SUBSCRIBE_EVENTGROUP
        assert entries[0].eventgroup_id == 0x0001

    def test_subscribe_ack(self):
        """SubscribeEventgroupAck message parses correctly."""
        raw = build_subscribe_ack(
            service_id=HVAC_SERVICE_ID,
            instance_id=HVAC_INSTANCE_ID,
            eventgroup_id=0x0001,
        )
        entries = parse_sd_message(raw)
        assert len(entries) == 1
        assert entries[0].entry_type == SdEntryType.SUBSCRIBE_EVENTGROUP_ACK

    def test_parse_garbage_returns_empty(self):
        """Parsing random garbage should return an empty list, not crash."""
        assert parse_sd_message(b"\x00\x01\x02\x03") == []
        assert parse_sd_message(b"") == []
        assert parse_sd_message(b"\xFF" * 100) == []

    def test_session_id_increments(self):
        """Each SD message should have a different session ID."""
        raw1 = build_offer_service(HVAC_SERVICE_ID, HVAC_INSTANCE_ID, "1.2.3.4", 30501)
        raw2 = build_offer_service(HVAC_SERVICE_ID, HVAC_INSTANCE_ID, "1.2.3.4", 30501)
        msg1 = unpack_someip(raw1)
        msg2 = unpack_someip(raw2)
        assert msg1.header.session_id != msg2.header.session_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
