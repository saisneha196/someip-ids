"""
Central registry of SOME/IP service, method, and event-group identifiers.

These IDs follow the AUTOSAR SOME/IP naming conventions but are
chosen arbitrarily for this simulation.  In a real vehicle, these
would come from the ARXML service interface definitions.
"""

# ---------------------------------------------------------------------------
# Service Discovery well-known identifiers (AUTOSAR spec)
# ---------------------------------------------------------------------------
SD_SERVICE_ID = 0xFFFF
SD_METHOD_ID = 0x8100
SD_MULTICAST_GROUP = "224.224.224.245"
SD_PORT = 30490

# ---------------------------------------------------------------------------
# Simulated ECU services
# ---------------------------------------------------------------------------

# HVAC (Heating, Ventilation, Air Conditioning)
HVAC_SERVICE_ID = 0x1001
HVAC_INSTANCE_ID = 0x0001
HVAC_METHODS = {
    "SetTemperature": 0x0001,
    "GetTemperature": 0x0002,
}
HVAC_EVENTGROUPS = {
    "TemperatureChanged": 0x0001,
}
HVAC_PORT = 30501

# Media / Infotainment
MEDIA_SERVICE_ID = 0x2001
MEDIA_INSTANCE_ID = 0x0001
MEDIA_METHODS = {
    "Play": 0x0001,
    "Pause": 0x0002,
    "NextTrack": 0x0003,
}
MEDIA_EVENTGROUPS = {
    "TrackChanged": 0x0001,
}
MEDIA_PORT = 30502

# Navigation
NAV_SERVICE_ID = 0x3001
NAV_INSTANCE_ID = 0x0001
NAV_METHODS = {
    "SetDestination": 0x0001,
}
NAV_EVENTGROUPS = {
    "RouteUpdated": 0x0001,
}
NAV_PORT = 30503

# ---------------------------------------------------------------------------
# Convenience lookup table  service_id → metadata
# ---------------------------------------------------------------------------
SERVICES = {
    HVAC_SERVICE_ID: {
        "name": "HVAC",
        "instance_id": HVAC_INSTANCE_ID,
        "methods": HVAC_METHODS,
        "eventgroups": HVAC_EVENTGROUPS,
        "port": HVAC_PORT,
    },
    MEDIA_SERVICE_ID: {
        "name": "Media",
        "instance_id": MEDIA_INSTANCE_ID,
        "methods": MEDIA_METHODS,
        "eventgroups": MEDIA_EVENTGROUPS,
        "port": MEDIA_PORT,
    },
    NAV_SERVICE_ID: {
        "name": "Navigation",
        "instance_id": NAV_INSTANCE_ID,
        "methods": NAV_METHODS,
        "eventgroups": NAV_EVENTGROUPS,
        "port": NAV_PORT,
    },
}

# Reverse lookup:  method_id → human-readable name (across all services)
METHOD_NAMES: dict[int, str] = {}
for _svc in SERVICES.values():
    for _name, _mid in _svc["methods"].items():
        METHOD_NAMES[_mid] = f"{_svc['name']}.{_name}"

SERVICE_NAMES: dict[int, str] = {
    sid: meta["name"] for sid, meta in SERVICES.items()
}

# ---------------------------------------------------------------------------
# HMAC Pre-shared keys for SD Offer authentication
#
# In a real vehicle, these would be provisioned during manufacturing
# (e.g., stored in HSM / SecOC key slots).  Here they're simple
# constants simulating that trust anchor.
# ---------------------------------------------------------------------------
SERVICE_HMAC_KEYS: dict[int, bytes] = {
    HVAC_SERVICE_ID: b"hvac-secret-key-2026-autosar",
    MEDIA_SERVICE_ID: b"media-secret-key-2026-autosar",
    NAV_SERVICE_ID: b"navigation-secret-key-2026-autosar",
}
