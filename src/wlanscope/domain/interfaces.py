from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from uuid import UUID


class InterfaceKind(Enum):
    ETHERNET = "Ethernet"
    WIFI = "Wi-Fi"
    LOOPBACK = "Loopback"
    TUNNEL = "Tunnel"
    VIRTUAL = "Virtual"
    OTHER = "Other"


class OperationalState(Enum):
    UP = "Up"
    DOWN = "Down"
    DORMANT = "Dormant"
    TESTING = "Testing"
    NOT_PRESENT = "Not present"
    LOWER_LAYER_DOWN = "Lower layer down"
    UNKNOWN = "Unknown"


class AdministrativeState(Enum):
    UP = "Up"
    DOWN = "Down"
    TESTING = "Testing"
    UNKNOWN = "Unknown"


class MediaState(Enum):
    CONNECTED = "Connected"
    DISCONNECTED = "Disconnected"
    UNKNOWN = "Unknown"


@dataclass(frozen=True, slots=True)
class AdapterStatistics:
    received_bytes: int | None
    sent_bytes: int | None
    received_unicast_packets: int | None
    sent_unicast_packets: int | None
    received_multicast_packets: int | None
    sent_multicast_packets: int | None
    received_broadcast_packets: int | None
    sent_broadcast_packets: int | None
    received_discards: int | None
    outbound_discards: int | None
    received_errors: int | None
    outbound_errors: int | None

    def __post_init__(self) -> None:
        values = (
            self.received_bytes,
            self.sent_bytes,
            self.received_unicast_packets,
            self.sent_unicast_packets,
            self.received_multicast_packets,
            self.sent_multicast_packets,
            self.received_broadcast_packets,
            self.sent_broadcast_packets,
            self.received_discards,
            self.outbound_discards,
            self.received_errors,
            self.outbound_errors,
        )
        if any(value is not None and value < 0 for value in values):
            raise ValueError("Adapter statistics cannot be negative")

    @property
    def has_values(self) -> bool:
        return any(
            value is not None
            for value in (
                self.received_bytes,
                self.sent_bytes,
                self.received_unicast_packets,
                self.sent_unicast_packets,
                self.received_multicast_packets,
                self.sent_multicast_packets,
                self.received_broadcast_packets,
                self.sent_broadcast_packets,
                self.received_discards,
                self.outbound_discards,
                self.received_errors,
                self.outbound_errors,
            )
        )

    @property
    def provenance(self) -> str:
        return "Get-NetAdapterStatistics"


@dataclass(frozen=True, slots=True)
class AdapterHardwareDetails:
    connector_present: bool | None = None
    driver_date: str | None = None
    device_id: str | None = None


@dataclass(frozen=True, slots=True)
class MacAddress:
    octets: bytes

    def __post_init__(self) -> None:
        if len(self.octets) != 6:
            raise ValueError("A MAC address must contain exactly six octets")
        if not any(self.octets):
            raise ValueError("An all-zero MAC address does not identify an interface")

    @classmethod
    def from_text(cls, value: str) -> MacAddress:
        normalized = value.strip().replace("-", ":")
        parts = normalized.split(":")
        if len(parts) != 6 or any(len(part) != 2 for part in parts):
            raise ValueError("Invalid MAC address format")
        try:
            return cls(bytes(int(part, 16) for part in parts))
        except ValueError as error:
            raise ValueError("Invalid MAC address format") from error

    def __str__(self) -> str:
        return ":".join(f"{octet:02X}" for octet in self.octets)

    @property
    def is_locally_administered(self) -> bool:
        return bool(self.octets[0] & 0x02)

    @property
    def is_multicast(self) -> bool:
        return bool(self.octets[0] & 0x01)


@dataclass(frozen=True, slots=True)
class NetworkInterface:
    interface_index: int
    stable_id: str
    alias: str
    friendly_name: str
    description: str | None
    windows_interface_type: int
    kind: InterfaceKind
    operational_state: OperationalState
    administrative_state: AdministrativeState
    media_state: MediaState
    mac_address: MacAddress | None
    mtu: int | None
    receive_link_speed_bps: int | None
    transmit_link_speed_bps: int | None
    is_hardware: bool | None
    is_virtual: bool | None = None
    is_hidden: bool | None = None
    manufacturer: str | None = None
    driver_description: str | None = None
    driver_version: str | None = None
    statistics: AdapterStatistics | None = None
    hardware: AdapterHardwareDetails | None = None

    def __post_init__(self) -> None:
        if self.interface_index < 0:
            raise ValueError("Interface index cannot be negative")
        if not self.stable_id.strip():
            raise ValueError("Stable interface identifier cannot be empty")
        if not self.alias.strip():
            raise ValueError("Interface alias cannot be empty")
        if not self.friendly_name.strip():
            raise ValueError("Friendly interface name cannot be empty")
        if self.windows_interface_type < 0:
            raise ValueError("Windows interface type cannot be negative")
        for value in (
            self.mtu,
            self.receive_link_speed_bps,
            self.transmit_link_speed_bps,
        ):
            if value is not None and value <= 0:
                raise ValueError("Interface measurements must be positive when available")


@dataclass(frozen=True, slots=True)
class AdapterEnrichment:
    stable_id: str | None
    interface_index: int | None
    manufacturer: str | None = None
    driver_description: str | None = None
    driver_version: str | None = None
    is_virtual: bool | None = None
    is_hidden: bool | None = None
    administrative_state: AdministrativeState = AdministrativeState.UNKNOWN
    media_state: MediaState = MediaState.UNKNOWN
    receive_link_speed_bps: int | None = None
    transmit_link_speed_bps: int | None = None
    statistics: AdapterStatistics | None = None
    hardware: AdapterHardwareDetails | None = None

    def __post_init__(self) -> None:
        if self.stable_id is None and self.interface_index is None:
            raise ValueError("Adapter enrichment requires a stable identifier or interface index")
        if self.interface_index is not None and self.interface_index < 0:
            raise ValueError("Interface index cannot be negative")


@dataclass(frozen=True, slots=True)
class InterfaceInventory:
    interfaces: tuple[NetworkInterface, ...]
    warnings: tuple[str, ...] = ()

    @property
    def is_partial(self) -> bool:
        return bool(self.warnings)


class InterfaceCollectionError(RuntimeError):
    pass


class InterfaceEnrichmentError(RuntimeError):
    pass


def normalize_stable_id(value: str) -> str:
    normalized = value.strip().strip("{}")
    if not normalized:
        raise ValueError("Stable interface identifier cannot be empty")
    try:
        return str(UUID(normalized))
    except ValueError:
        return normalized.casefold()
