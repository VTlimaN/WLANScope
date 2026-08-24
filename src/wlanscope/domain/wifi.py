from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from wlanscope.domain.interfaces import NetworkInterface, normalize_stable_id


@dataclass(frozen=True, slots=True)
class NativeWifiValue:
    native_value: int
    labels: ClassVar[tuple[tuple[int, str], ...]] = ()

    @property
    def display_name(self) -> str:
        return next(
            (label for value, label in self.labels if value == self.native_value),
            f"Unknown ({self.native_value})",
        )


class WifiInterfaceState(NativeWifiValue):
    labels = (
        (0, "Not ready"),
        (1, "Connected"),
        (2, "Ad hoc network formed"),
        (3, "Disconnecting"),
        (4, "Disconnected"),
        (5, "Associating"),
        (6, "Discovering"),
        (7, "Authenticating"),
    )

    @property
    def is_connected(self) -> bool:
        return self.native_value in {1, 2}


class WifiConnectionMode(NativeWifiValue):
    labels = (
        (0, "Profile"),
        (1, "Temporary profile"),
        (2, "Secure discovery"),
        (3, "Unsecure discovery"),
        (4, "Automatic"),
        (5, "Invalid"),
    )


class WifiPhyType(NativeWifiValue):
    labels = (
        (0, "Unknown"),
        (1, "FHSS"),
        (2, "DSSS"),
        (3, "IR baseband"),
        (4, "OFDM"),
        (5, "HR-DSSS"),
        (6, "ERP"),
        (7, "HT"),
        (8, "VHT"),
        (9, "DMG"),
        (10, "HE"),
        (11, "EHT"),
    )


class WifiAuthentication(NativeWifiValue):
    labels = (
        (1, "Open"),
        (2, "Shared Key"),
        (3, "WPA"),
        (4, "WPA-PSK"),
        (5, "WPA-None"),
        (6, "RSNA"),
        (7, "RSNA-PSK"),
        (8, "WPA3-Enterprise-192"),
        (9, "WPA3-SAE"),
        (10, "OWE"),
        (11, "WPA3-Enterprise"),
    )


class WifiCipher(NativeWifiValue):
    labels = (
        (0, "None"),
        (1, "WEP-40"),
        (2, "TKIP"),
        (4, "CCMP"),
        (5, "WEP-104"),
        (6, "BIP"),
        (8, "GCMP"),
        (9, "GCMP-256"),
        (10, "CCMP-256"),
        (11, "BIP-GMAC-128"),
        (12, "BIP-GMAC-256"),
        (13, "BIP-CMAC-256"),
        (0x100, "Group"),
        (0x101, "WEP"),
    )


@dataclass(frozen=True, slots=True)
class WifiSsid:
    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) > 32:
            raise ValueError("An SSID cannot exceed 32 bytes")

    @property
    def is_empty(self) -> bool:
        return not self.raw

    @property
    def display_text(self) -> str:
        decoded = self.raw.decode("utf-8", errors="backslashreplace")
        return "".join(
            character if character.isprintable() else _escape(character) for character in decoded
        )


def _escape(character: str) -> str:
    code_point = ord(character)
    if code_point <= 0xFF:
        return f"\\x{code_point:02x}"
    return f"\\u{code_point:04x}"


@dataclass(frozen=True, slots=True)
class WifiBssid:
    octets: bytes

    def __post_init__(self) -> None:
        if len(self.octets) != 6:
            raise ValueError("A BSSID must contain exactly six octets")
        if not any(self.octets):
            raise ValueError("An all-zero BSSID does not identify an access point")

    def __str__(self) -> str:
        return ":".join(f"{octet:02X}" for octet in self.octets)


@dataclass(frozen=True, slots=True)
class WifiSecurity:
    enabled: bool
    authentication: WifiAuthentication
    cipher: WifiCipher


@dataclass(frozen=True, slots=True)
class WifiConnection:
    state: WifiInterfaceState
    mode: WifiConnectionMode
    profile_name: str | None
    ssid: WifiSsid
    bssid: WifiBssid
    phy_type: WifiPhyType
    signal_quality: int
    receive_rate_kbps: int | None
    transmit_rate_kbps: int | None
    security: WifiSecurity

    def __post_init__(self) -> None:
        if not self.state.is_connected:
            raise ValueError("Current connection attributes must report a connected state")
        if not 0 <= self.signal_quality <= 100:
            raise ValueError("Signal quality must be between 0 and 100")
        if self.receive_rate_kbps is not None and self.receive_rate_kbps <= 0:
            raise ValueError("Receive rate must be positive when available")
        if self.transmit_rate_kbps is not None and self.transmit_rate_kbps <= 0:
            raise ValueError("Transmit rate must be positive when available")


class WifiIssueCode(Enum):
    ACCESS_DENIED = "Access denied"
    CONNECTION_UNAVAILABLE = "Connection unavailable"
    INTERFACE_ASSOCIATION_FAILED = "Interface association failed"


@dataclass(frozen=True, slots=True)
class WifiIssue:
    code: WifiIssueCode
    message: str
    interface_id: str | None = None


@dataclass(frozen=True, slots=True)
class WifiInterfaceSnapshot:
    interface_id: str
    description: str
    state: WifiInterfaceState
    connection: WifiConnection | None = None
    network_interface: NetworkInterface | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "interface_id", normalize_stable_id(self.interface_id))
        if not self.description.strip():
            raise ValueError("Wi-Fi interface description cannot be empty")
        if self.connection is not None and not self.state.is_connected:
            raise ValueError("A disconnected Wi-Fi interface cannot contain a connection")


@dataclass(frozen=True, slots=True)
class CurrentWifiSnapshot:
    interfaces: tuple[WifiInterfaceSnapshot, ...]
    issues: tuple[WifiIssue, ...] = ()

    @property
    def is_partial(self) -> bool:
        return bool(self.issues)


class WifiCollectionError(RuntimeError):
    pass


class WifiAccessDeniedError(WifiCollectionError):
    pass


class WlanServiceUnavailableError(WifiCollectionError):
    pass


class WlanApiUnavailableError(WifiCollectionError):
    pass


class NativeWifiDataError(WifiCollectionError):
    pass


class WindowsWlanApiError(WifiCollectionError):
    def __init__(self, operation: str, error_code: int) -> None:
        self.operation = operation
        self.error_code = error_code
        super().__init__(f"{operation} failed with Windows error {error_code}")
