from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum

from wlanscope.domain.enrichment import EnrichmentSource, VendorResolutionState
from wlanscope.domain.interfaces import normalize_stable_id
from wlanscope.domain.wifi import (
    WifiAuthentication,
    WifiBssid,
    WifiCipher,
    WifiPhyType,
    WifiSsid,
)


class WifiBand(Enum):
    BAND_2_4_GHZ = "2.4 GHz"
    BAND_5_GHZ = "5 GHz"
    BAND_6_GHZ = "6 GHz"
    OTHER = "Other"


@dataclass(frozen=True, slots=True)
class WifiRsnDetails:
    version: int
    group_cipher: str | None
    pairwise_ciphers: tuple[str, ...]
    akm_suites: tuple[str, ...]
    mfp_capable: bool | None
    mfp_required: bool | None
    group_management_cipher: str | None = None


class WifiWpsPresence(Enum):
    UNAVAILABLE = "Unavailable"
    NOT_PRESENT = "No"
    PRESENT = "Yes"


class WifiWpsParseStatus(Enum):
    COMPLETE = "Complete"
    PARTIAL = "Partial"


@dataclass(frozen=True, slots=True)
class WifiProtectedSetupDetails:
    presence: WifiWpsPresence = WifiWpsPresence.UNAVAILABLE
    ie_count: int = 0
    parse_status: WifiWpsParseStatus | None = None
    version: int | None = None
    state: int | None = None
    ap_setup_locked: bool | None = None
    selected_registrar: bool | None = None
    device_password_id: int | None = None
    config_methods: tuple[str, ...] = ()
    config_methods_raw: int | None = None
    config_methods_unknown_bits: int = 0
    manufacturer: str | None = None
    model_name: str | None = None
    model_number: str | None = None
    device_name: str | None = None

    def __post_init__(self) -> None:
        if self.ie_count < 0:
            raise ValueError("WPS IE count cannot be negative")
        if self.presence is WifiWpsPresence.PRESENT:
            if self.ie_count == 0 or self.parse_status is None:
                raise ValueError("Present WPS data requires an IE count and parse status")
        elif self.ie_count or self.parse_status is not None:
            raise ValueError("Absent WPS data cannot contain parsed IE metadata")


@dataclass(frozen=True, slots=True)
class WifiAccessPointVendor:
    state: VendorResolutionState = VendorResolutionState.REGISTRY_UNAVAILABLE
    vendor: str | None = None
    source: EnrichmentSource | None = None

    def __post_init__(self) -> None:
        if self.state is VendorResolutionState.RESOLVED:
            if not self.vendor or self.source is not EnrichmentSource.LOCAL_OUI_REGISTRY:
                raise ValueError("A resolved AP vendor requires a name and registry source")
        elif self.vendor is not None or self.source is not None:
            raise ValueError("An unresolved AP vendor cannot contain a name or source")


@dataclass(frozen=True, slots=True)
class WifiInformationElementSummary:
    available: bool = False
    supported_rates_mbps: tuple[float, ...] = ()
    country_code: str | None = None
    rsn: WifiRsnDetails | None = None
    ht_capabilities_present: bool = False
    ht_operation_present: bool = False
    vht_capabilities_present: bool = False
    vht_operation_present: bool = False
    extended_capabilities_present: bool = False
    extension_element_ids: tuple[int, ...] = ()
    vendor_specific_ouis: tuple[str, ...] = ()
    unknown_element_ids: tuple[int, ...] = ()
    malformed: bool = False
    wps: WifiProtectedSetupDetails = WifiProtectedSetupDetails()


def wifi_band_from_frequency(center_frequency_khz: int) -> WifiBand:
    frequency_mhz = center_frequency_khz / 1_000
    if 2_400 <= frequency_mhz <= 2_500:
        return WifiBand.BAND_2_4_GHZ
    if 4_900 <= frequency_mhz <= 5_900:
        return WifiBand.BAND_5_GHZ
    if 5_925 <= frequency_mhz <= 7_125:
        return WifiBand.BAND_6_GHZ
    return WifiBand.OTHER


_FIVE_GHZ_CHANNELS = frozenset(
    {
        32,
        34,
        36,
        38,
        40,
        42,
        44,
        46,
        48,
        52,
        56,
        60,
        64,
        100,
        104,
        108,
        112,
        116,
        120,
        124,
        128,
        132,
        136,
        140,
        144,
        149,
        153,
        157,
        161,
        165,
        169,
        173,
        177,
    }
)


def wifi_channel_from_frequency(center_frequency_khz: int) -> int | None:
    if center_frequency_khz % 1_000:
        return None
    frequency_mhz = center_frequency_khz // 1_000
    if frequency_mhz == 2_484:
        return 14
    if 2_412 <= frequency_mhz <= 2_472 and (frequency_mhz - 2_407) % 5 == 0:
        return (frequency_mhz - 2_407) // 5
    if (frequency_mhz - 5_000) % 5 == 0:
        channel = (frequency_mhz - 5_000) // 5
        if channel in _FIVE_GHZ_CHANNELS:
            return channel
    if frequency_mhz == 5_935:
        return 2
    if 5_955 <= frequency_mhz <= 7_115 and (frequency_mhz - 5_955) % 20 == 0:
        return 1 + (frequency_mhz - 5_955) // 5
    return None


@dataclass(frozen=True, slots=True)
class WifiAccessPoint:
    interface_id: str
    ssid: WifiSsid
    bssid: WifiBssid
    phy_type: WifiPhyType
    signal_quality: int
    rssi_dbm: int
    center_frequency_khz: int
    beacon_period_tu: int | None = None
    capability_information: int | None = None
    timestamp_us: int | None = None
    host_timestamp: int | None = None
    phy_id: int | None = None
    bss_type: int | None = None
    in_reg_domain: bool | None = None
    supported_rates_mbps: tuple[float, ...] = ()
    basic_rates_mbps: tuple[float, ...] = ()
    capability_flags: tuple[str, ...] = ()
    information_elements: WifiInformationElementSummary = WifiInformationElementSummary()
    vendor: WifiAccessPointVendor = WifiAccessPointVendor()

    def __post_init__(self) -> None:
        object.__setattr__(self, "interface_id", normalize_stable_id(self.interface_id))
        if not 0 <= self.signal_quality <= 100:
            raise ValueError("Signal quality must be between 0 and 100")
        if self.center_frequency_khz <= 0:
            raise ValueError("Center frequency must be positive")
        for value, name in (
            (self.beacon_period_tu, "Beacon period"),
            (self.capability_information, "Capability information"),
            (self.timestamp_us, "Timestamp"),
            (self.host_timestamp, "Host timestamp"),
        ):
            if value is not None and value < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.phy_id is not None and self.phy_id < 0:
            raise ValueError("PHY identifier cannot be negative")
        if any(rate <= 0 for rate in (*self.supported_rates_mbps, *self.basic_rates_mbps)):
            raise ValueError("Supported rates must be positive")

    @property
    def band(self) -> WifiBand:
        return wifi_band_from_frequency(self.center_frequency_khz)

    @property
    def beacon_interval_microseconds(self) -> int | None:
        return self.beacon_period_tu * 1_024 if self.beacon_period_tu is not None else None

    @property
    def host_observed_at(self) -> datetime | None:
        if self.host_timestamp is None:
            return None
        try:
            return datetime(1601, 1, 1, tzinfo=UTC) + timedelta(
                microseconds=self.host_timestamp // 10
            )
        except OverflowError:
            return None

    @property
    def provenance(self) -> str:
        return "802.11 Beacon / Probe Response via Native WLAN API"

    @property
    def channel(self) -> int | None:
        return wifi_channel_from_frequency(self.center_frequency_khz)


@dataclass(frozen=True, slots=True)
class AvailableWifiNetwork:
    interface_id: str
    ssid: WifiSsid
    connectable: bool
    profile_name: str | None
    signal_quality: int
    security_enabled: bool
    authentication: WifiAuthentication
    cipher: WifiCipher
    reported_bss_count: int
    bss_type: int | None = None
    not_connectable_reason: int | None = None
    supported_phy_types: tuple[WifiPhyType, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "interface_id", normalize_stable_id(self.interface_id))
        if not 0 <= self.signal_quality <= 100:
            raise ValueError("Signal quality must be between 0 and 100")
        if self.reported_bss_count < 0:
            raise ValueError("Reported BSS count cannot be negative")


@dataclass(frozen=True, slots=True)
class WifiNetwork:
    interface_id: str
    interface_description: str
    ssid: WifiSsid
    connectable: bool
    profile_name: str | None
    signal_quality: int
    security_enabled: bool | None
    authentication: WifiAuthentication
    cipher: WifiCipher
    reported_bss_count: int
    access_points: tuple[WifiAccessPoint, ...]
    bss_type: int | None = None
    not_connectable_reason: int | None = None
    supported_phy_types: tuple[WifiPhyType, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "interface_id", normalize_stable_id(self.interface_id))
        if not self.interface_description.strip():
            raise ValueError("Wi-Fi interface description cannot be empty")
        if not 0 <= self.signal_quality <= 100:
            raise ValueError("Signal quality must be between 0 and 100")
        if self.reported_bss_count < 0:
            raise ValueError("Reported BSS count cannot be negative")
        if any(
            access_point.interface_id != self.interface_id for access_point in self.access_points
        ):
            raise ValueError("Access points must originate from the same Wi-Fi interface")
        if any(access_point.ssid != self.ssid for access_point in self.access_points):
            raise ValueError("Access points must belong to the same SSID")

    @property
    def best_signal_quality(self) -> int:
        return max(
            (access_point.signal_quality for access_point in self.access_points),
            default=self.signal_quality,
        )

    @property
    def bands(self) -> tuple[WifiBand, ...]:
        observed = {access_point.band for access_point in self.access_points}
        return tuple(sorted(observed, key=lambda band: band.value))


class WifiScanIssueCode(Enum):
    ACCESS_DENIED = "Access denied"
    TIMEOUT = "Scan timeout"
    SCAN_FAILED = "Scan failed"
    AVAILABLE_NETWORKS_FAILED = "Available networks unavailable"
    BSS_LIST_FAILED = "BSS list unavailable"


@dataclass(frozen=True, slots=True)
class WifiScanIssue:
    code: WifiScanIssueCode
    message: str
    interface_id: str | None = None


@dataclass(frozen=True, slots=True)
class NearbyWifiInterface:
    interface_id: str
    description: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "interface_id", normalize_stable_id(self.interface_id))
        if not self.description.strip():
            raise ValueError("Wi-Fi interface description cannot be empty")


@dataclass(frozen=True, slots=True)
class NativeNearbyWifiData:
    interfaces: tuple[NearbyWifiInterface, ...]
    available_networks: tuple[AvailableWifiNetwork, ...]
    access_points: tuple[WifiAccessPoint, ...]
    issues: tuple[WifiScanIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class NearbyWifiSnapshot:
    interfaces: tuple[NearbyWifiInterface, ...]
    networks: tuple[WifiNetwork, ...]
    issues: tuple[WifiScanIssue, ...] = ()

    @property
    def is_partial(self) -> bool:
        return bool(self.issues) and bool(self.networks)

    @property
    def failed(self) -> bool:
        return bool(self.issues) and not self.networks


class WifiScanTimeoutError(RuntimeError):
    pass
