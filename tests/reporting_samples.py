from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from wlanscope.domain.discovery import (
    DeviceInventory,
    DiscoveredHost,
    DiscoveryPlan,
    DiscoverySource,
    NeighborState,
    ReachabilityState,
)
from wlanscope.domain.enrichment import (
    EnrichedDeviceInventory,
    EnrichedHost,
    EnrichmentSource,
    HostnameResolution,
    HostnameResolutionState,
    VendorResolution,
    VendorResolutionState,
)
from wlanscope.domain.full_scan import (
    FullNetworkSnapshot,
    FullScanIssue,
    ScanSection,
    ScanSectionResult,
    ScanSectionStatus,
)
from wlanscope.domain.interfaces import (
    AdapterHardwareDetails,
    AdapterStatistics,
    AdministrativeState,
    InterfaceInventory,
    InterfaceKind,
    MacAddress,
    MediaState,
    NetworkInterface,
    OperationalState,
)
from wlanscope.domain.nearby_wifi import (
    NearbyWifiInterface,
    NearbyWifiSnapshot,
    WifiAccessPoint,
    WifiAccessPointVendor,
    WifiInformationElementSummary,
    WifiNetwork,
    WifiProtectedSetupDetails,
    WifiRsnDetails,
    WifiWpsParseStatus,
    WifiWpsPresence,
)
from wlanscope.domain.network import (
    AddressOrigin,
    CurrentNetworkSnapshot,
    DadState,
    DhcpConfiguration,
    DhcpState,
    DnsConfiguration,
    InterfaceNetworkContext,
    IpAddressAssignment,
    NetworkConnectivity,
    NetworkProfile,
    PrefixOrigin,
    Route,
    RouteOrigin,
    RouteProtocol,
)
from wlanscope.domain.wifi import (
    CurrentWifiSnapshot,
    WifiAuthCipherCapabilities,
    WifiAuthCipherPair,
    WifiAuthentication,
    WifiBssid,
    WifiBssType,
    WifiCapabilityState,
    WifiCipher,
    WifiConnection,
    WifiConnectionMode,
    WifiInterfaceCapabilities,
    WifiInterfaceSnapshot,
    WifiInterfaceState,
    WifiPhyRadioState,
    WifiPhyStatistics,
    WifiPhyType,
    WifiRadioState,
    WifiSecurity,
    WifiSsid,
    WifiStatistics,
)

INTERFACE_ID = "11111111-1111-1111-1111-111111111111"


def sample_snapshot(
    section_status: ScanSectionStatus = ScanSectionStatus.SUCCESS,
    external_text: str = "Example Network",
    ssid: WifiSsid | None = None,
) -> FullNetworkSnapshot:
    selected_ssid = ssid or WifiSsid(b"Example Wi-Fi")
    interface = _interface(external_text)
    wifi_interface = _wifi_interface(selected_ssid, interface, external_text)
    current_wifi = CurrentWifiSnapshot((wifi_interface,))
    current_network = _current_network(interface, wifi_interface, external_text)
    nearby = _nearby(selected_ssid, external_text)
    devices = _devices(external_text)
    sections = tuple(
        ScanSectionResult(
            section,
            section_status,
            (FullScanIssue(section, f"{external_text} issue"),)
            if section_status is not ScanSectionStatus.SUCCESS
            else (),
        )
        for section in ScanSection
    )
    started = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    return FullNetworkSnapshot(
        started,
        started + timedelta(seconds=2),
        sections,
        InterfaceInventory((interface,)),
        current_wifi,
        current_network,
        nearby,
        devices,
    )


def _interface(external_text: str) -> NetworkInterface:
    return NetworkInterface(
        7,
        INTERFACE_ID,
        external_text,
        external_text,
        external_text,
        71,
        InterfaceKind.WIFI,
        OperationalState.UP,
        AdministrativeState.UP,
        MediaState.CONNECTED,
        MacAddress.from_text("00:11:22:33:44:55"),
        1500,
        1_000_000_000,
        1_000_000_000,
        True,
        False,
        False,
        external_text,
        external_text,
        "1.0",
        AdapterStatistics(1000, 2000, 10, 20, 3, 4, 5, 6, 1, 2, 0, 1),
        AdapterHardwareDetails(True, "2026-01-02", "SANITIZED\\DEVICE"),
    )


def _wifi_interface(
    ssid: WifiSsid,
    interface: NetworkInterface,
    external_text: str,
) -> WifiInterfaceSnapshot:
    state = WifiInterfaceState(1)
    connection = WifiConnection(
        state,
        WifiConnectionMode(0),
        external_text,
        ssid,
        WifiBssid(bytes.fromhex("001122334466")),
        WifiPhyType(10),
        88,
        866_000,
        780_000,
        WifiSecurity(True, WifiAuthentication(7), WifiCipher(4)),
        WifiBssType(1),
    )
    return WifiInterfaceSnapshot(
        INTERFACE_ID,
        external_text,
        state,
        connection,
        interface,
        WifiInterfaceCapabilities(
            0,
            True,
            16,
            16,
            (WifiPhyType(8), WifiPhyType(10)),
            WifiAuthCipherCapabilities(
                WifiCapabilityState.AVAILABLE,
                (WifiAuthCipherPair(WifiAuthentication(7), WifiCipher(4)),),
            ),
            WifiAuthCipherCapabilities(WifiCapabilityState.UNSUPPORTED),
        ),
        36,
        -51,
        1,
        True,
        (WifiPhyRadioState(0, WifiRadioState(1), WifiRadioState(1)),),
        WifiStatistics(1, 2, 10, 20, 3, 4, 100, 1, (WifiPhyStatistics(0, 9, 8, 1, 2, 1, 3),)),
    )


def _current_network(
    interface: NetworkInterface,
    wifi: WifiInterfaceSnapshot,
    external_text: str,
) -> CurrentNetworkSnapshot:
    ipv4 = IpAddressAssignment(
        IPv4Address("192.0.2.10"),
        24,
        7,
        PrefixOrigin(3),
        AddressOrigin(3),
        DadState(4),
        3600,
        7200,
        False,
    )
    ipv6 = IpAddressAssignment(
        IPv6Address("2001:db8::10"),
        64,
        7,
        PrefixOrigin(4),
        AddressOrigin(4),
        DadState(4),
        None,
        None,
        False,
        7,
    )
    context = InterfaceNetworkContext(
        7,
        (ipv4, ipv6),
        DnsConfiguration(
            7, (IPv4Address("192.0.2.53"), IPv6Address("2001:db8::53")), external_text
        ),
        DhcpConfiguration(7, DhcpState.ENABLED, DhcpState.UNKNOWN, IPv4Address("192.0.2.1")),
        interface,
        wifi,
        NetworkProfile(
            7,
            external_text,
            "Private",
            NetworkConnectivity.INTERNET,
            NetworkConnectivity.NO_TRAFFIC,
        ),
    )
    routes = (
        Route(
            IPv4Network("0.0.0.0/0"),
            IPv4Address("192.0.2.1"),
            7,
            10,
            25,
            RouteProtocol(3),
            RouteOrigin(2),
        ),
        Route(
            IPv6Network("::/0"),
            IPv6Address("2001:db8::1"),
            7,
            20,
            25,
            RouteProtocol(3),
            RouteOrigin(3),
            7,
        ),
    )
    return CurrentNetworkSnapshot((context,), routes)


def _nearby(ssid: WifiSsid, external_text: str) -> NearbyWifiSnapshot:
    access_point = WifiAccessPoint(
        INTERFACE_ID,
        ssid,
        WifiBssid(bytes.fromhex("001122334477")),
        WifiPhyType(8),
        80,
        -48,
        5_180_000,
        100,
        1,
        10,
        20,
        3,
        1,
        True,
        (1.0, 2.0, 5.5),
        (1.0,),
        ("ESS", "Privacy"),
        WifiInformationElementSummary(
            available=True,
            supported_rates_mbps=(1.0, 2.0, 5.5),
            country_code="US",
            rsn=WifiRsnDetails(1, "CCMP-128", ("CCMP-128",), ("PSK",), True, False),
            ht_capabilities_present=True,
            wps=WifiProtectedSetupDetails(
                WifiWpsPresence.PRESENT,
                1,
                WifiWpsParseStatus.COMPLETE,
                0x20,
                2,
                True,
                False,
                4,
                ("Push Button",),
                0x0080,
                0,
                external_text,
                "Model X",
                "1",
                external_text,
            ),
        ),
        WifiAccessPointVendor(
            VendorResolutionState.RESOLVED,
            external_text,
            EnrichmentSource.LOCAL_OUI_REGISTRY,
        ),
    )
    network = WifiNetwork(
        INTERFACE_ID,
        external_text,
        ssid,
        True,
        external_text,
        79,
        True,
        WifiAuthentication(7),
        WifiCipher(4),
        1,
        (access_point,),
    )
    return NearbyWifiSnapshot((NearbyWifiInterface(INTERFACE_ID, external_text),), (network,))


def _devices(external_text: str) -> EnrichedDeviceInventory:
    address = IPv4Address("192.0.2.20")
    plan = DiscoveryPlan(
        7,
        IPv4Network("192.0.2.0/24"),
        (IPv4Address("192.0.2.10"),),
        (IPv4Address("192.0.2.1"),),
        254,
        (address,),
        750,
        32,
    )
    host = DiscoveredHost(
        7,
        address,
        MacAddress.from_text("00:11:22:33:44:66"),
        ReachabilityState.RESPONDED,
        frozenset({DiscoverySource.NEIGHBOR_CACHE, DiscoverySource.ICMP_RESPONSE}),
        NeighborState(5),
        True,
    )
    discovered = DeviceInventory(plan, (host,), 1)
    enriched = EnrichedHost(
        host,
        HostnameResolution(
            address,
            HostnameResolutionState.RESOLVED,
            external_text,
            EnrichmentSource.PTR,
        ),
        VendorResolution(
            7,
            address,
            VendorResolutionState.RESOLVED,
            external_text,
            EnrichmentSource.LOCAL_OUI_REGISTRY,
        ),
    )
    return EnrichedDeviceInventory(discovered, (enriched,))
