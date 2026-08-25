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
    WifiNetwork,
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
    PrefixOrigin,
    Route,
    RouteOrigin,
    RouteProtocol,
)
from wlanscope.domain.wifi import (
    CurrentWifiSnapshot,
    WifiAuthentication,
    WifiBssid,
    WifiCipher,
    WifiConnection,
    WifiConnectionMode,
    WifiInterfaceSnapshot,
    WifiInterfaceState,
    WifiPhyType,
    WifiSecurity,
    WifiSsid,
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
    )
    return WifiInterfaceSnapshot(INTERFACE_ID, external_text, state, connection, interface)


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
