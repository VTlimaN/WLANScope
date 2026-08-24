from ipaddress import IPv4Address, ip_address, ip_network

import pytest

from wlanscope.application.inspect_current_network import InspectCurrentNetwork
from wlanscope.domain.interfaces import (
    AdministrativeState,
    InterfaceCollectionError,
    InterfaceKind,
    MediaState,
    NetworkInterface,
    OperationalState,
)
from wlanscope.domain.network import (
    AddressOrigin,
    DadState,
    DhcpEnrichment,
    DhcpState,
    InterfaceNetworkEnrichment,
    IpAddressAssignment,
    NativeNetworkData,
    NetworkCollectionError,
    NetworkEnrichmentError,
    NetworkIssueSource,
    PrefixOrigin,
    Route,
    RouteOrigin,
    RouteProtocol,
)
from wlanscope.domain.wifi import (
    CurrentWifiSnapshot,
    WifiCollectionError,
    WifiInterfaceSnapshot,
    WifiInterfaceState,
    WifiIssue,
    WifiIssueCode,
)

_INTERFACE_ID = "aaaaaaaa-0000-0000-0000-000000000001"


def test_all_sources_merge_into_current_context() -> None:
    result = _use_case().execute()
    context = result.interfaces[0]

    assert not result.is_partial
    assert context.network_interface is not None
    assert context.wifi_interface is not None
    assert context.dns is not None
    assert [str(server) for server in context.dns.servers] == ["192.0.2.53"]
    assert context.dhcp.ipv4_state is DhcpState.ENABLED
    assert str(context.dhcp.server) == "192.0.2.1"
    assert result.routes[0].interface_metric == 20
    assert result.routes[0].effective_metric == 30


@pytest.mark.parametrize(
    ("source", "issue_source"),
    [
        ("network", NetworkIssueSource.DNS_AND_METRICS),
        ("dhcp", NetworkIssueSource.DHCP),
        ("interfaces", NetworkIssueSource.INTERFACE_ASSOCIATION),
        ("wifi", NetworkIssueSource.WIFI_ASSOCIATION),
    ],
)
def test_optional_source_failure_preserves_native_results(
    source: str,
    issue_source: NetworkIssueSource,
) -> None:
    result = _use_case(failing_source=source).execute()

    assert result.is_partial
    assert len(result.interfaces[0].addresses) == 1
    assert len(result.routes) == 1
    assert issue_source in {issue.source for issue in result.issues}


def test_primary_failure_is_not_silenced() -> None:
    with pytest.raises(NetworkCollectionError, match="Routing unavailable"):
        InspectCurrentNetwork(FailingPrimaryCollector()).execute()


def test_no_network_returns_empty_snapshot() -> None:
    result = InspectCurrentNetwork(StaticPrimaryCollector(NativeNetworkData((), ()))).execute()

    assert result.interfaces == ()
    assert result.routes == ()


def test_ipv4_ipv6_and_multiple_interfaces_are_preserved() -> None:
    data = NativeNetworkData(
        (_assignment("192.0.2.24", 24, 7), _assignment("2001:db8::24", 64, 8)),
        (
            _route("0.0.0.0/0", "192.0.2.1", 7, 10),
            _route("::/0", "2001:db8::1", 8, 5),
        ),
    )

    result = InspectCurrentNetwork(StaticPrimaryCollector(data)).execute()

    assert len(result.interfaces) == 2
    assert {route.destination.version for route in result.default_routes} == {4, 6}


def test_vpn_default_route_wins_by_effective_metric_without_name_heuristic() -> None:
    data = NativeNetworkData(
        (_assignment("192.0.2.24", 24, 7), _assignment("198.51.100.24", 24, 42)),
        (
            _route("0.0.0.0/0", "192.0.2.1", 7, 10),
            _route("0.0.0.0/0", "198.51.100.1", 42, 1),
        ),
    )
    enrichments = (
        _enrichment(7, 4, 30),
        _enrichment(42, 4, 5),
    )

    result = InspectCurrentNetwork(
        StaticPrimaryCollector(data), StaticNetworkCollector(enrichments)
    ).execute()

    preferred = result.preferred_default_route(4)
    assert preferred is not None
    assert preferred.interface_index == 42


def test_wifi_privacy_issue_is_preserved_as_partial() -> None:
    wifi = CurrentWifiSnapshot(
        (_wifi_interface(),),
        (WifiIssue(WifiIssueCode.ACCESS_DENIED, "Location access may be required"),),
    )

    result = InspectCurrentNetwork(
        StaticPrimaryCollector(_native_data()), wifi_collector=StaticWifiCollector(wifi)
    ).execute()

    assert result.is_partial
    assert result.issues[0].source is NetworkIssueSource.WIFI_ASSOCIATION


class StaticPrimaryCollector:
    def __init__(self, data: NativeNetworkData) -> None:
        self._data = data

    def collect(self) -> NativeNetworkData:
        return self._data


class FailingPrimaryCollector:
    def collect(self) -> NativeNetworkData:
        raise NetworkCollectionError("Routing unavailable")


class StaticNetworkCollector:
    def __init__(self, records: tuple[InterfaceNetworkEnrichment, ...]) -> None:
        self._records = records

    def collect(self) -> tuple[InterfaceNetworkEnrichment, ...]:
        return self._records


class FailingNetworkCollector:
    def collect(self) -> tuple[InterfaceNetworkEnrichment, ...]:
        raise NetworkEnrichmentError("DNS unavailable")


class StaticDhcpCollector:
    def collect(self) -> tuple[DhcpEnrichment, ...]:
        server = ip_address("192.0.2.1")
        assert isinstance(server, IPv4Address)
        return (DhcpEnrichment(7, True, server),)


class FailingDhcpCollector:
    def collect(self) -> tuple[DhcpEnrichment, ...]:
        raise NetworkEnrichmentError("DHCP unavailable")


class StaticInterfaceCollector:
    def collect(self) -> tuple[NetworkInterface, ...]:
        return (_network_interface(),)


class FailingInterfaceCollector:
    def collect(self) -> tuple[NetworkInterface, ...]:
        raise InterfaceCollectionError("Interface unavailable")


class StaticWifiCollector:
    def __init__(self, snapshot: CurrentWifiSnapshot | None = None) -> None:
        self._snapshot = snapshot or CurrentWifiSnapshot((_wifi_interface(),))

    def collect(self) -> CurrentWifiSnapshot:
        return self._snapshot


class FailingWifiCollector:
    def collect(self) -> CurrentWifiSnapshot:
        raise WifiCollectionError("Wi-Fi unavailable")


def _use_case(failing_source: str | None = None) -> InspectCurrentNetwork:
    network_collector = (
        FailingNetworkCollector()
        if failing_source == "network"
        else StaticNetworkCollector((_enrichment(7, 4, 20),))
    )
    dhcp_collector = FailingDhcpCollector() if failing_source == "dhcp" else StaticDhcpCollector()
    interface_collector = (
        FailingInterfaceCollector()
        if failing_source == "interfaces"
        else StaticInterfaceCollector()
    )
    wifi_collector = FailingWifiCollector() if failing_source == "wifi" else StaticWifiCollector()
    return InspectCurrentNetwork(
        StaticPrimaryCollector(_native_data()),
        network_collector,
        dhcp_collector,
        interface_collector,
        wifi_collector,
    )


def _native_data() -> NativeNetworkData:
    return NativeNetworkData(
        (_assignment("192.0.2.24", 24, 7),),
        (_route("0.0.0.0/0", "192.0.2.1", 7, 10),),
    )


def _assignment(address: str, prefix: int, index: int) -> IpAddressAssignment:
    return IpAddressAssignment(
        ip_address(address),
        prefix,
        index,
        PrefixOrigin(3),
        AddressOrigin(3),
        DadState(4),
        3600,
        7200,
        False,
    )


def _route(destination: str, next_hop: str, index: int, metric: int) -> Route:
    return Route(
        ip_network(destination),
        ip_address(next_hop),
        index,
        metric,
        None,
        RouteProtocol(3),
        RouteOrigin(2),
    )


def _enrichment(index: int, family: int, metric: int) -> InterfaceNetworkEnrichment:
    return InterfaceNetworkEnrichment(
        index,
        family,
        metric,
        DhcpState.ENABLED,
        (ip_address("192.0.2.53"),) if family == 4 else (ip_address("2001:db8::53"),),
        "example.invalid",
    )


def _network_interface() -> NetworkInterface:
    return NetworkInterface(
        7,
        _INTERFACE_ID,
        "Sanitized adapter",
        "Sanitized adapter",
        "Sanitized adapter",
        71,
        InterfaceKind.WIFI,
        OperationalState.UP,
        AdministrativeState.UP,
        MediaState.CONNECTED,
        None,
        1500,
        None,
        None,
        True,
    )


def _wifi_interface() -> WifiInterfaceSnapshot:
    return WifiInterfaceSnapshot(
        _INTERFACE_ID,
        "Sanitized wireless adapter",
        WifiInterfaceState(4),
    )
