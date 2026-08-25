from wlanscope.application.inspect_current_wifi import InspectCurrentWifi
from wlanscope.domain.interfaces import (
    AdministrativeState,
    InterfaceCollectionError,
    InterfaceKind,
    MediaState,
    NetworkInterface,
    OperationalState,
)
from wlanscope.domain.wifi import (
    CurrentWifiSnapshot,
    WifiInterfaceSnapshot,
    WifiInterfaceState,
    WifiIssue,
    WifiIssueCode,
)


def test_use_case_returns_zero_interfaces() -> None:
    result = InspectCurrentWifi(StaticWifiCollector(CurrentWifiSnapshot(()))).execute()

    assert result.interfaces == ()


def test_use_case_orders_connected_interface_first() -> None:
    disconnected = _wifi_interface("bbbbbbbb-0000-0000-0000-000000000002", 4, "Adapter B")
    connected = _wifi_interface("aaaaaaaa-0000-0000-0000-000000000001", 1, "Adapter A")

    result = InspectCurrentWifi(
        StaticWifiCollector(CurrentWifiSnapshot((disconnected, connected)))
    ).execute()

    assert result.interfaces == (connected, disconnected)


def test_use_case_preserves_multiple_connected_interfaces() -> None:
    second = _wifi_interface("bbbbbbbb-0000-0000-0000-000000000002", 1, "Adapter B")
    first = _wifi_interface("aaaaaaaa-0000-0000-0000-000000000001", 1, "Adapter A")

    result = InspectCurrentWifi(StaticWifiCollector(CurrentWifiSnapshot((second, first)))).execute()

    assert result.interfaces == (first, second)


def test_use_case_associates_m1_interface_by_guid() -> None:
    wifi_interface = _wifi_interface("aaaaaaaa-0000-0000-0000-000000000001", 4, "Wireless")
    network_interface = _network_interface(wifi_interface.interface_id)

    result = InspectCurrentWifi(
        StaticWifiCollector(CurrentWifiSnapshot((wifi_interface,))),
        StaticInterfaceCollector((network_interface,)),
    ).execute()

    assert result.interfaces[0].network_interface == network_interface


def test_supplied_m1_interfaces_avoid_duplicate_collection() -> None:
    wifi_interface = _wifi_interface("aaaaaaaa-0000-0000-0000-000000000001", 4)
    network_interface = _network_interface(wifi_interface.interface_id)

    result = InspectCurrentWifi(
        StaticWifiCollector(CurrentWifiSnapshot((wifi_interface,))),
        FailingInterfaceCollector(),
    ).execute((network_interface,))

    assert result.interfaces[0].network_interface is network_interface
    assert not result.is_partial


def test_use_case_does_not_associate_by_description() -> None:
    wifi_interface = _wifi_interface("aaaaaaaa-0000-0000-0000-000000000001", 4, "Same")
    network_interface = _network_interface("bbbbbbbb-0000-0000-0000-000000000002", "Same")

    result = InspectCurrentWifi(
        StaticWifiCollector(CurrentWifiSnapshot((wifi_interface,))),
        StaticInterfaceCollector((network_interface,)),
    ).execute()

    assert result.interfaces[0].network_interface is None


def test_interface_association_failure_is_partial() -> None:
    snapshot = CurrentWifiSnapshot((_wifi_interface("aaaaaaaa-0000-0000-0000-000000000001", 4),))

    result = InspectCurrentWifi(
        StaticWifiCollector(snapshot), FailingInterfaceCollector()
    ).execute()

    assert result.is_partial
    assert result.issues[0].code is WifiIssueCode.INTERFACE_ASSOCIATION_FAILED


def test_collector_issues_are_preserved() -> None:
    issue = WifiIssue(WifiIssueCode.ACCESS_DENIED, "Access denied")
    snapshot = CurrentWifiSnapshot((), (issue,))

    assert InspectCurrentWifi(StaticWifiCollector(snapshot)).execute().issues == (issue,)


class StaticWifiCollector:
    def __init__(self, snapshot: CurrentWifiSnapshot) -> None:
        self._snapshot = snapshot

    def collect(self) -> CurrentWifiSnapshot:
        return self._snapshot


class StaticInterfaceCollector:
    def __init__(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        self._interfaces = interfaces

    def collect(self) -> tuple[NetworkInterface, ...]:
        return self._interfaces


class FailingInterfaceCollector:
    def collect(self) -> tuple[NetworkInterface, ...]:
        raise InterfaceCollectionError("Interface data unavailable")


def _wifi_interface(
    interface_id: str,
    state: int,
    description: str = "Sanitized adapter",
) -> WifiInterfaceSnapshot:
    return WifiInterfaceSnapshot(interface_id, description, WifiInterfaceState(state))


def _network_interface(stable_id: str, name: str = "Sanitized adapter") -> NetworkInterface:
    return NetworkInterface(
        interface_index=7,
        stable_id=stable_id,
        alias=name,
        friendly_name=name,
        description=name,
        windows_interface_type=71,
        kind=InterfaceKind.WIFI,
        operational_state=OperationalState.DOWN,
        administrative_state=AdministrativeState.UNKNOWN,
        media_state=MediaState.DISCONNECTED,
        mac_address=None,
        mtu=1500,
        receive_link_speed_bps=None,
        transmit_link_speed_bps=None,
        is_hardware=True,
    )
