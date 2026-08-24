import subprocess
import sys
from io import StringIO
from ipaddress import ip_address, ip_network

import pytest
from pytest import CaptureFixture
from rich.console import Console

from wlanscope.application.inspect_current_network import InspectCurrentNetwork
from wlanscope.application.inspect_current_wifi import InspectCurrentWifi
from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.cli import PROJECT_NAME, PROJECT_TAGLINE, main
from wlanscope.domain.interfaces import (
    AdapterEnrichment,
    AdministrativeState,
    InterfaceCollectionError,
    InterfaceEnrichmentError,
    InterfaceKind,
    MacAddress,
    MediaState,
    NetworkInterface,
    OperationalState,
)
from wlanscope.domain.network import (
    AddressOrigin,
    DadState,
    DhcpState,
    InterfaceNetworkEnrichment,
    IpAddressAssignment,
    NativeNetworkData,
    NetworkCollectionError,
    NetworkEnrichmentError,
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
    WifiCollectionError,
    WifiConnection,
    WifiConnectionMode,
    WifiInterfaceSnapshot,
    WifiInterfaceState,
    WifiIssue,
    WifiIssueCode,
    WifiPhyType,
    WifiSecurity,
    WifiSsid,
)
from wlanscope.version import __version__


def test_help_describes_available_cli(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_result:
        main(["--help"])

    output = capsys.readouterr().out

    assert exit_result.value.code == 0
    assert PROJECT_NAME in output
    assert PROJECT_TAGLINE in output
    assert "--version" in output


def test_version_uses_package_metadata(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_result:
        main(["--version"])

    assert exit_result.value.code == 0
    assert capsys.readouterr().out.strip() == f"{PROJECT_NAME} {__version__}"


@pytest.mark.parametrize("option", ["--help", "--version"])
def test_module_entry_point(option: str) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wlanscope", option],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert PROJECT_NAME in result.stdout
    assert result.stderr == ""


def test_module_entry_point_without_arguments() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wlanscope"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_cli_without_arguments_succeeds(capsys: CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert capsys.readouterr().out == ""


def test_adapters_command_renders_fake_interfaces() -> None:
    output = StringIO()
    use_case = ListNetworkInterfaces(StaticInterfaceCollector((_interface(),)))

    exit_code = main(
        ["adapters"],
        interface_use_case=use_case,
        console=Console(file=output, color_system=None, width=100),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Network Interfaces" in rendered
    assert "Ethernet" in rendered
    assert "02:00:00:00:00:01" in rendered


def test_adapters_command_handles_empty_inventory() -> None:
    output = StringIO()
    use_case = ListNetworkInterfaces(StaticInterfaceCollector(()))

    exit_code = main(
        ["adapters"],
        interface_use_case=use_case,
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert "No network interfaces" in output.getvalue()


def test_adapters_command_reports_primary_failure() -> None:
    output = StringIO()
    use_case = ListNetworkInterfaces(FailingInterfaceCollector())

    exit_code = main(
        ["adapters"],
        interface_use_case=use_case,
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 1
    assert "Interface collection unavailable" in output.getvalue()


def test_adapters_command_reports_partial_enrichment() -> None:
    output = StringIO()
    use_case = ListNetworkInterfaces(
        StaticInterfaceCollector((_interface(),)),
        FailingAdapterEnrichmentCollector(),
    )

    exit_code = main(
        ["adapters"],
        interface_use_case=use_case,
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 3
    assert "Warning" in output.getvalue()


def test_wifi_command_renders_current_connection_without_secrets() -> None:
    output = StringIO()
    snapshot = CurrentWifiSnapshot((_wifi_interface(1, _wifi_connection()),))

    exit_code = main(
        ["wifi"],
        wifi_use_case=InspectCurrentWifi(StaticWifiCollector(snapshot)),
        console=Console(file=output, color_system=None, width=100),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Current Wi-Fi" in rendered
    assert "SANITIZED" in rendered
    assert "78%" in rendered
    assert "866.7 Mbps" in rendered
    assert "password" not in rendered.casefold()
    assert "key material" not in rendered.casefold()


def test_wifi_command_renders_disconnected_interface() -> None:
    output = StringIO()
    snapshot = CurrentWifiSnapshot((_wifi_interface(4),))

    exit_code = main(
        ["wifi"],
        wifi_use_case=InspectCurrentWifi(StaticWifiCollector(snapshot)),
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert "Disconnected" in output.getvalue()


def test_wifi_command_reports_no_wireless_interface() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi"],
        wifi_use_case=InspectCurrentWifi(StaticWifiCollector(CurrentWifiSnapshot(()))),
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert "No Wi-Fi interfaces" in output.getvalue()


def test_wifi_command_reports_access_denied_as_partial_without_traceback() -> None:
    output = StringIO()
    issue = WifiIssue(
        WifiIssueCode.ACCESS_DENIED,
        "Windows denied access. Location access may be required.",
    )

    exit_code = main(
        ["wifi"],
        wifi_use_case=InspectCurrentWifi(
            StaticWifiCollector(CurrentWifiSnapshot((_wifi_interface(1),), (issue,)))
        ),
        console=Console(file=output, color_system=None),
    )

    rendered = output.getvalue()
    assert exit_code == 3
    assert "Warning" in rendered
    assert "Location access may be required" in rendered
    assert "Traceback" not in rendered


def test_wifi_command_renders_unknown_values_and_hidden_ssid() -> None:
    output = StringIO()
    connection = _wifi_connection(ssid=WifiSsid(b""), phy_type=WifiPhyType(99))

    exit_code = main(
        ["wifi"],
        wifi_use_case=InspectCurrentWifi(
            StaticWifiCollector(CurrentWifiSnapshot((_wifi_interface(1, connection),)))
        ),
        console=Console(file=output, color_system=None),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "<Hidden or empty>" in rendered
    assert "Unknown (99)" in rendered


def test_wifi_command_renders_multiple_interfaces() -> None:
    output = StringIO()
    snapshot = CurrentWifiSnapshot(
        (
            _wifi_interface(1, _wifi_connection()),
            WifiInterfaceSnapshot(
                "bbbbbbbb-0000-0000-0000-000000000002",
                "Sanitized adapter B",
                WifiInterfaceState(4),
            ),
        )
    )

    exit_code = main(
        ["wifi"],
        wifi_use_case=InspectCurrentWifi(StaticWifiCollector(snapshot)),
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert output.getvalue().count("Interface ") >= 2


def test_wifi_command_reports_operational_failure_without_traceback() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi"],
        wifi_use_case=InspectCurrentWifi(FailingWifiCollector()),
        console=Console(file=output, color_system=None),
    )

    rendered = output.getvalue()
    assert exit_code == 1
    assert "Wi-Fi collection unavailable" in rendered
    assert "Traceback" not in rendered


def test_current_command_renders_dual_stack_context_without_route_dump() -> None:
    output = StringIO()
    use_case = InspectCurrentNetwork(
        StaticCurrentPrimaryCollector(_current_data(dual_stack=True)),
        StaticCurrentEnrichmentCollector(_current_enrichments()),
    )

    exit_code = main(
        ["current"],
        current_use_case=use_case,
        console=Console(file=output, color_system=None, width=100),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Current Network" in rendered
    assert "192.0.2.24/24" in rendered
    assert "2001:db8::24/64" in rendered
    assert "192.0.2.53" in rendered
    assert "Routes observed: 3" in rendered
    assert "203.0.113.0/24" not in rendered


def test_current_command_reports_partial_dhcp_without_traceback() -> None:
    output = StringIO()
    use_case = InspectCurrentNetwork(
        StaticCurrentPrimaryCollector(_current_data()),
        StaticCurrentEnrichmentCollector(_current_enrichments()),
        FailingCurrentDhcpCollector(),
    )

    exit_code = main(
        ["current"],
        current_use_case=use_case,
        console=Console(file=output, color_system=None),
    )

    rendered = output.getvalue()
    assert exit_code == 3
    assert "DHCP enrichment" in rendered
    assert "Traceback" not in rendered


def test_current_command_handles_no_network() -> None:
    output = StringIO()
    use_case = InspectCurrentNetwork(StaticCurrentPrimaryCollector(NativeNetworkData((), ())))

    exit_code = main(
        ["current"],
        current_use_case=use_case,
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert "No usable IP configuration" in output.getvalue()


def test_current_command_reports_primary_failure_without_traceback() -> None:
    output = StringIO()

    exit_code = main(
        ["current"],
        current_use_case=InspectCurrentNetwork(FailingCurrentPrimaryCollector()),
        console=Console(file=output, color_system=None),
    )

    rendered = output.getvalue()
    assert exit_code == 1
    assert "IP configuration unavailable" in rendered
    assert "Traceback" not in rendered


def test_current_command_numbers_default_routes_per_address_family() -> None:
    output = StringIO()
    use_case = InspectCurrentNetwork(
        StaticCurrentPrimaryCollector(_current_data(dual_stack=True)),
        StaticCurrentEnrichmentCollector(_current_enrichments()),
    )

    main(
        ["current"],
        current_use_case=use_case,
        console=Console(file=output, color_system=None),
    )

    rendered = output.getvalue()
    assert "Default IPv4 #" not in rendered
    assert "Default IPv6 #" not in rendered


class StaticInterfaceCollector:
    def __init__(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        self._interfaces = interfaces

    def collect(self) -> tuple[NetworkInterface, ...]:
        return self._interfaces


class FailingInterfaceCollector:
    def collect(self) -> tuple[NetworkInterface, ...]:
        raise InterfaceCollectionError("Interface collection unavailable")


class FailingAdapterEnrichmentCollector:
    def collect(self) -> tuple[AdapterEnrichment, ...]:
        raise InterfaceEnrichmentError("Adapter enrichment unavailable")


class StaticWifiCollector:
    def __init__(self, snapshot: CurrentWifiSnapshot) -> None:
        self._snapshot = snapshot

    def collect(self) -> CurrentWifiSnapshot:
        return self._snapshot


class FailingWifiCollector:
    def collect(self) -> CurrentWifiSnapshot:
        raise WifiCollectionError("Wi-Fi collection unavailable")


class StaticCurrentPrimaryCollector:
    def __init__(self, data: NativeNetworkData) -> None:
        self._data = data

    def collect(self) -> NativeNetworkData:
        return self._data


class FailingCurrentPrimaryCollector:
    def collect(self) -> NativeNetworkData:
        raise NetworkCollectionError("IP configuration unavailable")


class StaticCurrentEnrichmentCollector:
    def __init__(self, records: tuple[InterfaceNetworkEnrichment, ...]) -> None:
        self._records = records

    def collect(self) -> tuple[InterfaceNetworkEnrichment, ...]:
        return self._records


class FailingCurrentDhcpCollector:
    def collect(self) -> tuple[()]:
        raise NetworkEnrichmentError("DHCP source unavailable")


def _interface() -> NetworkInterface:
    return NetworkInterface(
        interface_index=7,
        stable_id="aaaaaaaa-0000-0000-0000-000000000001",
        alias="Adapter A",
        friendly_name="Adapter A",
        description="Sanitized adapter",
        windows_interface_type=6,
        kind=InterfaceKind.ETHERNET,
        operational_state=OperationalState.UP,
        administrative_state=AdministrativeState.UP,
        media_state=MediaState.CONNECTED,
        mac_address=MacAddress.from_text("02:00:00:00:00:01"),
        mtu=1500,
        receive_link_speed_bps=1_000_000_000,
        transmit_link_speed_bps=1_000_000_000,
        is_hardware=True,
    )


def _wifi_interface(
    state: int,
    connection: WifiConnection | None = None,
) -> WifiInterfaceSnapshot:
    return WifiInterfaceSnapshot(
        "aaaaaaaa-0000-0000-0000-000000000001",
        "Sanitized wireless adapter",
        WifiInterfaceState(state),
        connection,
    )


def _wifi_connection(
    ssid: WifiSsid | None = None,
    phy_type: WifiPhyType | None = None,
) -> WifiConnection:
    return WifiConnection(
        state=WifiInterfaceState(1),
        mode=WifiConnectionMode(0),
        profile_name="SANITIZED",
        ssid=ssid or WifiSsid(b"SANITIZED"),
        bssid=WifiBssid(bytes.fromhex("020000000011")),
        phy_type=phy_type or WifiPhyType(8),
        signal_quality=78,
        receive_rate_kbps=866_700,
        transmit_rate_kbps=433_300,
        security=WifiSecurity(True, WifiAuthentication(6), WifiCipher(4)),
    )


def _current_data(dual_stack: bool = False) -> NativeNetworkData:
    addresses = [_current_assignment("192.0.2.24", 24)]
    routes = [
        _current_route("0.0.0.0/0", "192.0.2.1", 10),
        _current_route("203.0.113.0/24", "0.0.0.0", 0),
    ]
    if dual_stack:
        addresses.append(_current_assignment("2001:db8::24", 64))
        routes.append(_current_route("::/0", "2001:db8::1", 20))
    return NativeNetworkData(tuple(addresses), tuple(routes))


def _current_assignment(address: str, prefix: int) -> IpAddressAssignment:
    return IpAddressAssignment(
        ip_address(address),
        prefix,
        7,
        PrefixOrigin(3),
        AddressOrigin(3),
        DadState(4),
        3600,
        7200,
        False,
    )


def _current_route(destination: str, next_hop: str, metric: int) -> Route:
    return Route(
        ip_network(destination),
        ip_address(next_hop),
        7,
        metric,
        None,
        RouteProtocol(3),
        RouteOrigin(2),
    )


def _current_enrichments() -> tuple[InterfaceNetworkEnrichment, ...]:
    return (
        InterfaceNetworkEnrichment(
            7,
            4,
            20,
            DhcpState.ENABLED,
            (ip_address("192.0.2.53"),),
            "example.invalid",
        ),
        InterfaceNetworkEnrichment(
            7,
            6,
            30,
            DhcpState.DISABLED,
            (ip_address("2001:db8::53"),),
            "example.invalid",
        ),
    )
