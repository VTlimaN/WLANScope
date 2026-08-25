from io import StringIO

import pytest
from pytest import CaptureFixture
from rich.console import Console

from wlanscope.application.scan_nearby_wifi import ScanNearbyWifi
from wlanscope.cli import main
from wlanscope.domain.nearby_wifi import (
    AvailableWifiNetwork,
    NativeNearbyWifiData,
    NearbyWifiInterface,
    WifiAccessPoint,
    WifiScanIssue,
    WifiScanIssueCode,
)
from wlanscope.domain.wifi import (
    WifiAuthentication,
    WifiBssid,
    WifiCipher,
    WifiPhyType,
    WifiSsid,
)

_FIRST_ID = "aaaaaaaa-0000-0000-0000-000000000001"
_SECOND_ID = "bbbbbbbb-0000-0000-0000-000000000002"


def test_detail_selection_renders_network_and_bss_summary() -> None:
    output = StringIO()
    collector = CountingCollector(_data())

    exit_code = main(
        ["wifi", "scan", "--details", "1"],
        nearby_wifi_use_case=ScanNearbyWifi(collector),
        console=_console(output),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Network Details" in rendered
    assert "Reported BSS count" in rendered
    assert "Observed BSS count" in rendered
    assert "Access Points" in rendered
    assert "no additional scan was performed" in rendered
    assert collector.calls == 1


def test_access_point_selection_renders_full_bss_details() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi", "scan", "--details", "1", "--access-point", "2"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(_data())),
        console=_console(output),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Access Point Details" in rendered
    assert "RSSI" in rendered
    assert "5,180.000 MHz (5.180 GHz)" in rendered
    assert "Beacon period" in rendered
    assert "Capability information" in rendered
    assert "BSS timestamp" in rendered


@pytest.mark.parametrize("selection", ["0", "-1", "9"])
def test_invalid_network_selection_returns_usage_error(selection: str) -> None:
    output = StringIO()

    exit_code = main(
        ["wifi", "scan", "--details", selection],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(_data())),
        console=_console(output),
    )

    assert exit_code == 2
    assert "Selection error" in output.getvalue()
    assert "Traceback" not in output.getvalue()


def test_access_point_without_network_selection_is_invalid_usage(
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as result:
        main(["wifi", "scan", "--access-point", "1"])

    assert result.value.code == 2
    assert "--access-point requires --details" in capsys.readouterr().err


def test_invalid_access_point_selection_returns_usage_error() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi", "scan", "--details", "1", "--access-point", "9"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(_data())),
        console=_console(output),
    )

    assert exit_code == 2
    assert "Access point selection" in output.getvalue()


def test_hidden_network_is_selectable_by_index() -> None:
    output = StringIO()
    data = _data(networks=(_available(_FIRST_ID, b"", "PROFILE"),))

    exit_code = main(
        ["wifi", "scan", "--details", "1"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(data)),
        console=_console(output),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "<Hidden>" in rendered
    assert "Hidden" in rendered
    assert "Yes" in rendered


def test_duplicate_ssid_on_multiple_interfaces_uses_selected_snapshot_index() -> None:
    output = StringIO()
    networks = (
        _available(_FIRST_ID, b"DUPLICATE", "PROFILE A"),
        _available(_SECOND_ID, b"DUPLICATE", "PROFILE B"),
    )
    data = _data(networks=networks, multiple_interfaces=True)

    exit_code = main(
        ["wifi", "scan", "--details", "2"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(data)),
        console=_console(output),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Adapter B" in rendered
    assert "PROFILE B" in rendered
    assert "PROFILE A" not in rendered


def test_partial_snapshot_detail_preserves_partial_exit_code() -> None:
    output = StringIO()
    issue = WifiScanIssue(WifiScanIssueCode.BSS_LIST_FAILED, "BSS unavailable", _FIRST_ID)
    data = _data(issues=(issue,))

    exit_code = main(
        ["wifi", "scan", "--details", "1"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(data)),
        console=_console(output),
    )

    assert exit_code == 3
    assert "Warning" in output.getvalue()


def test_detail_selection_with_empty_successful_snapshot_returns_usage_error() -> None:
    output = StringIO()
    data = NativeNearbyWifiData((NearbyWifiInterface(_FIRST_ID, "Adapter"),), (), ())

    exit_code = main(
        ["wifi", "scan", "--details", "1"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(data)),
        console=_console(output),
    )

    assert exit_code == 2
    assert "No networks are available" in output.getvalue()


def test_detail_selection_with_no_interfaces_returns_usage_error() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi", "scan", "--details", "1"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(NativeNearbyWifiData((), (), ()))),
        console=_console(output),
    )

    assert exit_code == 2
    assert "No Wi-Fi interfaces" in output.getvalue()
    assert "No networks are available" in output.getvalue()


def test_non_tty_scan_without_selector_lists_and_never_prompts() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(_data())),
        console=_console(output),
    )

    assert exit_code == 0
    assert "Nearby Wi-Fi Networks" in output.getvalue()
    assert "Select" not in output.getvalue()


def test_external_markup_like_text_is_rendered_literally() -> None:
    output = StringIO()
    data = _data(
        networks=(
            _available(
                _FIRST_ID,
                b"[bold]SANITIZED[/bold]",
                "[blue]PROFILE[/blue]",
            ),
        ),
        first_interface_description="[red]Adapter[/red]",
    )

    exit_code = main(
        ["wifi", "scan", "--details", "1"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(data)),
        console=_console(output),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "[bold]SANITIZED[/bold]" in rendered
    assert "[red]Adapter[/red]" in rendered
    assert "[blue]PROFILE[/blue]" in rendered


def test_unknown_channel_remains_unknown_in_access_point_detail() -> None:
    output = StringIO()
    ssid = WifiSsid(b"SANITIZED")
    access_point = _access_point(_FIRST_ID, ssid, 11, 5_185_000)
    data = _data(access_points=(access_point,))

    exit_code = main(
        ["wifi", "scan", "--details", "1", "--access-point", "1"],
        nearby_wifi_use_case=ScanNearbyWifi(CountingCollector(data)),
        console=_console(output),
    )

    assert exit_code == 0
    assert "Unknown" in output.getvalue()


class CountingCollector:
    def __init__(self, data: NativeNearbyWifiData) -> None:
        self._data = data
        self.calls = 0

    def collect(self) -> NativeNearbyWifiData:
        self.calls += 1
        return self._data


def _console(output: StringIO) -> Console:
    return Console(file=output, color_system=None, width=100)


def _data(
    networks: tuple[AvailableWifiNetwork, ...] | None = None,
    access_points: tuple[WifiAccessPoint, ...] | None = None,
    issues: tuple[WifiScanIssue, ...] = (),
    multiple_interfaces: bool = False,
    first_interface_description: str = "Sanitized adapter",
) -> NativeNearbyWifiData:
    default_network = _available(_FIRST_ID, b"SANITIZED", "SANITIZED")
    selected_networks = networks if networks is not None else (default_network,)
    first_network = selected_networks[0]
    interfaces = [NearbyWifiInterface(_FIRST_ID, first_interface_description)]
    if multiple_interfaces:
        interfaces.append(NearbyWifiInterface(_SECOND_ID, "Adapter B"))
    return NativeNearbyWifiData(
        tuple(interfaces),
        selected_networks,
        access_points
        if access_points is not None
        else _access_points(first_network.interface_id, first_network.ssid),
        issues,
    )


def _available(
    interface_id: str,
    ssid: bytes,
    profile_name: str,
) -> AvailableWifiNetwork:
    return AvailableWifiNetwork(
        interface_id,
        WifiSsid(ssid),
        True,
        profile_name,
        67,
        True,
        WifiAuthentication(6),
        WifiCipher(4),
        3,
    )


def _access_points(
    interface_id: str,
    ssid: WifiSsid,
) -> tuple[WifiAccessPoint, ...]:
    return (
        _access_point(interface_id, ssid, 11, 2_437_000),
        _access_point(interface_id, ssid, 12, 5_180_000),
    )


def _access_point(
    interface_id: str,
    ssid: WifiSsid,
    bssid: int,
    frequency: int,
) -> WifiAccessPoint:
    return WifiAccessPoint(
        interface_id,
        ssid,
        WifiBssid(bytes.fromhex(f"0200000000{bssid:02x}")),
        WifiPhyType(8),
        75,
        -50,
        frequency,
        beacon_period_tu=100,
        capability_information=1,
        timestamp_us=1_000,
        host_timestamp=2_000,
    )
