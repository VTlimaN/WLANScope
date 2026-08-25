from io import StringIO

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
    WifiCollectionError,
    WifiPhyType,
    WifiSsid,
)

_INTERFACE_ID = "aaaaaaaa-0000-0000-0000-000000000001"


def test_wifi_scan_renders_network_summary() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(StaticCollector(_data())),
        console=Console(file=output, color_system=None, width=120),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Nearby Wi-Fi Networks" in rendered
    assert "SANITIZED" in rendered
    assert "2.4 GHz/5 GHz" in rendered
    assert "RSNA / CCMP" in rendered
    assert "2" in rendered


def test_wifi_scan_renders_hidden_network() -> None:
    output = StringIO()
    data = _data(ssid=WifiSsid(b""), access_points=())

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(StaticCollector(data)),
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert "<Hidden>" in output.getvalue()


def test_wifi_scan_handles_zero_interfaces() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(StaticCollector(NativeNearbyWifiData((), (), ()))),
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert "No Wi-Fi interfaces" in output.getvalue()


def test_wifi_scan_handles_zero_networks() -> None:
    output = StringIO()
    data = NativeNearbyWifiData((NearbyWifiInterface(_INTERFACE_ID, "Adapter"),), (), ())

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(StaticCollector(data)),
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert "No nearby Wi-Fi networks" in output.getvalue()


def test_wifi_scan_returns_partial_when_one_source_fails() -> None:
    output = StringIO()
    issue = WifiScanIssue(WifiScanIssueCode.BSS_LIST_FAILED, "BSS unavailable", _INTERFACE_ID)
    data = _data(issues=(issue,))

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(StaticCollector(data)),
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 3
    assert "Warning" in output.getvalue()


def test_wifi_scan_returns_failure_when_privacy_denies_all_data() -> None:
    output = StringIO()
    issue = WifiScanIssue(
        WifiScanIssueCode.ACCESS_DENIED,
        "Windows denied access. Location access may be required.",
        _INTERFACE_ID,
    )
    data = NativeNearbyWifiData(
        (NearbyWifiInterface(_INTERFACE_ID, "Adapter"),),
        (),
        (),
        (issue,),
    )

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(StaticCollector(data)),
        console=Console(file=output, color_system=None),
    )

    rendered = output.getvalue()
    assert exit_code == 1
    assert "Location access may be required" in rendered
    assert "Traceback" not in rendered


def test_wifi_scan_reports_operational_failure_without_traceback() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(FailingCollector()),
        console=Console(file=output, color_system=None),
    )

    rendered = output.getvalue()
    assert exit_code == 1
    assert "Nearby Wi-Fi unavailable" in rendered
    assert "Traceback" not in rendered


def test_wifi_without_scan_keeps_current_connection_behavior() -> None:
    output = StringIO()
    data = NativeNearbyWifiData((), (), ())

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(StaticCollector(data)),
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert "Current Wi-Fi" not in output.getvalue()


class StaticCollector:
    def __init__(self, data: NativeNearbyWifiData) -> None:
        self._data = data

    def collect(self) -> NativeNearbyWifiData:
        return self._data


class FailingCollector:
    def collect(self) -> NativeNearbyWifiData:
        raise WifiCollectionError("Nearby Wi-Fi unavailable")


def _data(
    ssid: WifiSsid | None = None,
    access_points: tuple[WifiAccessPoint, ...] | None = None,
    issues: tuple[WifiScanIssue, ...] = (),
) -> NativeNearbyWifiData:
    network_ssid = ssid or WifiSsid(b"SANITIZED")
    observed = access_points if access_points is not None else _access_points(network_ssid)
    network = AvailableWifiNetwork(
        _INTERFACE_ID,
        network_ssid,
        True,
        "SANITIZED",
        75,
        True,
        WifiAuthentication(6),
        WifiCipher(4),
        2,
    )
    return NativeNearbyWifiData(
        (NearbyWifiInterface(_INTERFACE_ID, "Sanitized adapter"),),
        (network,),
        observed,
        issues,
    )


def _access_points(ssid: WifiSsid) -> tuple[WifiAccessPoint, ...]:
    return (
        WifiAccessPoint(
            _INTERFACE_ID,
            ssid,
            WifiBssid(bytes.fromhex("020000000011")),
            WifiPhyType(7),
            70,
            -55,
            2_437_000,
        ),
        WifiAccessPoint(
            _INTERFACE_ID,
            ssid,
            WifiBssid(bytes.fromhex("020000000012")),
            WifiPhyType(8),
            75,
            -50,
            5_180_000,
        ),
    )
