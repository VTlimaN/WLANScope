import pytest

from wlanscope.domain.nearby_wifi import (
    AvailableWifiNetwork,
    NearbyWifiInterface,
    NearbyWifiSnapshot,
    WifiAccessPoint,
    WifiBand,
    WifiNetwork,
    WifiScanIssue,
    WifiScanIssueCode,
    wifi_band_from_frequency,
    wifi_channel_from_frequency,
)
from wlanscope.domain.wifi import (
    WifiAuthentication,
    WifiBssid,
    WifiCipher,
    WifiPhyType,
    WifiSsid,
)

_INTERFACE_ID = "aaaaaaaa-0000-0000-0000-000000000001"


@pytest.mark.parametrize(
    ("frequency_khz", "expected"),
    [
        (2_412_000, 1),
        (2_437_000, 6),
        (2_472_000, 13),
        (2_484_000, 14),
        (5_180_000, 36),
        (5_260_000, 52),
        (5_500_000, 100),
        (5_745_000, 149),
        (5_935_000, 2),
        (5_955_000, 1),
        (5_975_000, 5),
        (7_115_000, 233),
    ],
)
def test_known_frequency_maps_to_channel(frequency_khz: int, expected: int) -> None:
    assert wifi_channel_from_frequency(frequency_khz) == expected


@pytest.mark.parametrize(
    "frequency_khz",
    [0, 2_413_000, 5_185_000, 5_951_000, 7_120_000, 5_955_500],
)
def test_unknown_frequency_does_not_invent_channel(frequency_khz: int) -> None:
    assert wifi_channel_from_frequency(frequency_khz) is None


@pytest.mark.parametrize(
    ("frequency_khz", "expected"),
    [
        (2_412_000, WifiBand.BAND_2_4_GHZ),
        (5_500_000, WifiBand.BAND_5_GHZ),
        (5_955_000, WifiBand.BAND_6_GHZ),
        (900_000, WifiBand.OTHER),
    ],
)
def test_frequency_maps_to_band(frequency_khz: int, expected: WifiBand) -> None:
    assert wifi_band_from_frequency(frequency_khz) is expected


def test_access_point_preserves_rssi_signal_phy_and_frequency() -> None:
    access_point = _access_point(5_180_000, 81, -47)

    assert access_point.signal_quality == 81
    assert access_point.rssi_dbm == -47
    assert access_point.phy_type.display_name == "VHT"
    assert access_point.channel == 36
    assert access_point.band is WifiBand.BAND_5_GHZ


@pytest.mark.parametrize("signal", [-1, 101])
def test_access_point_rejects_invalid_signal(signal: int) -> None:
    with pytest.raises(ValueError, match="Signal quality"):
        _access_point(5_180_000, signal, -47)


def test_access_point_rejects_non_positive_frequency() -> None:
    with pytest.raises(ValueError, match="Center frequency"):
        _access_point(0, 50, -60)


def test_network_supports_multiple_access_points_and_bands() -> None:
    network = _network((_access_point(2_437_000), _access_point(5_180_000, bssid=12)))

    assert len(network.access_points) == 2
    assert network.best_signal_quality == 70
    assert set(network.bands) == {WifiBand.BAND_2_4_GHZ, WifiBand.BAND_5_GHZ}


def test_hidden_network_retains_empty_byte_safe_ssid() -> None:
    network = _network((), ssid=WifiSsid(b""))

    assert network.ssid.is_empty
    assert network.ssid.raw == b""


def test_network_rejects_access_point_from_another_interface() -> None:
    access_point = WifiAccessPoint(
        "bbbbbbbb-0000-0000-0000-000000000002",
        WifiSsid(b"SANITIZED"),
        WifiBssid(bytes.fromhex("020000000011")),
        WifiPhyType(8),
        70,
        -55,
        5_180_000,
    )

    with pytest.raises(ValueError, match="same Wi-Fi interface"):
        _network((access_point,))


def test_available_network_validates_reported_bss_count() -> None:
    with pytest.raises(ValueError, match="BSS count"):
        AvailableWifiNetwork(
            _INTERFACE_ID,
            WifiSsid(b"SANITIZED"),
            True,
            None,
            50,
            True,
            WifiAuthentication(6),
            WifiCipher(4),
            -1,
        )


def test_snapshot_distinguishes_partial_and_failed() -> None:
    issue = WifiScanIssue(WifiScanIssueCode.ACCESS_DENIED, "Denied", _INTERFACE_ID)
    interface = NearbyWifiInterface(_INTERFACE_ID, "Sanitized adapter")

    partial = NearbyWifiSnapshot((interface,), (_network(()),), (issue,))
    failed = NearbyWifiSnapshot((interface,), (), (issue,))

    assert partial.is_partial
    assert not partial.failed
    assert failed.failed
    assert not failed.is_partial


def _access_point(
    frequency_khz: int,
    signal: int = 70,
    rssi: int = -55,
    bssid: int = 11,
) -> WifiAccessPoint:
    return WifiAccessPoint(
        _INTERFACE_ID,
        WifiSsid(b"SANITIZED"),
        WifiBssid(bytes.fromhex(f"0200000000{bssid:02x}")),
        WifiPhyType(8),
        signal,
        rssi,
        frequency_khz,
    )


def _network(
    access_points: tuple[WifiAccessPoint, ...],
    ssid: WifiSsid | None = None,
) -> WifiNetwork:
    return WifiNetwork(
        _INTERFACE_ID,
        "Sanitized adapter",
        ssid or WifiSsid(b"SANITIZED"),
        True,
        None,
        65,
        True,
        WifiAuthentication(6),
        WifiCipher(4),
        len(access_points),
        access_points,
    )
