import pytest

from wlanscope.application.inspect_nearby_wifi import (
    InspectNearbyWifiNetwork,
    WifiAccessPointSelection,
    WifiNetworkSelection,
    WifiSelectionError,
)
from wlanscope.domain.nearby_wifi import (
    NearbyWifiInterface,
    NearbyWifiSnapshot,
    WifiAccessPoint,
    WifiBand,
    WifiNetwork,
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


@pytest.mark.parametrize("index", [0, -1])
def test_network_selection_rejects_non_positive_index(index: int) -> None:
    with pytest.raises(WifiSelectionError, match="positive one-based"):
        WifiNetworkSelection(index)


@pytest.mark.parametrize("index", [0, -1])
def test_access_point_selection_rejects_non_positive_index(index: int) -> None:
    with pytest.raises(WifiSelectionError, match="positive one-based"):
        WifiAccessPointSelection(index)


def test_network_selection_rejects_index_above_snapshot_range() -> None:
    snapshot = _snapshot((_network(_FIRST_ID, b"FIRST"),))

    with pytest.raises(WifiSelectionError, match="outside the available range"):
        InspectNearbyWifiNetwork().execute(snapshot, WifiNetworkSelection(2))


def test_selects_hidden_network_by_snapshot_index() -> None:
    hidden = _network(_FIRST_ID, b"")
    snapshot = _snapshot((_network(_FIRST_ID, b"VISIBLE"), hidden))

    details = InspectNearbyWifiNetwork().execute(snapshot, WifiNetworkSelection(2))

    assert details.network is hidden
    assert details.network.ssid.is_empty


def test_duplicate_ssids_remain_unambiguous_by_index() -> None:
    first = _network(_FIRST_ID, b"DUPLICATE")
    second = _network(_SECOND_ID, b"DUPLICATE")
    snapshot = _snapshot((first, second), multiple_interfaces=True)

    use_case = InspectNearbyWifiNetwork()

    assert use_case.execute(snapshot, WifiNetworkSelection(1)).network.interface_id == _FIRST_ID
    assert use_case.execute(snapshot, WifiNetworkSelection(2)).network.interface_id == _SECOND_ID


def test_selection_is_stable_within_same_snapshot() -> None:
    first = _network(_FIRST_ID, b"FIRST")
    second = _network(_FIRST_ID, b"SECOND")
    snapshot = _snapshot((first, second))
    use_case = InspectNearbyWifiNetwork()

    first_result = use_case.execute(snapshot, WifiNetworkSelection(2))
    second_result = use_case.execute(snapshot, WifiNetworkSelection(2))

    assert first_result.network is second
    assert second_result.network is second


def test_details_preserve_reported_and_observed_bss_counts() -> None:
    network = _network(
        _FIRST_ID,
        b"SANITIZED",
        access_points=(_access_point(_FIRST_ID, b"SANITIZED", 11, 5_180_000),),
        reported_bss_count=3,
    )

    details = InspectNearbyWifiNetwork().execute(_snapshot((network,)), WifiNetworkSelection(1))

    assert details.reported_bss_count == 3
    assert details.observed_bss_count == 1
    assert details.has_bss_count_discrepancy


def test_details_aggregate_distinct_bands_phys_frequencies_and_channels() -> None:
    access_points = (
        _access_point(_FIRST_ID, b"SANITIZED", 11, 2_437_000, phy=7),
        _access_point(_FIRST_ID, b"SANITIZED", 12, 5_180_000, phy=8),
        _access_point(_FIRST_ID, b"SANITIZED", 13, 5_180_000, phy=8),
        _access_point(_FIRST_ID, b"SANITIZED", 14, 5_185_000, phy=99),
    )
    network = _network(_FIRST_ID, b"SANITIZED", access_points=access_points)

    details = InspectNearbyWifiNetwork().execute(_snapshot((network,)), WifiNetworkSelection(1))

    assert details.bands == (WifiBand.BAND_2_4_GHZ, WifiBand.BAND_5_GHZ)
    assert [item.native_value for item in details.phy_types] == [7, 8, 99]
    assert details.center_frequencies_khz == (2_437_000, 5_180_000, 5_185_000)
    assert details.channels == (6, 36)


def test_best_observed_signal_is_distinct_from_aggregate_signal() -> None:
    network = _network(
        _FIRST_ID,
        b"SANITIZED",
        access_points=(_access_point(_FIRST_ID, b"SANITIZED", 11, 5_180_000, signal=82),),
        aggregate_signal=61,
    )

    details = InspectNearbyWifiNetwork().execute(_snapshot((network,)), WifiNetworkSelection(1))

    assert details.network.signal_quality == 61
    assert details.best_observed_signal_quality == 82


def test_best_observed_signal_is_unavailable_without_bss() -> None:
    details = InspectNearbyWifiNetwork().execute(
        _snapshot((_network(_FIRST_ID, b"SANITIZED"),)),
        WifiNetworkSelection(1),
    )

    assert details.best_observed_signal_quality is None


def test_selects_access_point_by_deterministic_snapshot_order() -> None:
    first = _access_point(_FIRST_ID, b"SANITIZED", 11, 5_180_000, signal=80)
    second = _access_point(_FIRST_ID, b"SANITIZED", 12, 5_220_000, signal=70)
    network = _network(_FIRST_ID, b"SANITIZED", access_points=(first, second))
    use_case = InspectNearbyWifiNetwork()
    details = use_case.execute(_snapshot((network,)), WifiNetworkSelection(1))

    selected = use_case.select_access_point(details, WifiAccessPointSelection(2))

    assert selected is second


def test_access_point_selection_rejects_index_above_range() -> None:
    network = _network(_FIRST_ID, b"SANITIZED")
    details = InspectNearbyWifiNetwork().execute(_snapshot((network,)), WifiNetworkSelection(1))

    with pytest.raises(WifiSelectionError, match="outside the available range"):
        InspectNearbyWifiNetwork().select_access_point(
            details,
            WifiAccessPointSelection(1),
        )


def _snapshot(
    networks: tuple[WifiNetwork, ...],
    multiple_interfaces: bool = False,
) -> NearbyWifiSnapshot:
    interfaces = [NearbyWifiInterface(_FIRST_ID, "Sanitized adapter A")]
    if multiple_interfaces:
        interfaces.append(NearbyWifiInterface(_SECOND_ID, "Sanitized adapter B"))
    return NearbyWifiSnapshot(tuple(interfaces), networks)


def _network(
    interface_id: str,
    ssid: bytes,
    access_points: tuple[WifiAccessPoint, ...] = (),
    reported_bss_count: int | None = None,
    aggregate_signal: int = 70,
) -> WifiNetwork:
    return WifiNetwork(
        interface_id,
        "Sanitized adapter",
        WifiSsid(ssid),
        True,
        "SANITIZED",
        aggregate_signal,
        True,
        WifiAuthentication(6),
        WifiCipher(4),
        len(access_points) if reported_bss_count is None else reported_bss_count,
        access_points,
    )


def _access_point(
    interface_id: str,
    ssid: bytes,
    bssid: int,
    frequency: int,
    phy: int = 8,
    signal: int = 70,
) -> WifiAccessPoint:
    return WifiAccessPoint(
        interface_id,
        WifiSsid(ssid),
        WifiBssid(bytes.fromhex(f"0200000000{bssid:02x}")),
        WifiPhyType(phy),
        signal,
        -55,
        frequency,
    )
