from collections.abc import Sequence

from wlanscope.application.scan_nearby_wifi import ScanNearbyWifi
from wlanscope.domain.enrichment import EnrichmentSource, VendorResolutionState
from wlanscope.domain.nearby_wifi import (
    AvailableWifiNetwork,
    NativeNearbyWifiData,
    NearbyWifiInterface,
    WifiAccessPoint,
    WifiAccessPointVendor,
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


def test_groups_multiple_access_points_under_available_network() -> None:
    data = _data(
        networks=(_available(_FIRST_ID, b"SANITIZED", 68, 2),),
        access_points=(
            _access_point(_FIRST_ID, b"SANITIZED", 11, 68, 2_437_000),
            _access_point(_FIRST_ID, b"SANITIZED", 12, 81, 5_180_000),
        ),
    )

    snapshot = ScanNearbyWifi(StaticNearbyCollector(data)).execute()

    assert len(snapshot.networks) == 1
    assert len(snapshot.networks[0].access_points) == 2
    assert snapshot.networks[0].best_signal_quality == 81


def test_preserves_same_ssid_per_interface() -> None:
    data = NativeNearbyWifiData(
        (
            NearbyWifiInterface(_FIRST_ID, "Adapter A"),
            NearbyWifiInterface(_SECOND_ID, "Adapter B"),
        ),
        (
            _available(_FIRST_ID, b"SANITIZED", 70, 1),
            _available(_SECOND_ID, b"SANITIZED", 60, 1),
        ),
        (),
    )

    snapshot = ScanNearbyWifi(StaticNearbyCollector(data)).execute()

    assert len(snapshot.networks) == 2
    assert {network.interface_id for network in snapshot.networks} == {_FIRST_ID, _SECOND_ID}


def test_preserves_hidden_network() -> None:
    snapshot = ScanNearbyWifi(
        StaticNearbyCollector(_data(networks=(_available(_FIRST_ID, b"", 50, 1),)))
    ).execute()

    assert snapshot.networks[0].ssid.is_empty


def test_bss_without_available_network_is_preserved() -> None:
    access_point = _access_point(_FIRST_ID, b"SANITIZED", 11, 72, 5_180_000)

    snapshot = ScanNearbyWifi(StaticNearbyCollector(_data(access_points=(access_point,)))).execute()

    assert len(snapshot.networks) == 1
    assert snapshot.networks[0].authentication.display_name == "Unknown (0)"
    assert snapshot.networks[0].access_points == (access_point,)


def test_exact_duplicate_uses_strongest_newest_observation() -> None:
    older = _access_point(_FIRST_ID, b"SANITIZED", 11, 60, 5_180_000, host_timestamp=10)
    newer = _access_point(_FIRST_ID, b"SANITIZED", 11, 75, 5_180_000, host_timestamp=20)
    data = _data(
        networks=(_available(_FIRST_ID, b"SANITIZED", 70, 1),),
        access_points=(older, newer),
    )

    snapshot = ScanNearbyWifi(StaticNearbyCollector(data)).execute()

    assert snapshot.networks[0].access_points == (newer,)


def test_same_bssid_on_different_frequencies_is_not_collapsed() -> None:
    data = _data(
        networks=(_available(_FIRST_ID, b"SANITIZED", 70, 2),),
        access_points=(
            _access_point(_FIRST_ID, b"SANITIZED", 11, 70, 5_180_000),
            _access_point(_FIRST_ID, b"SANITIZED", 11, 65, 5_220_000),
        ),
    )

    snapshot = ScanNearbyWifi(StaticNearbyCollector(data)).execute()

    assert len(snapshot.networks[0].access_points) == 2


def test_network_sorting_is_visible_then_signal_then_ssid() -> None:
    data = _data(
        networks=(
            _available(_FIRST_ID, b"BETA", 40, 1),
            _available(_FIRST_ID, b"", 99, 1),
            _available(_FIRST_ID, b"ALPHA", 80, 1),
        )
    )

    snapshot = ScanNearbyWifi(StaticNearbyCollector(data)).execute()

    assert [network.ssid.raw for network in snapshot.networks] == [b"ALPHA", b"BETA", b""]


def test_access_points_sort_by_signal_frequency_and_bssid() -> None:
    data = _data(
        networks=(_available(_FIRST_ID, b"SANITIZED", 70, 3),),
        access_points=(
            _access_point(_FIRST_ID, b"SANITIZED", 13, 60, 5_220_000),
            _access_point(_FIRST_ID, b"SANITIZED", 12, 80, 5_220_000),
            _access_point(_FIRST_ID, b"SANITIZED", 11, 80, 5_180_000),
        ),
    )

    access_points = ScanNearbyWifi(StaticNearbyCollector(data)).execute().networks[0].access_points

    assert [item.bssid.octets[-1] for item in access_points] == [11, 12, 13]


def test_partial_issues_are_preserved() -> None:
    issue = WifiScanIssue(WifiScanIssueCode.BSS_LIST_FAILED, "BSS unavailable", _FIRST_ID)
    data = _data(networks=(_available(_FIRST_ID, b"SANITIZED", 70, 1),), issues=(issue,))

    snapshot = ScanNearbyWifi(StaticNearbyCollector(data)).execute()

    assert snapshot.is_partial
    assert snapshot.issues == (issue,)


def test_empty_scan_is_successful() -> None:
    snapshot = ScanNearbyWifi(StaticNearbyCollector(_data())).execute()

    assert snapshot.networks == ()
    assert not snapshot.failed


def test_vendor_enrichment_runs_once_after_access_point_deduplication() -> None:
    older = _access_point(_FIRST_ID, b"SANITIZED", 11, 60, 5_180_000)
    newer = _access_point(_FIRST_ID, b"SANITIZED", 11, 75, 5_180_000)
    resolver = VendorResolverSpy()

    snapshot = ScanNearbyWifi(
        StaticNearbyCollector(
            _data(
                networks=(_available(_FIRST_ID, b"SANITIZED", 70, 1),),
                access_points=(older, newer),
            )
        ),
        resolver,
    ).execute()

    assert len(resolver.calls) == 1
    assert len(resolver.calls[0]) == 1
    assert snapshot.networks[0].access_points[0].vendor.vendor == "Example Networks"


class StaticNearbyCollector:
    def __init__(self, data: NativeNearbyWifiData) -> None:
        self._data = data

    def collect(self) -> NativeNearbyWifiData:
        return self._data


class VendorResolverSpy:
    def __init__(self) -> None:
        self.calls: list[tuple[WifiBssid, ...]] = []

    def resolve_bssids(
        self,
        bssids: Sequence[WifiBssid],
    ) -> tuple[WifiAccessPointVendor, ...]:
        self.calls.append(tuple(bssids))
        return tuple(
            WifiAccessPointVendor(
                VendorResolutionState.RESOLVED,
                "Example Networks",
                EnrichmentSource.LOCAL_OUI_REGISTRY,
            )
            for _ in bssids
        )


def _data(
    networks: tuple[AvailableWifiNetwork, ...] = (),
    access_points: tuple[WifiAccessPoint, ...] = (),
    issues: tuple[WifiScanIssue, ...] = (),
) -> NativeNearbyWifiData:
    return NativeNearbyWifiData(
        (NearbyWifiInterface(_FIRST_ID, "Sanitized adapter"),),
        networks,
        access_points,
        issues,
    )


def _available(
    interface_id: str,
    ssid: bytes,
    signal: int,
    bss_count: int,
) -> AvailableWifiNetwork:
    return AvailableWifiNetwork(
        interface_id,
        WifiSsid(ssid),
        True,
        "SANITIZED",
        signal,
        True,
        WifiAuthentication(6),
        WifiCipher(4),
        bss_count,
    )


def _access_point(
    interface_id: str,
    ssid: bytes,
    bssid: int,
    signal: int,
    frequency: int,
    host_timestamp: int = 0,
) -> WifiAccessPoint:
    return WifiAccessPoint(
        interface_id,
        WifiSsid(ssid),
        WifiBssid(bytes.fromhex(f"0200000000{bssid:02x}")),
        WifiPhyType(8),
        signal,
        -55,
        frequency,
        host_timestamp=host_timestamp,
    )
