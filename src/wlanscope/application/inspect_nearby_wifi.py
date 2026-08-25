from dataclasses import dataclass

from wlanscope.domain.nearby_wifi import (
    NearbyWifiSnapshot,
    WifiAccessPoint,
    WifiBand,
    WifiNetwork,
)
from wlanscope.domain.wifi import WifiPhyType


class WifiSelectionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WifiNetworkSelection:
    index: int

    def __post_init__(self) -> None:
        if self.index < 1:
            raise WifiSelectionError("Network selection must be a positive one-based index")


@dataclass(frozen=True, slots=True)
class WifiAccessPointSelection:
    index: int

    def __post_init__(self) -> None:
        if self.index < 1:
            raise WifiSelectionError("Access point selection must be a positive one-based index")


@dataclass(frozen=True, slots=True)
class NearbyWifiNetworkDetails:
    network: WifiNetwork
    bands: tuple[WifiBand, ...]
    phy_types: tuple[WifiPhyType, ...]
    center_frequencies_khz: tuple[int, ...]
    channels: tuple[int, ...]

    @property
    def reported_bss_count(self) -> int:
        return self.network.reported_bss_count

    @property
    def observed_bss_count(self) -> int:
        return len(self.network.access_points)

    @property
    def has_bss_count_discrepancy(self) -> bool:
        return self.reported_bss_count != self.observed_bss_count

    @property
    def best_observed_signal_quality(self) -> int | None:
        return max(
            (access_point.signal_quality for access_point in self.network.access_points),
            default=None,
        )


class InspectNearbyWifiNetwork:
    def execute(
        self,
        snapshot: NearbyWifiSnapshot,
        selection: WifiNetworkSelection,
    ) -> NearbyWifiNetworkDetails:
        network = _select_network(snapshot, selection.index)
        return NearbyWifiNetworkDetails(
            network=network,
            bands=network.bands,
            phy_types=_distinct_phy_types(network),
            center_frequencies_khz=tuple(
                sorted({item.center_frequency_khz for item in network.access_points})
            ),
            channels=tuple(
                sorted(
                    {
                        channel
                        for item in network.access_points
                        if (channel := item.channel) is not None
                    }
                )
            ),
        )

    def select_access_point(
        self,
        details: NearbyWifiNetworkDetails,
        selection: WifiAccessPointSelection,
    ) -> WifiAccessPoint:
        return _select_access_point(details.network, selection.index)


def _select_network(snapshot: NearbyWifiSnapshot, index: int) -> WifiNetwork:
    try:
        return snapshot.networks[index - 1]
    except IndexError as error:
        raise WifiSelectionError(
            f"Network selection {index} is outside the available range 1-{len(snapshot.networks)}"
        ) from error


def _select_access_point(network: WifiNetwork, index: int) -> WifiAccessPoint:
    try:
        return network.access_points[index - 1]
    except IndexError as error:
        raise WifiSelectionError(
            "Access point selection "
            f"{index} is outside the available range 1-{len(network.access_points)}"
        ) from error


def _distinct_phy_types(network: WifiNetwork) -> tuple[WifiPhyType, ...]:
    by_value = {item.phy_type.native_value: item.phy_type for item in network.access_points}
    return tuple(by_value[value] for value in sorted(by_value))
