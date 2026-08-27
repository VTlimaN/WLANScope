from collections.abc import Sequence
from dataclasses import replace
from typing import Protocol

from wlanscope.domain.nearby_wifi import (
    AvailableWifiNetwork,
    NativeNearbyWifiData,
    NearbyWifiInterface,
    NearbyWifiSnapshot,
    WifiAccessPoint,
    WifiAccessPointVendor,
    WifiNetwork,
)
from wlanscope.domain.wifi import WifiAuthentication, WifiBssid, WifiCipher


class NearbyWifiCollector(Protocol):
    def collect(self) -> NativeNearbyWifiData: ...


class AccessPointVendorResolver(Protocol):
    def resolve_bssids(
        self,
        bssids: Sequence[WifiBssid],
    ) -> tuple[WifiAccessPointVendor, ...]: ...


class ScanNearbyWifi:
    def __init__(
        self,
        collector: NearbyWifiCollector,
        vendor_resolver: AccessPointVendorResolver | None = None,
    ) -> None:
        self._collector = collector
        self._vendor_resolver = vendor_resolver

    def execute(self) -> NearbyWifiSnapshot:
        data = self._collector.collect()
        access_points = _deduplicate_access_points(data.access_points)
        if self._vendor_resolver is not None:
            resolutions = self._vendor_resolver.resolve_bssids(
                tuple(access_point.bssid for access_point in access_points)
            )
            if len(resolutions) != len(access_points):
                raise ValueError("AP vendor resolver must preserve access point cardinality")
            access_points = tuple(
                replace(access_point, vendor=resolution)
                for access_point, resolution in zip(access_points, resolutions, strict=True)
            )
        networks = _build_networks(data.available_networks, access_points, data.interfaces)
        return NearbyWifiSnapshot(data.interfaces, _sort_networks(networks), data.issues)


def _deduplicate_access_points(
    access_points: Sequence[WifiAccessPoint],
) -> tuple[WifiAccessPoint, ...]:
    selected: dict[tuple[str, bytes, bytes, int], WifiAccessPoint] = {}
    for access_point in access_points:
        identity = (
            access_point.interface_id,
            access_point.ssid.raw,
            access_point.bssid.octets,
            access_point.center_frequency_khz,
        )
        existing = selected.get(identity)
        if existing is None or _observation_rank(access_point) > _observation_rank(existing):
            selected[identity] = access_point
    return tuple(selected.values())


def _observation_rank(access_point: WifiAccessPoint) -> tuple[int, int, int]:
    return (
        access_point.signal_quality,
        access_point.host_timestamp or -1,
        access_point.timestamp_us or -1,
    )


def _build_networks(
    available_networks: Sequence[AvailableWifiNetwork],
    access_points: Sequence[WifiAccessPoint],
    interfaces: Sequence[NearbyWifiInterface],
) -> tuple[WifiNetwork, ...]:
    descriptions = {interface.interface_id: interface.description for interface in interfaces}
    selected = _deduplicate_available_networks(available_networks)
    networks = [
        _network_from_available(network, access_points, descriptions[network.interface_id])
        for network in selected
    ]
    represented = {(network.interface_id, network.ssid.raw) for network in selected}
    orphaned = _group_orphaned_access_points(access_points, represented)
    networks.extend(
        _network_from_access_points(
            interface_id,
            ssid,
            grouped,
            descriptions[interface_id],
        )
        for (interface_id, ssid), grouped in orphaned.items()
    )
    return tuple(networks)


def _deduplicate_available_networks(
    networks: Sequence[AvailableWifiNetwork],
) -> tuple[AvailableWifiNetwork, ...]:
    selected: dict[tuple[str, bytes, int, int], AvailableWifiNetwork] = {}
    for network in networks:
        identity = (
            network.interface_id,
            network.ssid.raw,
            network.authentication.native_value,
            network.cipher.native_value,
        )
        existing = selected.get(identity)
        if existing is None:
            selected[identity] = network
            continue
        selected[identity] = replace(
            existing,
            connectable=existing.connectable or network.connectable,
            profile_name=existing.profile_name or network.profile_name,
            signal_quality=max(existing.signal_quality, network.signal_quality),
            reported_bss_count=max(existing.reported_bss_count, network.reported_bss_count),
        )
    return tuple(selected.values())


def _network_from_available(
    network: AvailableWifiNetwork,
    access_points: Sequence[WifiAccessPoint],
    interface_description: str,
) -> WifiNetwork:
    matching = tuple(
        access_point
        for access_point in access_points
        if access_point.interface_id == network.interface_id
        and access_point.ssid.raw == network.ssid.raw
    )
    return WifiNetwork(
        interface_id=network.interface_id,
        interface_description=interface_description,
        ssid=network.ssid,
        connectable=network.connectable,
        profile_name=network.profile_name,
        signal_quality=network.signal_quality,
        security_enabled=network.security_enabled,
        authentication=network.authentication,
        cipher=network.cipher,
        reported_bss_count=network.reported_bss_count,
        access_points=_sort_access_points(matching),
        bss_type=network.bss_type,
        not_connectable_reason=network.not_connectable_reason,
        supported_phy_types=network.supported_phy_types,
    )


def _group_orphaned_access_points(
    access_points: Sequence[WifiAccessPoint],
    represented: set[tuple[str, bytes]],
) -> dict[tuple[str, bytes], tuple[WifiAccessPoint, ...]]:
    grouped: dict[tuple[str, bytes], list[WifiAccessPoint]] = {}
    for access_point in access_points:
        identity = (access_point.interface_id, access_point.ssid.raw)
        if identity not in represented:
            grouped.setdefault(identity, []).append(access_point)
    return {identity: tuple(items) for identity, items in grouped.items()}


def _network_from_access_points(
    interface_id: str,
    ssid: bytes,
    access_points: tuple[WifiAccessPoint, ...],
    interface_description: str,
) -> WifiNetwork:
    strongest = max(access_points, key=lambda item: item.signal_quality)
    return WifiNetwork(
        interface_id=interface_id,
        interface_description=interface_description,
        ssid=strongest.ssid,
        connectable=False,
        profile_name=None,
        signal_quality=strongest.signal_quality,
        security_enabled=None,
        authentication=WifiAuthentication(0),
        cipher=WifiCipher(0),
        reported_bss_count=len(access_points),
        access_points=_sort_access_points(access_points),
        bss_type=strongest.bss_type,
        supported_phy_types=tuple(
            dict.fromkeys(access_point.phy_type for access_point in access_points)
        ),
    )


def _sort_access_points(
    access_points: Sequence[WifiAccessPoint],
) -> tuple[WifiAccessPoint, ...]:
    return tuple(
        sorted(
            access_points,
            key=lambda item: (
                -item.signal_quality,
                item.center_frequency_khz,
                item.bssid.octets,
            ),
        )
    )


def _sort_networks(networks: Sequence[WifiNetwork]) -> tuple[WifiNetwork, ...]:
    return tuple(
        sorted(
            networks,
            key=lambda network: (
                network.ssid.is_empty,
                -network.best_signal_quality,
                network.ssid.display_text.casefold(),
                network.ssid.raw,
                network.interface_id,
                network.authentication.native_value,
                network.cipher.native_value,
            ),
        )
    )
