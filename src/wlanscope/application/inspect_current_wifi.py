from collections.abc import Sequence
from dataclasses import replace
from typing import Protocol

from wlanscope.application.list_interfaces import InterfaceCollector
from wlanscope.domain.interfaces import InterfaceCollectionError, NetworkInterface
from wlanscope.domain.wifi import (
    CurrentWifiSnapshot,
    WifiInterfaceSnapshot,
    WifiIssue,
    WifiIssueCode,
)


class CurrentWifiCollector(Protocol):
    def collect(self) -> CurrentWifiSnapshot: ...


class InspectCurrentWifi:
    def __init__(
        self,
        wifi_collector: CurrentWifiCollector,
        interface_collector: InterfaceCollector | None = None,
    ) -> None:
        self._wifi_collector = wifi_collector
        self._interface_collector = interface_collector

    def execute(
        self,
        network_interfaces: Sequence[NetworkInterface] | None = None,
    ) -> CurrentWifiSnapshot:
        snapshot = self._wifi_collector.collect()
        if network_interfaces is not None:
            associated = _associate_interfaces(snapshot.interfaces, network_interfaces)
            return _sorted_snapshot(replace(snapshot, interfaces=associated))
        if self._interface_collector is None:
            return _sorted_snapshot(snapshot)

        try:
            network_interfaces = self._interface_collector.collect()
        except InterfaceCollectionError as error:
            issue = WifiIssue(
                WifiIssueCode.INTERFACE_ASSOCIATION_FAILED,
                f"Windows network interface association was unavailable: {error}",
            )
            return _sorted_snapshot(replace(snapshot, issues=(*snapshot.issues, issue)))

        associated = _associate_interfaces(snapshot.interfaces, network_interfaces)
        return _sorted_snapshot(replace(snapshot, interfaces=associated))


def _associate_interfaces(
    wifi_interfaces: Sequence[WifiInterfaceSnapshot],
    network_interfaces: Sequence[NetworkInterface],
) -> tuple[WifiInterfaceSnapshot, ...]:
    by_identifier = {
        network_interface.stable_id.casefold(): network_interface
        for network_interface in network_interfaces
    }
    return tuple(
        replace(
            wifi_interface,
            network_interface=by_identifier.get(wifi_interface.interface_id.casefold()),
        )
        for wifi_interface in wifi_interfaces
    )


def _sorted_snapshot(snapshot: CurrentWifiSnapshot) -> CurrentWifiSnapshot:
    interfaces = tuple(
        sorted(
            snapshot.interfaces,
            key=lambda interface: (
                0 if interface.state.is_connected else 1,
                interface.state.native_value,
                interface.description.casefold(),
                interface.interface_id.casefold(),
            ),
        )
    )
    return replace(snapshot, interfaces=interfaces)
