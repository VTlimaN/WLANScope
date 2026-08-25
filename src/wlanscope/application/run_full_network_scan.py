from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from threading import Event
from typing import Protocol

from wlanscope.domain.discovery import (
    DeviceInventory,
    DiscoveryError,
    NoUsableSubnetError,
    RangeAuthorizationRequiredError,
    RangeTooLargeError,
)
from wlanscope.domain.enrichment import EnrichedDeviceInventory
from wlanscope.domain.full_scan import (
    FullNetworkSnapshot,
    FullScanIssue,
    ScanSection,
    ScanSectionResult,
    ScanSectionStatus,
)
from wlanscope.domain.interfaces import (
    InterfaceCollectionError,
    InterfaceInventory,
    NetworkInterface,
)
from wlanscope.domain.nearby_wifi import NearbyWifiSnapshot
from wlanscope.domain.network import CurrentNetworkSnapshot, NetworkCollectionError
from wlanscope.domain.wifi import CurrentWifiSnapshot, WifiCollectionError


class InterfaceInventoryUseCase(Protocol):
    def execute(self) -> InterfaceInventory: ...


class CurrentWifiUseCase(Protocol):
    def execute(
        self,
        network_interfaces: Sequence[NetworkInterface] | None = None,
    ) -> CurrentWifiSnapshot: ...


class CurrentNetworkUseCase(Protocol):
    def execute_with_associations(
        self,
        interfaces: Sequence[NetworkInterface],
        wifi: CurrentWifiSnapshot | None,
    ) -> CurrentNetworkSnapshot: ...


class NearbyWifiUseCase(Protocol):
    def execute(self) -> NearbyWifiSnapshot: ...


class DeviceDiscoveryUseCase(Protocol):
    def execute(
        self,
        allow_large_range: bool = False,
        cancel_event: Event | None = None,
        network_snapshot: CurrentNetworkSnapshot | None = None,
    ) -> DeviceInventory: ...


class DeviceEnrichmentUseCase(Protocol):
    def execute(
        self,
        inventory: DeviceInventory,
        cancel_event: Event | None = None,
    ) -> EnrichedDeviceInventory: ...


class RunFullNetworkScan:
    def __init__(
        self,
        interfaces: InterfaceInventoryUseCase,
        current_wifi: CurrentWifiUseCase,
        current_network: CurrentNetworkUseCase,
        nearby_wifi: NearbyWifiUseCase,
        devices: DeviceDiscoveryUseCase,
        enrichment: DeviceEnrichmentUseCase,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._interfaces = interfaces
        self._current_wifi = current_wifi
        self._current_network = current_network
        self._nearby_wifi = nearby_wifi
        self._devices = devices
        self._enrichment = enrichment
        self._clock = clock or _utc_now

    def execute(
        self,
        allow_large_range: bool = False,
        cancel_event: Event | None = None,
    ) -> FullNetworkSnapshot:
        cancellation = cancel_event or Event()
        started_at = self._clock()
        sections: list[ScanSectionResult] = []

        interfaces = self._run_interfaces(sections)
        current_wifi = self._run_current_wifi(interfaces, sections)
        current_network = self._run_current_network(interfaces, current_wifi, sections)
        nearby_wifi = self._run_nearby_wifi(sections)
        devices = self._run_devices(
            current_network,
            allow_large_range,
            cancellation,
            sections,
        )

        return FullNetworkSnapshot(
            started_at=started_at,
            completed_at=self._clock(),
            sections=tuple(sections),
            interfaces=interfaces,
            current_wifi=current_wifi,
            current_network=current_network,
            nearby_wifi=nearby_wifi,
            devices=devices,
        )

    def _run_interfaces(
        self,
        sections: list[ScanSectionResult],
    ) -> InterfaceInventory | None:
        try:
            inventory = self._interfaces.execute()
        except InterfaceCollectionError as error:
            sections.append(_failed(ScanSection.ADAPTERS, str(error)))
            return None
        sections.append(_completed(ScanSection.ADAPTERS, inventory.is_partial, inventory.warnings))
        return inventory

    def _run_current_wifi(
        self,
        interfaces: InterfaceInventory | None,
        sections: list[ScanSectionResult],
    ) -> CurrentWifiSnapshot | None:
        known_interfaces = interfaces.interfaces if interfaces is not None else ()
        try:
            snapshot = self._current_wifi.execute(known_interfaces)
        except WifiCollectionError as error:
            sections.append(_failed(ScanSection.CURRENT_WIFI, str(error)))
            return None
        messages = tuple(issue.message for issue in snapshot.issues)
        sections.append(_completed(ScanSection.CURRENT_WIFI, snapshot.is_partial, messages))
        return snapshot

    def _run_current_network(
        self,
        interfaces: InterfaceInventory | None,
        wifi: CurrentWifiSnapshot | None,
        sections: list[ScanSectionResult],
    ) -> CurrentNetworkSnapshot | None:
        known_interfaces = interfaces.interfaces if interfaces is not None else ()
        try:
            snapshot = self._current_network.execute_with_associations(known_interfaces, wifi)
        except NetworkCollectionError as error:
            sections.append(_failed(ScanSection.CURRENT_NETWORK, str(error)))
            return None
        messages = tuple(issue.message for issue in snapshot.issues)
        sections.append(_completed(ScanSection.CURRENT_NETWORK, snapshot.is_partial, messages))
        return snapshot

    def _run_nearby_wifi(
        self,
        sections: list[ScanSectionResult],
    ) -> NearbyWifiSnapshot | None:
        try:
            snapshot = self._nearby_wifi.execute()
        except WifiCollectionError as error:
            sections.append(_failed(ScanSection.NEARBY_WIFI, str(error)))
            return None
        messages = tuple(issue.message for issue in snapshot.issues)
        if snapshot.failed:
            sections.append(_failed(ScanSection.NEARBY_WIFI, *messages))
        else:
            sections.append(_completed(ScanSection.NEARBY_WIFI, snapshot.is_partial, messages))
        return snapshot

    def _run_devices(
        self,
        network: CurrentNetworkSnapshot | None,
        allow_large_range: bool,
        cancellation: Event,
        sections: list[ScanSectionResult],
    ) -> EnrichedDeviceInventory | None:
        if network is None:
            sections.append(
                _skipped(
                    ScanSection.DEVICES,
                    "Current network context was unavailable",
                )
            )
            return None
        try:
            discovered = self._devices.execute(
                allow_large_range,
                cancellation,
                network,
            )
        except (NoUsableSubnetError, RangeAuthorizationRequiredError, RangeTooLargeError) as error:
            sections.append(_skipped(ScanSection.DEVICES, str(error)))
            return None
        except DiscoveryError as error:
            sections.append(_failed(ScanSection.DEVICES, str(error)))
            return None
        enriched = self._enrichment.execute(discovered, cancellation)
        messages = (
            *(issue.message for issue in discovered.issues),
            *(issue.message for issue in enriched.issues),
        )
        sections.append(_completed(ScanSection.DEVICES, enriched.is_partial, messages))
        return enriched


def _completed(
    section: ScanSection,
    partial: bool,
    messages: Sequence[str],
) -> ScanSectionResult:
    status = ScanSectionStatus.PARTIAL if partial else ScanSectionStatus.SUCCESS
    return ScanSectionResult(section, status, _issues(section, messages))


def _failed(section: ScanSection, *messages: str) -> ScanSectionResult:
    return ScanSectionResult(
        section,
        ScanSectionStatus.FAILED,
        _issues(section, messages or ("The section failed",)),
    )


def _skipped(section: ScanSection, message: str) -> ScanSectionResult:
    return ScanSectionResult(
        section,
        ScanSectionStatus.SKIPPED,
        (FullScanIssue(section, message),),
    )


def _issues(section: ScanSection, messages: Sequence[str]) -> tuple[FullScanIssue, ...]:
    return tuple(FullScanIssue(section, message) for message in dict.fromkeys(messages))


def _utc_now() -> datetime:
    return datetime.now(UTC)
