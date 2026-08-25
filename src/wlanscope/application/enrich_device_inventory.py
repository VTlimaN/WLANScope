from __future__ import annotations

from collections.abc import Sequence
from threading import Event
from typing import Protocol

from wlanscope.domain.discovery import DeviceInventory, DiscoveredHost, HostAddress
from wlanscope.domain.enrichment import (
    EnrichedDeviceInventory,
    EnrichedHost,
    EnrichmentIssue,
    HostnameResolution,
    HostnameResolutionBatch,
    HostnameResolutionState,
    VendorResolution,
    VendorResolutionBatch,
    VendorResolutionState,
)


class HostnameResolver(Protocol):
    def resolve_many(
        self,
        addresses: Sequence[HostAddress],
        cancel_event: Event,
    ) -> HostnameResolutionBatch: ...


class VendorResolver(Protocol):
    def resolve_many(self, hosts: Sequence[DiscoveredHost]) -> VendorResolutionBatch: ...


class EnrichDeviceInventory:
    def __init__(
        self,
        hostname_resolver: HostnameResolver,
        vendor_resolver: VendorResolver,
    ) -> None:
        self._hostname_resolver = hostname_resolver
        self._vendor_resolver = vendor_resolver

    def execute(
        self,
        inventory: DeviceInventory,
        cancel_event: Event | None = None,
    ) -> EnrichedDeviceInventory:
        cancellation = cancel_event or Event()
        addresses = tuple(host.address for host in inventory.hosts)
        hostname_batch = self._hostname_resolver.resolve_many(addresses, cancellation)
        vendor_batch = self._vendor_resolver.resolve_many(inventory.hosts)
        hostnames = {resolution.address: resolution for resolution in hostname_batch.resolutions}
        vendors = {
            (resolution.interface_index, resolution.address): resolution
            for resolution in vendor_batch.resolutions
        }
        hosts = tuple(
            EnrichedHost(
                discovered=host,
                hostname=hostnames.get(host.address, _hostname_not_attempted(host.address)),
                vendor=vendors.get(
                    (host.interface_index, host.address),
                    _vendor_not_applicable(host),
                ),
            )
            for host in inventory.hosts
        )
        issues = tuple(
            issue
            for issue in (
                _issue("DNS PTR", hostname_batch.systemic_issue),
                _issue("Local OUI registry", vendor_batch.systemic_issue),
            )
            if issue is not None
        )
        return EnrichedDeviceInventory(inventory, hosts, issues)


def _hostname_not_attempted(address: HostAddress) -> HostnameResolution:
    return HostnameResolution(address, HostnameResolutionState.NOT_ATTEMPTED)


def _vendor_not_applicable(host: DiscoveredHost) -> VendorResolution:
    return VendorResolution(
        host.interface_index,
        host.address,
        VendorResolutionState.NOT_APPLICABLE,
    )


def _issue(source: str, message: str | None) -> EnrichmentIssue | None:
    return EnrichmentIssue(source, message) if message else None
