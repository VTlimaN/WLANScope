from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from typing import Protocol

from wlanscope.application.inspect_current_wifi import CurrentWifiCollector
from wlanscope.application.list_interfaces import InterfaceCollector
from wlanscope.domain.interfaces import (
    InterfaceCollectionError,
    InterfaceEnrichmentError,
    NetworkInterface,
)
from wlanscope.domain.network import (
    CurrentNetworkSnapshot,
    DhcpConfiguration,
    DhcpEnrichment,
    DhcpState,
    DnsConfiguration,
    InterfaceNetworkContext,
    InterfaceNetworkEnrichment,
    NativeNetworkData,
    NetworkEnrichmentError,
    NetworkIssue,
    NetworkIssueSource,
    Route,
)
from wlanscope.domain.wifi import CurrentWifiSnapshot, WifiCollectionError, WifiInterfaceSnapshot


class NativeNetworkCollector(Protocol):
    def collect(self) -> NativeNetworkData: ...


class NetworkEnrichmentCollector(Protocol):
    def collect(self) -> tuple[InterfaceNetworkEnrichment, ...]: ...


class DhcpEnrichmentCollector(Protocol):
    def collect(self) -> tuple[DhcpEnrichment, ...]: ...


class InspectCurrentNetwork:
    def __init__(
        self,
        primary_collector: NativeNetworkCollector,
        enrichment_collector: NetworkEnrichmentCollector | None = None,
        dhcp_collector: DhcpEnrichmentCollector | None = None,
        interface_collector: InterfaceCollector | None = None,
        wifi_collector: CurrentWifiCollector | None = None,
    ) -> None:
        self._primary_collector = primary_collector
        self._enrichment_collector = enrichment_collector
        self._dhcp_collector = dhcp_collector
        self._interface_collector = interface_collector
        self._wifi_collector = wifi_collector

    def execute(self) -> CurrentNetworkSnapshot:
        native = self._primary_collector.collect()
        fallback_enrichments, enrichment_issues = self._collect_enrichments(native)
        fallback_dhcp, dhcp_issues = self._collect_dhcp(native)
        enrichments = _prefer_primary_enrichments(native.enrichments, fallback_enrichments)
        dhcp_enrichments = _prefer_primary_dhcp(native.dhcp_enrichments, fallback_dhcp)
        interfaces, interface_issues = self._collect_interfaces()
        wifi, wifi_issues = self._collect_wifi()
        routes = _enrich_routes(native.routes, enrichments)
        contexts = _create_contexts(native, routes, enrichments, dhcp_enrichments, interfaces, wifi)
        issues = (
            *native.issues,
            *enrichment_issues,
            *dhcp_issues,
            *interface_issues,
            *wifi_issues,
        )
        return CurrentNetworkSnapshot(contexts, routes, issues)

    def _collect_enrichments(
        self,
        native: NativeNetworkData,
    ) -> tuple[tuple[InterfaceNetworkEnrichment, ...], tuple[NetworkIssue, ...]]:
        required = {
            *((item.interface_index, item.address.version) for item in native.addresses),
            *((route.interface_index, route.destination.version) for route in native.routes),
        }
        available = {(item.interface_index, item.address_family) for item in native.enrichments}
        if self._enrichment_collector is None or required <= available:
            return (), ()
        try:
            return self._enrichment_collector.collect(), ()
        except (InterfaceEnrichmentError, NetworkEnrichmentError) as error:
            return (), (_issue(NetworkIssueSource.DNS_AND_METRICS, error),)

    def _collect_dhcp(
        self, native: NativeNetworkData
    ) -> tuple[tuple[DhcpEnrichment, ...], tuple[NetworkIssue, ...]]:
        required_indices = {item.interface_index for item in native.addresses}
        primary_by_index = {item.interface_index: item for item in native.dhcp_enrichments}
        incomplete = any(
            index not in primary_by_index
            or (primary_by_index[index].enabled and primary_by_index[index].server is None)
            for index in required_indices
        )
        if self._dhcp_collector is None or not incomplete:
            return (), ()
        try:
            return self._dhcp_collector.collect(), ()
        except (InterfaceEnrichmentError, NetworkEnrichmentError) as error:
            return (), (_issue(NetworkIssueSource.DHCP, error),)

    def _collect_interfaces(
        self,
    ) -> tuple[tuple[NetworkInterface, ...], tuple[NetworkIssue, ...]]:
        if self._interface_collector is None:
            return (), ()
        try:
            return self._interface_collector.collect(), ()
        except InterfaceCollectionError as error:
            return (), (_issue(NetworkIssueSource.INTERFACE_ASSOCIATION, error),)

    def _collect_wifi(self) -> tuple[CurrentWifiSnapshot | None, tuple[NetworkIssue, ...]]:
        if self._wifi_collector is None:
            return None, ()
        try:
            snapshot = self._wifi_collector.collect()
        except WifiCollectionError as error:
            return None, (_issue(NetworkIssueSource.WIFI_ASSOCIATION, error),)
        issues = tuple(
            NetworkIssue(NetworkIssueSource.WIFI_ASSOCIATION, issue.message)
            for issue in snapshot.issues
        )
        return snapshot, issues


def _enrich_routes(
    routes: Sequence[Route], enrichments: Sequence[InterfaceNetworkEnrichment]
) -> tuple[Route, ...]:
    metrics = {
        (enrichment.interface_index, enrichment.address_family): enrichment.interface_metric
        for enrichment in enrichments
        if enrichment.interface_metric is not None
    }
    enriched = tuple(
        replace(
            route,
            interface_metric=metrics.get((route.interface_index, route.destination.version)),
        )
        for route in routes
    )
    return tuple(sorted(enriched, key=_route_sort_key))


def _prefer_primary_enrichments(
    primary: Sequence[InterfaceNetworkEnrichment],
    fallback: Sequence[InterfaceNetworkEnrichment],
) -> tuple[InterfaceNetworkEnrichment, ...]:
    records = {(item.interface_index, item.address_family): item for item in fallback}
    records.update({(item.interface_index, item.address_family): item for item in primary})
    return tuple(records[key] for key in sorted(records))


def _prefer_primary_dhcp(
    primary: Sequence[DhcpEnrichment], fallback: Sequence[DhcpEnrichment]
) -> tuple[DhcpEnrichment, ...]:
    records = {item.interface_index: item for item in fallback}
    records.update({item.interface_index: item for item in primary})
    return tuple(records[key] for key in sorted(records))


def _create_contexts(
    native: NativeNetworkData,
    routes: Sequence[Route],
    enrichments: Sequence[InterfaceNetworkEnrichment],
    dhcp_enrichments: Sequence[DhcpEnrichment],
    network_interfaces: Sequence[NetworkInterface],
    wifi: CurrentWifiSnapshot | None,
) -> tuple[InterfaceNetworkContext, ...]:
    indices = {
        *(assignment.interface_index for assignment in native.addresses),
        *(route.interface_index for route in routes),
    }
    interfaces_by_index = {interface.interface_index: interface for interface in network_interfaces}
    wifi_by_id = _wifi_by_identifier(wifi)
    dhcp_by_index = {item.interface_index: item for item in dhcp_enrichments}
    contexts = tuple(
        _create_context(
            index,
            native,
            enrichments,
            dhcp_by_index.get(index),
            interfaces_by_index.get(index),
            wifi_by_id,
        )
        for index in indices
    )
    return tuple(sorted(contexts, key=_context_sort_key))


def _create_context(
    index: int,
    native: NativeNetworkData,
    enrichments: Sequence[InterfaceNetworkEnrichment],
    dhcp_enrichment: DhcpEnrichment | None,
    network_interface: NetworkInterface | None,
    wifi_by_id: dict[str, WifiInterfaceSnapshot],
) -> InterfaceNetworkContext:
    interface_enrichments = tuple(item for item in enrichments if item.interface_index == index)
    addresses = tuple(
        sorted(
            (item for item in native.addresses if item.interface_index == index),
            key=lambda item: (item.address.version, item.address.is_link_local, int(item.address)),
        )
    )
    dns = _create_dns(index, interface_enrichments)
    dhcp = _create_dhcp(index, interface_enrichments, dhcp_enrichment)
    wifi_interface = None
    if network_interface is not None:
        wifi_interface = wifi_by_id.get(network_interface.stable_id.casefold())
    return InterfaceNetworkContext(index, addresses, dns, dhcp, network_interface, wifi_interface)


def _create_dns(
    index: int, enrichments: Sequence[InterfaceNetworkEnrichment]
) -> DnsConfiguration | None:
    if not enrichments:
        return None
    servers = tuple(dict.fromkeys(server for item in enrichments for server in item.dns_servers))
    suffix = next((item.dns_suffix for item in enrichments if item.dns_suffix), None)
    return DnsConfiguration(index, servers, suffix)


def _create_dhcp(
    index: int,
    enrichments: Sequence[InterfaceNetworkEnrichment],
    dhcp_enrichment: DhcpEnrichment | None,
) -> DhcpConfiguration:
    states = {item.address_family: item.dhcp_state for item in enrichments}
    ipv4_state = states.get(4, DhcpState.UNKNOWN)
    if dhcp_enrichment is not None:
        ipv4_state = DhcpState.ENABLED if dhcp_enrichment.enabled else DhcpState.DISABLED
    return DhcpConfiguration(
        interface_index=index,
        ipv4_state=ipv4_state,
        ipv6_state=states.get(6, DhcpState.UNKNOWN),
        server=dhcp_enrichment.server if dhcp_enrichment else None,
    )


def _wifi_by_identifier(wifi: CurrentWifiSnapshot | None) -> dict[str, WifiInterfaceSnapshot]:
    if wifi is None:
        return {}
    return {interface.interface_id.casefold(): interface for interface in wifi.interfaces}


def _route_sort_key(route: Route) -> tuple[int, int, int, int, int, int]:
    effective = route.effective_metric
    return (
        route.destination.version,
        0 if route.is_default else 1,
        effective if effective is not None else 2**32,
        route.route_metric,
        route.interface_index,
        int(route.destination.network_address),
    )


def _context_sort_key(context: InterfaceNetworkContext) -> tuple[int, int]:
    usable = any(not address.address.is_loopback for address in context.addresses)
    return (0 if usable else 1, context.interface_index)


def _issue(source: NetworkIssueSource, error: Exception) -> NetworkIssue:
    return NetworkIssue(source, str(error))
