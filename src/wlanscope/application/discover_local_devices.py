from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from ipaddress import IPv4Address, IPv4Network
from threading import Event
from typing import Protocol

from wlanscope.domain.discovery import (
    DeviceInventory,
    DiscoveredHost,
    DiscoveryIssue,
    DiscoveryPlan,
    DiscoverySource,
    HostAddress,
    IcmpUnavailableError,
    NeighborCollectionError,
    NeighborEntry,
    NoUsableSubnetError,
    ProbeResult,
    RangeAuthorizationRequiredError,
    RangeTooLargeError,
    ReachabilityState,
)
from wlanscope.domain.network import CurrentNetworkSnapshot, IpAddressAssignment
from wlanscope.platform.windows.icmp import DEFAULT_PROBE_TIMEOUT_MS, DEFAULT_PROBE_WORKERS

DEFAULT_RANGE_LIMIT = 256
AUTHORIZED_RANGE_LIMIT = 4_096


class CurrentNetworkProvider(Protocol):
    def execute(self) -> CurrentNetworkSnapshot: ...


class NeighborCollector(Protocol):
    def collect(self) -> tuple[NeighborEntry, ...]: ...


class ProbeService(Protocol):
    timeout_ms: int
    worker_count: int

    def probe_many(
        self,
        targets: Sequence[IPv4Address],
        cancel_event: Event,
    ) -> tuple[ProbeResult, ...]: ...


class DiscoverLocalDevices:
    def __init__(
        self,
        current_network: CurrentNetworkProvider,
        neighbor_collector: NeighborCollector,
        probe_service: ProbeService,
    ) -> None:
        self._current_network = current_network
        self._neighbor_collector = neighbor_collector
        self._probe_service = probe_service

    def execute(
        self,
        allow_large_range: bool = False,
        cancel_event: Event | None = None,
    ) -> DeviceInventory:
        cancellation = cancel_event or Event()
        snapshot = self._current_network.execute()
        plan = create_discovery_plan(
            snapshot,
            allow_large_range,
            self._probe_service.timeout_ms,
            self._probe_service.worker_count,
        )
        issues: list[DiscoveryIssue] = []
        hosts: dict[tuple[int, int, int], DiscoveredHost] = {}
        _add_known_hosts(hosts, plan)
        initial_neighbors = self._collect_neighbors("Initial neighbor cache", issues)
        _merge_neighbors(hosts, plan, initial_neighbors, issues)
        probe_results: tuple[ProbeResult, ...] = ()
        if not cancellation.is_set():
            try:
                probe_results = self._probe_service.probe_many(plan.targets, cancellation)
            except IcmpUnavailableError as error:
                issues.append(DiscoveryIssue("ICMP", str(error)))
        _merge_probes(hosts, plan, probe_results)
        if not cancellation.is_set():
            refreshed_neighbors = self._collect_neighbors("Refreshed neighbor cache", issues)
            _merge_neighbors(hosts, plan, refreshed_neighbors, issues)
        ordered = tuple(sorted(hosts.values(), key=_host_sort_key))
        return DeviceInventory(
            plan=plan,
            hosts=ordered,
            probes_executed=len(probe_results),
            issues=tuple(issues),
            canceled=cancellation.is_set(),
        )

    def _collect_neighbors(
        self,
        stage: str,
        issues: list[DiscoveryIssue],
    ) -> tuple[NeighborEntry, ...]:
        try:
            return self._neighbor_collector.collect()
        except NeighborCollectionError as error:
            issues.append(DiscoveryIssue(stage, str(error)))
            return ()


def create_discovery_plan(
    snapshot: CurrentNetworkSnapshot,
    allow_large_range: bool,
    timeout_ms: int = DEFAULT_PROBE_TIMEOUT_MS,
    worker_count: int = DEFAULT_PROBE_WORKERS,
) -> DiscoveryPlan:
    route = snapshot.preferred_default_route(4)
    if route is None or not isinstance(route.next_hop, IPv4Address):
        raise NoUsableSubnetError("No unambiguous IPv4 default route is available")
    context = next(
        (item for item in snapshot.interfaces if item.interface_index == route.interface_index),
        None,
    )
    if context is None:
        raise NoUsableSubnetError("The IPv4 default interface has no network context")
    assignments = tuple(
        assignment for assignment in context.addresses if _is_usable_assignment(assignment)
    )
    selected_network = _select_network(assignments, route.next_hop)
    local_addresses = tuple(
        sorted(
            (
                assignment.address
                for assignment in assignments
                if isinstance(assignment.address, IPv4Address)
                and assignment.network == selected_network
            ),
            key=int,
        )
    )
    usable_host_count = _usable_host_count(selected_network)
    _validate_range(usable_host_count, allow_large_range)
    targets = tuple(
        address for address in selected_network.hosts() if address not in local_addresses
    )
    gateways = (
        (route.next_hop,)
        if not route.next_hop.is_unspecified and route.next_hop in selected_network
        else ()
    )
    return DiscoveryPlan(
        interface_index=route.interface_index,
        subnet=selected_network,
        local_addresses=local_addresses,
        gateways=gateways,
        usable_host_count=usable_host_count,
        targets=targets,
        timeout_ms=timeout_ms,
        worker_count=worker_count,
    )


def _is_usable_assignment(assignment: IpAddressAssignment) -> bool:
    return (
        isinstance(assignment.address, IPv4Address)
        and not assignment.skip_as_source
        and assignment.dad_state.native_value == 4
        and not assignment.address.is_unspecified
        and not assignment.address.is_loopback
        and not assignment.address.is_link_local
    )


def _select_network(
    assignments: Sequence[IpAddressAssignment],
    gateway: IPv4Address,
) -> IPv4Network:
    networks = tuple(
        dict.fromkeys(
            assignment.network
            for assignment in assignments
            if isinstance(assignment.network, IPv4Network)
        )
    )
    containing_gateway = tuple(network for network in networks if gateway in network)
    if len(containing_gateway) == 1:
        return containing_gateway[0]
    if len(networks) == 1:
        return networks[0]
    raise NoUsableSubnetError("The IPv4 default interface has no unambiguous local subnet")


def _usable_host_count(network: IPv4Network) -> int:
    if network.prefixlen >= 31:
        return network.num_addresses
    return network.num_addresses - 2


def _validate_range(usable_host_count: int, allow_large_range: bool) -> None:
    if usable_host_count > AUTHORIZED_RANGE_LIMIT:
        raise RangeTooLargeError(usable_host_count)
    if usable_host_count > DEFAULT_RANGE_LIMIT and not allow_large_range:
        raise RangeAuthorizationRequiredError(usable_host_count)


def _add_known_hosts(
    hosts: dict[tuple[int, int, int], DiscoveredHost],
    plan: DiscoveryPlan,
) -> None:
    for address in plan.local_addresses:
        _merge_host(
            hosts,
            DiscoveredHost(
                plan.interface_index,
                address,
                None,
                ReachabilityState.NOT_PROBED,
                frozenset({DiscoverySource.SELF}),
            ),
            [],
        )
    for address in plan.gateways:
        _merge_host(
            hosts,
            DiscoveredHost(
                plan.interface_index,
                address,
                None,
                ReachabilityState.NOT_PROBED,
                frozenset({DiscoverySource.GATEWAY}),
            ),
            [],
        )


def _merge_neighbors(
    hosts: dict[tuple[int, int, int], DiscoveredHost],
    plan: DiscoveryPlan,
    neighbors: Sequence[NeighborEntry],
    issues: list[DiscoveryIssue],
) -> None:
    for neighbor in neighbors:
        if neighbor.interface_index != plan.interface_index:
            continue
        if isinstance(neighbor.address, IPv4Address) and (
            neighbor.address not in plan.subnet or _is_reserved_boundary(neighbor.address, plan)
        ):
            continue
        key = _host_key(neighbor.interface_index, neighbor.address)
        if neighbor.state.native_value in {0, 1} and key not in hosts:
            continue
        _merge_host(
            hosts,
            DiscoveredHost(
                neighbor.interface_index,
                neighbor.address,
                neighbor.mac_address,
                ReachabilityState.NOT_PROBED,
                frozenset({DiscoverySource.NEIGHBOR_CACHE}),
                neighbor.state,
            ),
            issues,
        )


def _is_reserved_boundary(address: IPv4Address, plan: DiscoveryPlan) -> bool:
    return plan.subnet.prefixlen < 31 and address in {
        plan.subnet.network_address,
        plan.subnet.broadcast_address,
    }


def _merge_probes(
    hosts: dict[tuple[int, int, int], DiscoveredHost],
    plan: DiscoveryPlan,
    results: Sequence[ProbeResult],
) -> None:
    for result in results:
        key = _host_key(plan.interface_index, result.address)
        existing = hosts.get(key)
        if existing is None and result.state is not ReachabilityState.RESPONDED:
            continue
        sources = (
            frozenset({DiscoverySource.ICMP_RESPONSE})
            if result.state is ReachabilityState.RESPONDED
            else frozenset()
        )
        if existing is None:
            hosts[key] = DiscoveredHost(
                plan.interface_index,
                result.address,
                None,
                result.state,
                sources,
            )
        else:
            hosts[key] = replace(
                existing,
                reachability=_preferred_reachability(existing.reachability, result.state),
                sources=existing.sources | sources,
            )


def _merge_host(
    hosts: dict[tuple[int, int, int], DiscoveredHost],
    candidate: DiscoveredHost,
    issues: list[DiscoveryIssue],
) -> None:
    key = _host_key(candidate.interface_index, candidate.address)
    existing = hosts.get(key)
    if existing is None:
        hosts[key] = candidate
        return
    mac_address = existing.mac_address or candidate.mac_address
    if (
        existing.mac_address is not None
        and candidate.mac_address is not None
        and existing.mac_address != candidate.mac_address
    ):
        issues.append(
            DiscoveryIssue(
                "Host merge",
                "Conflicting neighbor MAC data was preserved deterministically for "
                f"{candidate.address}",
            )
        )
    hosts[key] = replace(
        existing,
        mac_address=mac_address,
        reachability=_preferred_reachability(existing.reachability, candidate.reachability),
        sources=existing.sources | candidate.sources,
        neighbor_state=candidate.neighbor_state or existing.neighbor_state,
    )


def _preferred_reachability(
    first: ReachabilityState,
    second: ReachabilityState,
) -> ReachabilityState:
    priority = {
        ReachabilityState.RESPONDED: 0,
        ReachabilityState.NO_RESPONSE: 1,
        ReachabilityState.PROBE_FAILED: 2,
        ReachabilityState.CANCELED: 3,
        ReachabilityState.NOT_PROBED: 4,
    }
    return min((first, second), key=priority.__getitem__)


def _host_key(interface_index: int, address: HostAddress) -> tuple[int, int, int]:
    return (interface_index, address.version, int(address))


def _host_sort_key(host: DiscoveredHost) -> tuple[int, int, int]:
    return _host_key(host.interface_index, host.address)
