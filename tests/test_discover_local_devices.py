from collections.abc import Sequence
from ipaddress import IPv4Address, ip_address, ip_network
from threading import Event

import pytest

from wlanscope.application.discover_local_devices import (
    DiscoverLocalDevices,
    create_discovery_plan,
)
from wlanscope.domain.discovery import (
    DiscoverySource,
    IcmpUnavailableError,
    NeighborCollectionError,
    NeighborEntry,
    NeighborState,
    NoUsableSubnetError,
    ProbeResult,
    RangeAuthorizationRequiredError,
    RangeTooLargeError,
    ReachabilityState,
)
from wlanscope.domain.interfaces import MacAddress
from wlanscope.domain.network import (
    AddressOrigin,
    CurrentNetworkSnapshot,
    DadState,
    DhcpConfiguration,
    DhcpState,
    InterfaceNetworkContext,
    IpAddressAssignment,
    NetworkIssue,
    NetworkIssueSource,
    PrefixOrigin,
    Route,
    RouteOrigin,
    RouteProtocol,
)


class FakeCurrentNetwork:
    def __init__(self, snapshot: CurrentNetworkSnapshot) -> None:
        self.snapshot = snapshot
        self.calls = 0

    def execute(self) -> CurrentNetworkSnapshot:
        self.calls += 1
        return self.snapshot


class FakeNeighbors:
    def __init__(self, responses: list[tuple[NeighborEntry, ...] | Exception]) -> None:
        self.responses = responses
        self.calls = 0

    def collect(self) -> tuple[NeighborEntry, ...]:
        response = self.responses[self.calls]
        self.calls += 1
        if isinstance(response, Exception):
            raise response
        return response


class FakeProbes:
    timeout_ms = 750
    worker_count = 32

    def __init__(
        self, results: tuple[ProbeResult, ...] = (), error: Exception | None = None
    ) -> None:
        self.results = results
        self.error = error
        self.targets: tuple[IPv4Address, ...] = ()

    def probe_many(
        self,
        targets: Sequence[IPv4Address],
        cancel_event: Event,
    ) -> tuple[ProbeResult, ...]:
        self.targets = tuple(targets)
        if self.error is not None:
            raise self.error
        return self.results


def make_snapshot(prefix: int = 24, address: str = "192.0.2.10") -> CurrentNetworkSnapshot:
    assignment = IpAddressAssignment(
        ip_address(address),
        prefix,
        7,
        PrefixOrigin(3),
        AddressOrigin(3),
        DadState(4),
        3600,
        7200,
        False,
    )
    context = InterfaceNetworkContext(
        7,
        (assignment,),
        None,
        DhcpConfiguration(7, DhcpState.ENABLED, DhcpState.UNKNOWN),
    )
    route = Route(
        ip_network("0.0.0.0/0"),
        ip_address("192.0.2.1"),
        7,
        5,
        10,
        RouteProtocol(10006),
        RouteOrigin(0),
    )
    return CurrentNetworkSnapshot((context,), (route,))


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [(24, 254), (23, 510), (22, 1022), (31, 2), (32, 1)],
)
def test_plan_uses_correct_host_cardinality(prefix: int, expected: int) -> None:
    plan = create_discovery_plan(make_snapshot(prefix), prefix < 24)

    assert plan.usable_host_count == expected


def test_plan_excludes_local_address_from_targets() -> None:
    plan = create_discovery_plan(make_snapshot(), False)

    assert ip_address("192.0.2.10") not in plan.targets
    assert plan.gateways == (ip_address("192.0.2.1"),)


def test_medium_range_requires_explicit_authorization() -> None:
    with pytest.raises(RangeAuthorizationRequiredError):
        create_discovery_plan(make_snapshot(23), False)


def test_authorized_range_up_to_4096_is_allowed() -> None:
    plan = create_discovery_plan(make_snapshot(20), True)

    assert plan.usable_host_count == 4094


def test_range_above_4096_is_refused_even_when_authorized() -> None:
    with pytest.raises(RangeTooLargeError):
        create_discovery_plan(make_snapshot(19), True)


def test_plan_rejects_no_default_route() -> None:
    snapshot = CurrentNetworkSnapshot(make_snapshot().interfaces, ())

    with pytest.raises(NoUsableSubnetError):
        create_discovery_plan(snapshot, False)


def test_plan_does_not_use_non_preferred_or_skip_as_source_address() -> None:
    snapshot = make_snapshot()
    original = snapshot.interfaces[0].addresses[0]
    unusable = (
        IpAddressAssignment(
            original.address,
            original.prefix_length,
            original.interface_index,
            original.prefix_origin,
            original.address_origin,
            DadState(3),
            original.preferred_lifetime_seconds,
            original.valid_lifetime_seconds,
            True,
        ),
    )
    context = snapshot.interfaces[0]
    changed = InterfaceNetworkContext(
        context.interface_index,
        unusable,
        context.dns,
        context.dhcp,
    )

    with pytest.raises(NoUsableSubnetError):
        create_discovery_plan(CurrentNetworkSnapshot((changed,), snapshot.routes), False)


def test_discovery_merges_self_gateway_neighbor_and_icmp_sources() -> None:
    gateway = ip_address("192.0.2.1")
    neighbor = NeighborEntry(
        7,
        gateway,
        MacAddress.from_text("02:00:00:00:00:01"),
        NeighborState(5),
        True,
    )
    result = ProbeResult(IPv4Address(str(gateway)), ReachabilityState.RESPONDED, 2)
    use_case = DiscoverLocalDevices(
        FakeCurrentNetwork(make_snapshot()),
        FakeNeighbors([(neighbor,), (neighbor,)]),
        FakeProbes((result,)),
    )

    inventory = use_case.execute()
    found = next(host for host in inventory.hosts if host.address == gateway)

    assert found.sources == frozenset(
        {
            DiscoverySource.GATEWAY,
            DiscoverySource.NEIGHBOR_CACHE,
            DiscoverySource.ICMP_RESPONSE,
        }
    )
    assert found.reachability is ReachabilityState.RESPONDED


def test_supplied_m3_snapshot_avoids_duplicate_network_collection() -> None:
    snapshot = make_snapshot()
    provider = FakeCurrentNetwork(snapshot)
    use_case = DiscoverLocalDevices(provider, FakeNeighbors([(), ()]), FakeProbes())

    use_case.execute(network_snapshot=snapshot)

    assert provider.calls == 0


def test_post_scan_neighbor_enriches_responding_host_with_mac() -> None:
    target = ip_address("192.0.2.20")
    post = NeighborEntry(
        7,
        target,
        MacAddress.from_text("02:00:00:00:00:20"),
        NeighborState(4),
        False,
    )
    use_case = DiscoverLocalDevices(
        FakeCurrentNetwork(make_snapshot()),
        FakeNeighbors([(), (post,)]),
        FakeProbes((ProbeResult(IPv4Address(str(target)), ReachabilityState.RESPONDED, 3),)),
    )

    inventory = use_case.execute()
    found = next(host for host in inventory.hosts if host.address == target)

    assert found.mac_address == post.mac_address
    assert found.sources == frozenset(
        {DiscoverySource.ICMP_RESPONSE, DiscoverySource.NEIGHBOR_CACHE}
    )


def test_no_response_does_not_create_offline_host() -> None:
    target = ip_address("192.0.2.20")
    use_case = DiscoverLocalDevices(
        FakeCurrentNetwork(make_snapshot()),
        FakeNeighbors([(), ()]),
        FakeProbes((ProbeResult(IPv4Address(str(target)), ReachabilityState.NO_RESPONSE),)),
    )

    inventory = use_case.execute()

    assert all(host.address != target for host in inventory.hosts)


@pytest.mark.parametrize("native_state", [0, 1])
def test_incomplete_or_unreachable_neighbor_does_not_create_observed_host(
    native_state: int,
) -> None:
    target = ip_address("192.0.2.20")
    neighbor = NeighborEntry(7, target, None, NeighborState(native_state), False)
    use_case = DiscoverLocalDevices(
        FakeCurrentNetwork(make_snapshot()),
        FakeNeighbors([(neighbor,), (neighbor,)]),
        FakeProbes(),
    )

    inventory = use_case.execute()

    assert all(host.address != target for host in inventory.hosts)


def test_network_and_broadcast_neighbors_are_not_hosts() -> None:
    entries = (
        NeighborEntry(7, ip_address("192.0.2.0"), None, NeighborState(6), False),
        NeighborEntry(7, ip_address("192.0.2.255"), None, NeighborState(6), False),
    )
    use_case = DiscoverLocalDevices(
        FakeCurrentNetwork(make_snapshot()), FakeNeighbors([entries, entries]), FakeProbes()
    )

    inventory = use_case.execute()

    assert all(host.address not in {entry.address for entry in entries} for host in inventory.hosts)


def test_neighbor_failure_and_icmp_unavailable_return_partial_known_hosts() -> None:
    use_case = DiscoverLocalDevices(
        FakeCurrentNetwork(make_snapshot()),
        FakeNeighbors(
            [NeighborCollectionError("cache denied"), NeighborCollectionError("cache denied")]
        ),
        FakeProbes(error=IcmpUnavailableError("ICMP unavailable")),
    )

    inventory = use_case.execute()

    assert inventory.is_partial
    assert any(DiscoverySource.SELF in host.sources for host in inventory.hosts)
    assert any(DiscoverySource.GATEWAY in host.sources for host in inventory.hosts)


def test_unrelated_current_network_enrichment_issue_does_not_degrade_discovery() -> None:
    snapshot = make_snapshot()
    snapshot = CurrentNetworkSnapshot(
        snapshot.interfaces,
        snapshot.routes,
        (NetworkIssue(NetworkIssueSource.WIFI_ASSOCIATION, "Privacy limited"),),
    )
    use_case = DiscoverLocalDevices(
        FakeCurrentNetwork(snapshot), FakeNeighbors([(), ()]), FakeProbes()
    )

    inventory = use_case.execute()

    assert not inventory.is_partial


def test_canceled_discovery_does_not_probe_or_refresh_neighbors() -> None:
    cancellation = Event()
    cancellation.set()
    probes = FakeProbes()
    neighbors = FakeNeighbors([()])
    use_case = DiscoverLocalDevices(FakeCurrentNetwork(make_snapshot()), neighbors, probes)

    inventory = use_case.execute(cancel_event=cancellation)

    assert inventory.canceled
    assert probes.targets == ()
    assert neighbors.calls == 1


def test_ipv6_neighbor_is_observed_without_becoming_a_probe_target() -> None:
    neighbor = NeighborEntry(
        7,
        ip_address("2001:db8::20"),
        None,
        NeighborState(4),
        False,
    )
    probes = FakeProbes()
    use_case = DiscoverLocalDevices(
        FakeCurrentNetwork(make_snapshot()),
        FakeNeighbors([(neighbor,), (neighbor,)]),
        probes,
    )

    inventory = use_case.execute()

    assert any(host.address.version == 6 for host in inventory.hosts)
    assert all(target.version == 4 for target in probes.targets)


def test_inventory_order_is_deterministic() -> None:
    entries = (
        NeighborEntry(7, ip_address("192.0.2.30"), None, NeighborState(4), False),
        NeighborEntry(7, ip_address("192.0.2.20"), None, NeighborState(4), False),
    )
    use_case = DiscoverLocalDevices(
        FakeCurrentNetwork(make_snapshot()), FakeNeighbors([entries, entries]), FakeProbes()
    )

    inventory = use_case.execute()

    keys = [(host.address.version, int(host.address)) for host in inventory.hosts]
    assert keys == sorted(keys)
