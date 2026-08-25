from ipaddress import IPv4Address, IPv4Network, ip_address

import pytest

from wlanscope.domain.discovery import (
    DeviceInventory,
    DiscoveredHost,
    DiscoveryPlan,
    DiscoverySource,
    NeighborEntry,
    NeighborState,
    ProbeResult,
    ReachabilityState,
)
from wlanscope.domain.interfaces import MacAddress


def test_neighbor_state_preserves_known_and_unknown_values() -> None:
    assert NeighborState(5).display_name == "Reachable"
    assert NeighborState(99).display_name == "Unknown (99)"


def test_neighbor_entry_supports_ipv4_and_ipv6() -> None:
    ipv4 = NeighborEntry(7, ip_address("192.0.2.10"), None, NeighborState(4), False)
    ipv6 = NeighborEntry(7, ip_address("2001:db8::10"), None, NeighborState(5), True)

    assert ipv4.address.version == 4
    assert ipv6.address.version == 6
    assert ipv6.is_router


def test_neighbor_entry_rejects_negative_interface_index() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        NeighborEntry(-1, ip_address("192.0.2.10"), None, NeighborState(4), False)


def test_discovery_plan_validates_targets_belong_to_subnet() -> None:
    with pytest.raises(ValueError, match="targets"):
        DiscoveryPlan(
            7,
            IPv4Network("192.0.2.0/24"),
            (IPv4Address("192.0.2.10"),),
            (),
            254,
            (IPv4Address("198.51.100.10"),),
            750,
            32,
        )


def test_probe_response_requires_response_time() -> None:
    with pytest.raises(ValueError, match="response time"):
        ProbeResult(IPv4Address("192.0.2.10"), ReachabilityState.RESPONDED)


def test_discovered_host_requires_provenance() -> None:
    with pytest.raises(ValueError, match="source"):
        DiscoveredHost(
            7,
            ip_address("192.0.2.10"),
            None,
            ReachabilityState.NOT_PROBED,
            frozenset(),
        )


def test_device_inventory_is_partial_for_issues_or_cancellation() -> None:
    plan = DiscoveryPlan(
        7,
        IPv4Network("192.0.2.10/32"),
        (IPv4Address("192.0.2.10"),),
        (),
        1,
        (),
        750,
        32,
    )
    host = DiscoveredHost(
        7,
        ip_address("192.0.2.10"),
        MacAddress.from_text("02:00:00:00:00:10"),
        ReachabilityState.NOT_PROBED,
        frozenset({DiscoverySource.SELF}),
    )

    assert not DeviceInventory(plan, (host,), 0).is_partial
    assert DeviceInventory(plan, (host,), 0, canceled=True).is_partial
