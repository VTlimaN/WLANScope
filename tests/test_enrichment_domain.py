from ipaddress import IPv4Address, IPv4Network, ip_address

import pytest

from wlanscope.domain.discovery import (
    DeviceInventory,
    DiscoveredHost,
    DiscoveryPlan,
    DiscoverySource,
    ReachabilityState,
)
from wlanscope.domain.enrichment import (
    EnrichedDeviceInventory,
    EnrichedHost,
    EnrichmentSource,
    HostnameResolution,
    HostnameResolutionState,
    VendorResolution,
    VendorResolutionState,
)


def test_resolved_hostname_requires_ptr_provenance() -> None:
    address = ip_address("192.0.2.10")

    resolution = HostnameResolution(
        address,
        HostnameResolutionState.RESOLVED,
        "host.example",
        EnrichmentSource.PTR,
    )

    assert resolution.hostname == "host.example"


def test_unresolved_hostname_rejects_value() -> None:
    with pytest.raises(ValueError, match="unresolved"):
        HostnameResolution(
            ip_address("192.0.2.10"),
            HostnameResolutionState.NOT_FOUND,
            "host.example",
        )


def test_resolved_vendor_requires_registry_provenance() -> None:
    resolution = VendorResolution(
        7,
        ip_address("192.0.2.10"),
        VendorResolutionState.RESOLVED,
        "Example Networks",
        EnrichmentSource.LOCAL_OUI_REGISTRY,
    )

    assert resolution.vendor == "Example Networks"


def test_unresolved_vendor_rejects_value() -> None:
    with pytest.raises(ValueError, match="unresolved"):
        VendorResolution(
            7,
            ip_address("192.0.2.10"),
            VendorResolutionState.UNKNOWN,
            "Example Networks",
        )


def test_enriched_host_requires_matching_identity() -> None:
    discovered = DiscoveredHost(
        7,
        ip_address("192.0.2.10"),
        None,
        ReachabilityState.NOT_PROBED,
        frozenset({DiscoverySource.SELF}),
    )

    with pytest.raises(ValueError, match="Hostname"):
        EnrichedHost(
            discovered,
            HostnameResolution(ip_address("192.0.2.11"), HostnameResolutionState.NOT_FOUND),
            VendorResolution(
                7,
                discovered.address,
                VendorResolutionState.NOT_APPLICABLE,
            ),
        )


def test_resolved_vendor_requires_discovered_mac() -> None:
    discovered = DiscoveredHost(
        7,
        ip_address("192.0.2.10"),
        None,
        ReachabilityState.NOT_PROBED,
        frozenset({DiscoverySource.SELF}),
    )

    with pytest.raises(ValueError, match="MAC"):
        EnrichedHost(
            discovered,
            HostnameResolution(discovered.address, HostnameResolutionState.NOT_FOUND),
            VendorResolution(
                7,
                discovered.address,
                VendorResolutionState.RESOLVED,
                "Example Networks",
                EnrichmentSource.LOCAL_OUI_REGISTRY,
            ),
        )


def test_inventory_metrics_distinguish_attempts_and_results() -> None:
    address = IPv4Address("192.0.2.10")
    host = DiscoveredHost(
        7,
        address,
        None,
        ReachabilityState.NOT_PROBED,
        frozenset({DiscoverySource.SELF}),
    )
    plan = DiscoveryPlan(7, IPv4Network("192.0.2.10/32"), (address,), (), 1, (), 750, 32)
    discovered = DeviceInventory(plan, (host,), 0)
    enriched_host = EnrichedHost(
        host,
        HostnameResolution(
            address,
            HostnameResolutionState.RESOLVED,
            "host.example",
            EnrichmentSource.PTR,
        ),
        VendorResolution(7, address, VendorResolutionState.LOCALLY_ADMINISTERED),
    )
    inventory = EnrichedDeviceInventory(discovered, (enriched_host,))

    assert inventory.ptr_attempted_count == 1
    assert inventory.ptr_resolved_count == 1
    assert inventory.vendor_attempted_count == 0
    assert inventory.locally_administered_count == 1


def test_enriched_inventory_rejects_missing_or_reordered_hosts() -> None:
    address = IPv4Address("192.0.2.10")
    host = DiscoveredHost(
        7,
        address,
        None,
        ReachabilityState.NOT_PROBED,
        frozenset({DiscoverySource.SELF}),
    )
    plan = DiscoveryPlan(7, IPv4Network("192.0.2.10/32"), (address,), (), 1, (), 750, 32)
    discovered = DeviceInventory(plan, (host,), 0)

    with pytest.raises(ValueError, match="preserve"):
        EnrichedDeviceInventory(discovered, ())
