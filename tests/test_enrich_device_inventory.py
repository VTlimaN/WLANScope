from collections.abc import Sequence
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from threading import Event

from wlanscope.application.enrich_device_inventory import EnrichDeviceInventory
from wlanscope.domain.discovery import (
    DeviceInventory,
    DiscoveredHost,
    DiscoveryPlan,
    DiscoverySource,
    HostAddress,
    ReachabilityState,
)
from wlanscope.domain.enrichment import (
    EnrichmentSource,
    HostnameResolution,
    HostnameResolutionBatch,
    HostnameResolutionState,
    VendorResolution,
    VendorResolutionBatch,
    VendorResolutionState,
)
from wlanscope.domain.interfaces import MacAddress


class FakeHostnames:
    def __init__(self, batch: HostnameResolutionBatch) -> None:
        self.batch = batch
        self.addresses: tuple[HostAddress, ...] = ()

    def resolve_many(
        self,
        addresses: Sequence[HostAddress],
        cancel_event: Event,
    ) -> HostnameResolutionBatch:
        self.addresses = tuple(addresses)
        return self.batch


class FakeVendors:
    def __init__(self, batch: VendorResolutionBatch) -> None:
        self.batch = batch
        self.hosts: tuple[DiscoveredHost, ...] = ()

    def resolve_many(self, hosts: Sequence[DiscoveredHost]) -> VendorResolutionBatch:
        self.hosts = tuple(hosts)
        return self.batch


def make_inventory() -> DeviceInventory:
    local = DiscoveredHost(
        7,
        IPv4Address("192.0.2.10"),
        MacAddress.from_text("02:00:00:00:00:10"),
        ReachabilityState.NOT_PROBED,
        frozenset({DiscoverySource.SELF}),
    )
    gateway = DiscoveredHost(
        7,
        IPv4Address("192.0.2.1"),
        MacAddress.from_text("00:11:22:33:44:55"),
        ReachabilityState.RESPONDED,
        frozenset({DiscoverySource.GATEWAY, DiscoverySource.ICMP_RESPONSE}),
    )
    ipv6 = DiscoveredHost(
        7,
        IPv6Address("2001:db8::20"),
        None,
        ReachabilityState.NOT_PROBED,
        frozenset({DiscoverySource.NEIGHBOR_CACHE}),
    )
    plan = DiscoveryPlan(
        7,
        IPv4Network("192.0.2.0/24"),
        (IPv4Address("192.0.2.10"),),
        (IPv4Address("192.0.2.1"),),
        254,
        (IPv4Address("192.0.2.1"), IPv4Address("192.0.2.20")),
        750,
        32,
    )
    return DeviceInventory(plan, (gateway, local, ipv6), 2)


def hostname_batch(inventory: DeviceInventory) -> HostnameResolutionBatch:
    return HostnameResolutionBatch(
        tuple(
            HostnameResolution(
                host.address,
                HostnameResolutionState.RESOLVED,
                f"host-{position}.example",
                EnrichmentSource.PTR,
            )
            for position, host in enumerate(inventory.hosts, start=1)
        )
    )


def vendor_batch(inventory: DeviceInventory) -> VendorResolutionBatch:
    return VendorResolutionBatch(
        tuple(
            VendorResolution(
                host.interface_index,
                host.address,
                VendorResolutionState.RESOLVED
                if host.mac_address is not None
                else VendorResolutionState.NOT_APPLICABLE,
                "Example Networks" if host.mac_address is not None else None,
                EnrichmentSource.LOCAL_OUI_REGISTRY if host.mac_address is not None else None,
            )
            for host in inventory.hosts
        )
    )


def test_enrichment_only_receives_observed_hosts() -> None:
    inventory = make_inventory()
    hostnames = FakeHostnames(hostname_batch(inventory))
    vendors = FakeVendors(vendor_batch(inventory))

    EnrichDeviceInventory(hostnames, vendors).execute(inventory)

    assert hostnames.addresses == tuple(host.address for host in inventory.hosts)
    assert IPv4Address("192.0.2.20") not in hostnames.addresses
    assert vendors.hosts == inventory.hosts


def test_enrichment_preserves_every_discovery_field() -> None:
    inventory = make_inventory()

    enriched = EnrichDeviceInventory(
        FakeHostnames(hostname_batch(inventory)),
        FakeVendors(vendor_batch(inventory)),
    ).execute(inventory)

    assert enriched.discovered is inventory
    assert tuple(host.discovered for host in enriched.hosts) == inventory.hosts


def test_simultaneous_hostname_and_vendor_success_preserves_provenance() -> None:
    inventory = make_inventory()

    enriched = EnrichDeviceInventory(
        FakeHostnames(hostname_batch(inventory)),
        FakeVendors(vendor_batch(inventory)),
    ).execute(inventory)

    assert all(host.hostname.source is EnrichmentSource.PTR for host in enriched.hosts)
    assert all(
        host.vendor.source is EnrichmentSource.LOCAL_OUI_REGISTRY
        for host in enriched.hosts
        if host.discovered.mac_address is not None
    )


def test_missing_ptr_and_unknown_vendor_are_not_partial() -> None:
    inventory = make_inventory()
    hostnames = HostnameResolutionBatch(
        tuple(
            HostnameResolution(host.address, HostnameResolutionState.NOT_FOUND)
            for host in inventory.hosts
        )
    )
    vendors = VendorResolutionBatch(
        tuple(
            VendorResolution(
                host.interface_index,
                host.address,
                VendorResolutionState.UNKNOWN,
            )
            for host in inventory.hosts
        )
    )

    enriched = EnrichDeviceInventory(FakeHostnames(hostnames), FakeVendors(vendors)).execute(
        inventory
    )

    assert not enriched.is_partial
    assert enriched.hosts == tuple(enriched.hosts)


def test_systemic_failures_become_global_issues_without_removing_hosts() -> None:
    inventory = make_inventory()
    hostnames = HostnameResolutionBatch((), "Resolver unavailable")
    vendors = VendorResolutionBatch((), "Registry malformed")

    enriched = EnrichDeviceInventory(FakeHostnames(hostnames), FakeVendors(vendors)).execute(
        inventory
    )

    assert enriched.is_partial
    assert len(enriched.issues) == 2
    assert len(enriched.hosts) == len(inventory.hosts)
    assert all(
        host.hostname.state is HostnameResolutionState.NOT_ATTEMPTED for host in enriched.hosts
    )


def test_empty_inventory_does_not_create_hosts() -> None:
    inventory = make_inventory()
    empty = DeviceInventory(inventory.plan, (), 0)

    enriched = EnrichDeviceInventory(
        FakeHostnames(HostnameResolutionBatch(())),
        FakeVendors(VendorResolutionBatch(())),
    ).execute(empty)

    assert enriched.hosts == ()


def test_result_order_matches_deterministic_discovery_order() -> None:
    inventory = make_inventory()

    enriched = EnrichDeviceInventory(
        FakeHostnames(hostname_batch(inventory)),
        FakeVendors(vendor_batch(inventory)),
    ).execute(inventory)

    assert tuple(host.discovered for host in enriched.hosts) == inventory.hosts
