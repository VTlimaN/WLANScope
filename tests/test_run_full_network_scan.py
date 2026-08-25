from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from threading import Event

from wlanscope.application.run_full_network_scan import RunFullNetworkScan
from wlanscope.domain.discovery import (
    DeviceInventory,
    DiscoveryPlan,
    NoUsableSubnetError,
)
from wlanscope.domain.enrichment import EnrichedDeviceInventory, EnrichmentIssue
from wlanscope.domain.full_scan import FullScanStatus, ScanSection, ScanSectionStatus
from wlanscope.domain.interfaces import (
    InterfaceCollectionError,
    InterfaceInventory,
    NetworkInterface,
)
from wlanscope.domain.nearby_wifi import NearbyWifiSnapshot, WifiScanIssue, WifiScanIssueCode
from wlanscope.domain.network import CurrentNetworkSnapshot, NetworkCollectionError
from wlanscope.domain.wifi import (
    CurrentWifiSnapshot,
    WifiCollectionError,
    WifiIssue,
    WifiIssueCode,
)


class FakeInterfaces:
    def __init__(self, result: InterfaceInventory | Exception, order: list[str]) -> None:
        self.result = result
        self.order = order
        self.calls = 0

    def execute(self) -> InterfaceInventory:
        self.calls += 1
        self.order.append("adapters")
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FakeWifi:
    def __init__(self, result: CurrentWifiSnapshot | Exception, order: list[str]) -> None:
        self.result = result
        self.order = order
        self.calls = 0
        self.received_interfaces: tuple[NetworkInterface, ...] | None = None

    def execute(
        self,
        network_interfaces: Sequence[NetworkInterface] | None = None,
    ) -> CurrentWifiSnapshot:
        self.calls += 1
        self.order.append("current_wifi")
        self.received_interfaces = tuple(network_interfaces or ())
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FakeNetwork:
    def __init__(self, result: CurrentNetworkSnapshot | Exception, order: list[str]) -> None:
        self.result = result
        self.order = order
        self.calls = 0
        self.received_interfaces: tuple[NetworkInterface, ...] | None = None
        self.received_wifi: CurrentWifiSnapshot | None = None

    def execute_with_associations(
        self,
        interfaces: Sequence[NetworkInterface],
        wifi: CurrentWifiSnapshot | None,
    ) -> CurrentNetworkSnapshot:
        self.calls += 1
        self.order.append("current_network")
        self.received_interfaces = tuple(interfaces)
        self.received_wifi = wifi
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FakeNearby:
    def __init__(self, result: NearbyWifiSnapshot | Exception, order: list[str]) -> None:
        self.result = result
        self.order = order
        self.calls = 0

    def execute(self) -> NearbyWifiSnapshot:
        self.calls += 1
        self.order.append("nearby_wifi")
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FakeDevices:
    def __init__(self, result: DeviceInventory | Exception, order: list[str]) -> None:
        self.result = result
        self.order = order
        self.calls = 0
        self.allow_large_range: bool | None = None
        self.received_network: CurrentNetworkSnapshot | None = None

    def execute(
        self,
        allow_large_range: bool = False,
        cancel_event: Event | None = None,
        network_snapshot: CurrentNetworkSnapshot | None = None,
    ) -> DeviceInventory:
        self.calls += 1
        self.order.append("devices")
        self.allow_large_range = allow_large_range
        self.received_network = network_snapshot
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FakeEnrichment:
    def __init__(self, result: EnrichedDeviceInventory, order: list[str]) -> None:
        self.result = result
        self.order = order
        self.calls = 0
        self.received_inventory: DeviceInventory | None = None

    def execute(
        self,
        inventory: DeviceInventory,
        cancel_event: Event | None = None,
    ) -> EnrichedDeviceInventory:
        self.calls += 1
        self.order.append("enrichment")
        self.received_inventory = inventory
        return self.result


def device_inventory() -> DeviceInventory:
    address = IPv4Address("192.0.2.10")
    plan = DiscoveryPlan(
        7,
        IPv4Network("192.0.2.10/32"),
        (address,),
        (),
        1,
        (),
        750,
        32,
    )
    return DeviceInventory(plan, (), 0)


def use_case(
    interfaces: InterfaceInventory | Exception | None = None,
    wifi: CurrentWifiSnapshot | Exception | None = None,
    network: CurrentNetworkSnapshot | Exception | None = None,
    nearby: NearbyWifiSnapshot | Exception | None = None,
    devices: DeviceInventory | Exception | None = None,
    enriched: EnrichedDeviceInventory | None = None,
) -> tuple[
    RunFullNetworkScan,
    FakeInterfaces,
    FakeWifi,
    FakeNetwork,
    FakeNearby,
    FakeDevices,
    FakeEnrichment,
    list[str],
]:
    order: list[str] = []
    discovered = device_inventory()
    device_result = devices if devices is not None else discovered
    enriched_result = enriched or EnrichedDeviceInventory(discovered, ())
    interface_fake = FakeInterfaces(interfaces or InterfaceInventory(()), order)
    wifi_fake = FakeWifi(wifi or CurrentWifiSnapshot(()), order)
    network_fake = FakeNetwork(network or CurrentNetworkSnapshot((), ()), order)
    nearby_fake = FakeNearby(nearby or NearbyWifiSnapshot((), ()), order)
    devices_fake = FakeDevices(device_result, order)
    enrichment_fake = FakeEnrichment(enriched_result, order)
    started = datetime(2026, 1, 1, tzinfo=UTC)
    times = iter((started, started + timedelta(seconds=2)))
    runner = RunFullNetworkScan(
        interface_fake,
        wifi_fake,
        network_fake,
        nearby_fake,
        devices_fake,
        enrichment_fake,
        clock=lambda: next(times),
    )
    return (
        runner,
        interface_fake,
        wifi_fake,
        network_fake,
        nearby_fake,
        devices_fake,
        enrichment_fake,
        order,
    )


def test_full_success_executes_each_stage_once_in_order() -> None:
    runner, interfaces, wifi, network, nearby, devices, enrichment, order = use_case()

    snapshot = runner.execute()

    assert snapshot.status is FullScanStatus.SUCCESS
    assert order == [
        "adapters",
        "current_wifi",
        "current_network",
        "nearby_wifi",
        "devices",
        "enrichment",
    ]
    assert all(fake.calls == 1 for fake in (interfaces, wifi, network, nearby, devices, enrichment))


def test_results_are_reused_by_dependent_stages() -> None:
    interface_result = InterfaceInventory(())
    wifi_result = CurrentWifiSnapshot(())
    network_result = CurrentNetworkSnapshot((), ())
    discovered = device_inventory()
    runner, _, wifi, network, _, devices, enrichment, _ = use_case(
        interface_result,
        wifi_result,
        network_result,
        devices=discovered,
        enriched=EnrichedDeviceInventory(discovered, ()),
    )

    runner.execute(allow_large_range=True)

    assert wifi.received_interfaces is interface_result.interfaces
    assert network.received_interfaces == interface_result.interfaces
    assert network.received_wifi is wifi_result
    assert devices.received_network is network_result
    assert devices.allow_large_range is True
    assert enrichment.received_inventory is discovered


def test_current_wifi_partial_makes_global_partial() -> None:
    wifi = CurrentWifiSnapshot(
        (),
        (WifiIssue(WifiIssueCode.INTERFACE_ASSOCIATION_FAILED, "Association unavailable"),),
    )
    runner, *_ = use_case(wifi=wifi)

    snapshot = runner.execute()

    assert snapshot.status is FullScanStatus.PARTIAL
    assert snapshot.section(ScanSection.CURRENT_WIFI).status is ScanSectionStatus.PARTIAL


def test_nearby_privacy_failure_does_not_abort_devices() -> None:
    nearby = NearbyWifiSnapshot(
        (),
        (),
        (WifiScanIssue(WifiScanIssueCode.ACCESS_DENIED, "Location access denied"),),
    )
    runner, *_, devices, enrichment, order = use_case(nearby=nearby)

    snapshot = runner.execute()

    assert snapshot.status is FullScanStatus.PARTIAL
    assert snapshot.section(ScanSection.NEARBY_WIFI).status is ScanSectionStatus.FAILED
    assert devices.calls == 1
    assert enrichment.calls == 1
    assert order[-2:] == ["devices", "enrichment"]


def test_current_network_failure_skips_devices_and_continues_nearby() -> None:
    runner, *_, nearby, devices, enrichment, _ = use_case(
        network=NetworkCollectionError("IP Helper unavailable")
    )

    snapshot = runner.execute()

    assert nearby.calls == 1
    assert devices.calls == 0
    assert enrichment.calls == 0
    assert snapshot.section(ScanSection.CURRENT_NETWORK).status is ScanSectionStatus.FAILED
    assert snapshot.section(ScanSection.DEVICES).status is ScanSectionStatus.SKIPPED


def test_no_usable_subnet_skips_devices_without_enrichment() -> None:
    runner, *_, devices, enrichment, _ = use_case(
        devices=NoUsableSubnetError("No usable local subnet")
    )

    snapshot = runner.execute()

    assert devices.calls == 1
    assert enrichment.calls == 0
    assert snapshot.section(ScanSection.DEVICES).status is ScanSectionStatus.SKIPPED


def test_enrichment_systemic_issue_makes_devices_partial() -> None:
    discovered = device_inventory()
    enriched = EnrichedDeviceInventory(
        discovered,
        (),
        (EnrichmentIssue("DNS PTR", "Resolver unavailable"),),
    )
    runner, *_ = use_case(devices=discovered, enriched=enriched)

    snapshot = runner.execute()

    assert snapshot.section(ScanSection.DEVICES).status is ScanSectionStatus.PARTIAL
    assert snapshot.status is FullScanStatus.PARTIAL


def test_normal_unknown_enrichment_does_not_degrade_status() -> None:
    runner, *_ = use_case()

    snapshot = runner.execute()

    assert snapshot.section(ScanSection.DEVICES).status is ScanSectionStatus.SUCCESS


def test_independent_operational_failures_produce_failed_global_status() -> None:
    runner, *_ = use_case(
        interfaces=InterfaceCollectionError("Adapters unavailable"),
        wifi=WifiCollectionError("Wi-Fi unavailable"),
        network=NetworkCollectionError("Network unavailable"),
        nearby=WifiCollectionError("Scan unavailable"),
    )

    snapshot = runner.execute()

    assert snapshot.status is FullScanStatus.FAILED


def test_section_issues_are_associated_and_deduplicated() -> None:
    wifi = CurrentWifiSnapshot(
        (),
        (
            WifiIssue(WifiIssueCode.INTERFACE_ASSOCIATION_FAILED, "Limited"),
            WifiIssue(WifiIssueCode.INTERFACE_ASSOCIATION_FAILED, "Limited"),
        ),
    )
    runner, *_ = use_case(wifi=wifi)

    snapshot = runner.execute()

    assert tuple(issue.message for issue in snapshot.issues).count("Limited") == 1
    assert snapshot.issues[0].section is ScanSection.CURRENT_WIFI
