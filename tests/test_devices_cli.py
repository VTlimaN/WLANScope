from collections.abc import Sequence
from io import StringIO
from ipaddress import IPv4Address, IPv4Network, ip_address
from threading import Event
from typing import cast

import pytest
from pytest import CaptureFixture
from rich.console import Console

from wlanscope.application.discover_local_devices import DiscoverLocalDevices
from wlanscope.application.enrich_device_inventory import EnrichDeviceInventory
from wlanscope.cli import main
from wlanscope.domain.discovery import (
    DeviceInventory,
    DiscoveredHost,
    DiscoveryIssue,
    DiscoveryPlan,
    DiscoverySource,
    HostAddress,
    NeighborState,
    RangeAuthorizationRequiredError,
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


class FakeDevices:
    def __init__(self, result: DeviceInventory | Exception) -> None:
        self.result = result
        self.allow_large_range: bool | None = None

    def execute(self, allow_large_range: bool, cancellation: object) -> DeviceInventory:
        self.allow_large_range = allow_large_range
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class InterruptedDevices:
    def execute(self, allow_large_range: bool, cancellation: object) -> DeviceInventory:
        raise KeyboardInterrupt


class MissingHostnames:
    def resolve_many(
        self,
        addresses: Sequence[HostAddress],
        cancel_event: Event,
    ) -> HostnameResolutionBatch:
        return HostnameResolutionBatch(
            tuple(
                HostnameResolution(address, HostnameResolutionState.NOT_FOUND)
                for address in addresses
            )
        )


class UnavailableVendors:
    def resolve_many(self, hosts: Sequence[DiscoveredHost]) -> VendorResolutionBatch:
        return VendorResolutionBatch(
            tuple(
                VendorResolution(
                    host.interface_index,
                    host.address,
                    VendorResolutionState.REGISTRY_UNAVAILABLE
                    if host.mac_address is not None
                    else VendorResolutionState.NOT_APPLICABLE,
                )
                for host in hosts
            )
        )


class ResolvedHostnames:
    def resolve_many(
        self,
        addresses: Sequence[HostAddress],
        cancel_event: Event,
    ) -> HostnameResolutionBatch:
        return HostnameResolutionBatch(
            tuple(
                HostnameResolution(
                    address,
                    HostnameResolutionState.RESOLVED,
                    "[bold]host.example[/bold]" if position == 1 else "host.example",
                    EnrichmentSource.PTR,
                )
                for position, address in enumerate(addresses, start=1)
            )
        )


class ResolvedVendors:
    def resolve_many(self, hosts: Sequence[DiscoveredHost]) -> VendorResolutionBatch:
        return VendorResolutionBatch(
            tuple(
                VendorResolution(
                    host.interface_index,
                    host.address,
                    VendorResolutionState.RESOLVED
                    if host.mac_address is not None
                    else VendorResolutionState.NOT_APPLICABLE,
                    "[cyan]Example Networks[/cyan]" if host.mac_address is not None else None,
                    EnrichmentSource.LOCAL_OUI_REGISTRY if host.mac_address is not None else None,
                )
                for host in hosts
            )
        )


def make_inventory(
    issues: tuple[DiscoveryIssue, ...] = (),
    usable_host_count: int = 254,
) -> DeviceInventory:
    plan = DiscoveryPlan(
        7,
        IPv4Network("192.0.2.0/24"),
        (IPv4Address("192.0.2.10"),),
        (IPv4Address("192.0.2.1"),),
        usable_host_count,
        (IPv4Address("192.0.2.1"), IPv4Address("192.0.2.20")),
        750,
        32,
    )
    hosts = (
        DiscoveredHost(
            7,
            ip_address("192.0.2.1"),
            MacAddress.from_text("02:00:00:00:00:01"),
            ReachabilityState.RESPONDED,
            frozenset(
                {
                    DiscoverySource.GATEWAY,
                    DiscoverySource.NEIGHBOR_CACHE,
                    DiscoverySource.ICMP_RESPONSE,
                }
            ),
            NeighborState(5),
        ),
        DiscoveredHost(
            7,
            ip_address("192.0.2.10"),
            None,
            ReachabilityState.NOT_PROBED,
            frozenset({DiscoverySource.SELF}),
        ),
        DiscoveredHost(
            7,
            ip_address("2001:db8::20"),
            None,
            ReachabilityState.NOT_PROBED,
            frozenset({DiscoverySource.NEIGHBOR_CACHE}),
            NeighborState(4),
        ),
    )
    return DeviceInventory(plan, hosts, 2, issues)


def run_devices(
    fake: FakeDevices | InterruptedDevices,
    arguments: list[str],
    enrichment: EnrichDeviceInventory | None = None,
    width: int = 100,
) -> tuple[int, str]:
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=width)
    exit_code = main(
        arguments,
        devices_use_case=cast(DiscoverLocalDevices, fake),
        device_enrichment_use_case=enrichment
        or EnrichDeviceInventory(MissingHostnames(), UnavailableVendors()),
        console=console,
    )
    return exit_code, output.getvalue()


def test_devices_success_uses_observed_host_semantics() -> None:
    exit_code, output = run_devices(FakeDevices(make_inventory()), ["devices"])

    assert exit_code == 0
    assert "Local Network Discovery" in output
    assert "Observed hosts: 3" in output
    assert "Devices connected" not in output
    assert "Responded" in output
    assert "Neighbor" in output


def test_devices_partial_result_returns_three_and_prints_warning() -> None:
    inventory = make_inventory((DiscoveryIssue("ICMP", "Unavailable"),))

    exit_code, output = run_devices(FakeDevices(inventory), ["devices"])

    assert exit_code == 3
    assert "Warning (ICMP)" in output


def test_devices_large_range_flag_is_forwarded() -> None:
    fake = FakeDevices(make_inventory())

    exit_code, _ = run_devices(fake, ["devices", "--allow-large-range"])

    assert exit_code == 0
    assert fake.allow_large_range is True


def test_devices_large_range_requires_explicit_authorization() -> None:
    error = RangeAuthorizationRequiredError(510)

    exit_code, output = run_devices(FakeDevices(error), ["devices"])

    assert exit_code == 2
    assert "explicit large-range authorization" in output
    assert "required" in output
    assert "Traceback" not in output


def test_devices_cancellation_has_no_traceback() -> None:
    exit_code, output = run_devices(InterruptedDevices(), ["devices"])

    assert exit_code == 130
    assert "canceled" in output
    assert "Traceback" not in output


def test_devices_external_values_render_literally() -> None:
    inventory = make_inventory((DiscoveryIssue("[stage]", "[bold]literal[/bold]"),))

    _, output = run_devices(FakeDevices(inventory), ["devices"])

    assert "[stage]" in output
    assert "[bold]literal[/bold]" in output


def test_devices_help_exposes_local_range_authorization(
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as result:
        main(["devices", "--help"])

    assert result.value.code == 0
    assert "--allow-large-range" in capsys.readouterr().out


def test_devices_displays_resolved_hostname_and_vendor_literally() -> None:
    enrichment = EnrichDeviceInventory(ResolvedHostnames(), ResolvedVendors())

    exit_code, output = run_devices(
        FakeDevices(make_inventory()), ["devices"], enrichment, width=140
    )

    assert exit_code == 0
    assert "[bold]host.example[/bold]" in output
    assert "[cyan]Example Networks[/cyan]" in output
    assert "PTR resolved: 3/3" in output
    assert "Vendors resolved: 1/1" in output
    assert "Locally administered MACs: 0" in output


def test_devices_unknown_enrichment_is_normal_success() -> None:
    exit_code, output = run_devices(FakeDevices(make_inventory()), ["devices"])

    assert exit_code == 0
    assert "Not found" in output
    assert "Registry unavailable" in output


def test_devices_systemic_enrichment_issue_returns_partial() -> None:
    class FailedHostnames(MissingHostnames):
        def resolve_many(
            self,
            addresses: Sequence[HostAddress],
            cancel_event: Event,
        ) -> HostnameResolutionBatch:
            return HostnameResolutionBatch((), "Resolver unavailable")

    enrichment = EnrichDeviceInventory(FailedHostnames(), UnavailableVendors())

    exit_code, output = run_devices(FakeDevices(make_inventory()), ["devices"], enrichment)

    assert exit_code == 3
    assert "Warning (DNS PTR): Resolver unavailable" in output
    assert "Traceback" not in output


def test_devices_compact_width_omits_wide_columns() -> None:
    exit_code, output = run_devices(FakeDevices(make_inventory()), ["devices"], width=80)

    header = next(line for line in output.splitlines() if "Hostname" in line)
    assert exit_code == 0
    assert "MAC" not in header
    assert "Sources" not in header
    assert len(max(output.splitlines(), key=len)) <= 80
