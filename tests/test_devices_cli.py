from io import StringIO
from ipaddress import IPv4Address, IPv4Network, ip_address
from typing import cast

import pytest
from pytest import CaptureFixture
from rich.console import Console

from wlanscope.application.discover_local_devices import DiscoverLocalDevices
from wlanscope.cli import main
from wlanscope.domain.discovery import (
    DeviceInventory,
    DiscoveredHost,
    DiscoveryIssue,
    DiscoveryPlan,
    DiscoverySource,
    NeighborState,
    RangeAuthorizationRequiredError,
    ReachabilityState,
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


def run_devices(fake: FakeDevices | InterruptedDevices, arguments: list[str]) -> tuple[int, str]:
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=100)
    exit_code = main(
        arguments,
        devices_use_case=cast(DiscoverLocalDevices, fake),
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
