from dataclasses import replace
from io import StringIO
from typing import cast

import pytest
from pytest import CaptureFixture
from rich.console import Console

from tests.reporting_samples import sample_snapshot
from tests.test_cli import (
    FailingInterfaceCollector,
    StaticInterfaceCollector,
    StaticWifiCollector,
    _interface,
    _wifi_interface,
)
from tests.test_devices_cli import FakeDevices, make_inventory
from tests.test_full_scan_cli import FakeFullScan
from tests.test_nearby_wifi_cli import StaticCollector, _data
from tests.test_reporting_cli import FailingExporter
from wlanscope.application.discover_local_devices import DiscoverLocalDevices
from wlanscope.application.enrich_device_inventory import EnrichDeviceInventory
from wlanscope.application.export_full_network_report import ExportFullNetworkReport
from wlanscope.application.inspect_current_wifi import InspectCurrentWifi
from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.application.run_full_network_scan import RunFullNetworkScan
from wlanscope.application.scan_nearby_wifi import ScanNearbyWifi
from wlanscope.cli import main
from wlanscope.domain.wifi import CurrentWifiSnapshot, WifiIssue, WifiIssueCode


def _console(stream: StringIO, width: int = 100) -> Console:
    return Console(file=stream, force_terminal=False, color_system=None, width=width)


@pytest.mark.parametrize(
    ("arguments", "description"),
    [
        (["adapters", "--help"], "network interfaces"),
        (["wifi", "--help"], "current Wi-Fi"),
        (["wifi", "scan", "--help"], "nearby Wi-Fi"),
        (["current", "--help"], "routing"),
        (["devices", "--help"], "ICMP Echo"),
        (["scan", "--help"], "full network"),
    ],
)
def test_command_help_is_specific(
    arguments: list[str],
    description: str,
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as result:
        main(arguments)

    captured = capsys.readouterr()
    assert result.value.code == 0
    assert description.casefold() in captured.out.casefold()
    assert captured.err == ""


def test_root_help_explains_read_only_scope(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        main(["--help"])

    output = capsys.readouterr().out
    assert result.value.code == 0
    assert "Read-only" in output
    assert "COMMAND --help" in output
    assert "bounded ICMP Echo" in output


def test_usage_error_uses_stderr(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        main(["wifi", "scan", "--access-point", "1"])

    captured = capsys.readouterr()
    assert result.value.code == 2
    assert captured.out == ""
    assert "requires --details" in captured.err


def test_operational_failure_uses_stderr() -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = main(
        ["adapters"],
        interface_use_case=ListNetworkInterfaces(FailingInterfaceCollector()),
        console=_console(stdout),
        error_console=_console(stderr),
    )

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert "Network interfaces unavailable" in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()


def test_partial_result_separates_results_and_warning() -> None:
    stdout = StringIO()
    stderr = StringIO()
    issue = WifiIssue(WifiIssueCode.ACCESS_DENIED, "Windows location access is restricted.")
    snapshot = CurrentWifiSnapshot((_wifi_interface(1),), (issue,))

    exit_code = main(
        ["wifi"],
        wifi_use_case=InspectCurrentWifi(StaticWifiCollector(snapshot)),
        console=_console(stdout),
        error_console=_console(stderr),
    )

    assert exit_code == 3
    assert "Current Wi-Fi" in stdout.getvalue()
    assert "location access is restricted" not in stdout.getvalue()
    assert "location access is restricted" in stderr.getvalue()


def test_wifi_scan_cancellation_returns_130_on_stderr() -> None:
    class InterruptedScan:
        def execute(self) -> object:
            raise KeyboardInterrupt

    stdout = StringIO()
    stderr = StringIO()
    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=cast(ScanNearbyWifi, InterruptedScan()),
        console=_console(stdout),
        error_console=_console(stderr),
    )

    assert exit_code == 130
    assert stdout.getvalue() == ""
    assert "canceled" in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()


def test_canceled_device_inventory_skips_enrichment() -> None:
    class UnexpectedEnrichment:
        def execute(self, inventory: object, cancellation: object) -> object:
            raise AssertionError("Enrichment must not run after cancellation")

    stdout = StringIO()
    stderr = StringIO()
    canceled = replace(make_inventory(), canceled=True)
    exit_code = main(
        ["devices"],
        devices_use_case=cast(DiscoverLocalDevices, FakeDevices(canceled)),
        device_enrichment_use_case=cast(EnrichDeviceInventory, UnexpectedEnrichment()),
        console=_console(stdout),
        error_console=_console(stderr),
    )

    assert exit_code == 130
    assert stdout.getvalue() == ""
    assert "canceled" in stderr.getvalue()


def test_report_failure_uses_stderr() -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = main(
        ["scan", "--json", "report.json"],
        full_scan_use_case=cast(RunFullNetworkScan, FakeFullScan(sample_snapshot())),
        report_export_use_case=cast(ExportFullNetworkReport, FailingExporter()),
        console=_console(stdout),
        error_console=_console(stderr),
    )

    assert exit_code == 1
    assert "Full Network Scan" in stdout.getvalue()
    assert "Report error" not in stdout.getvalue()
    assert "Report error" in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()


def test_adapters_compact_width_keeps_essential_columns() -> None:
    output = StringIO()

    exit_code = main(
        ["adapters"],
        interface_use_case=ListNetworkInterfaces(StaticInterfaceCollector((_interface(),))),
        console=_console(output, 80),
    )

    header = next(line for line in output.getvalue().splitlines() if "Index" in line)
    assert exit_code == 0
    assert "Name" in header
    assert "MAC" not in header
    assert "Link" not in header
    assert max(map(len, output.getvalue().splitlines())) <= 80


def test_nearby_wifi_compact_width_keeps_essential_columns() -> None:
    output = StringIO()

    exit_code = main(
        ["wifi", "scan"],
        nearby_wifi_use_case=ScanNearbyWifi(StaticCollector(_data())),
        console=_console(output, 80),
    )

    header = next(line for line in output.getvalue().splitlines() if "SSID" in line)
    assert exit_code == 0
    assert "Signal" in header
    assert "Security" not in header
    assert "Interface" not in header
    assert max(map(len, output.getvalue().splitlines())) <= 80


def test_non_tty_output_has_no_ansi_or_prompt() -> None:
    output = StringIO()

    exit_code = main(
        ["scan"],
        full_scan_use_case=cast(RunFullNetworkScan, FakeFullScan(sample_snapshot())),
        console=_console(output, 80),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "\x1b[" not in rendered
    assert "Select" not in rendered
    assert "Press" not in rendered
