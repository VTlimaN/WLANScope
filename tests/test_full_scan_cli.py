from datetime import UTC, datetime, timedelta
from io import StringIO
from threading import Event
from typing import cast

import pytest
from pytest import CaptureFixture
from rich.console import Console

from wlanscope.application.run_full_network_scan import RunFullNetworkScan
from wlanscope.cli import main
from wlanscope.domain.full_scan import (
    FullNetworkSnapshot,
    FullScanIssue,
    ScanSection,
    ScanSectionResult,
    ScanSectionStatus,
)
from wlanscope.domain.interfaces import InterfaceInventory
from wlanscope.domain.nearby_wifi import NearbyWifiSnapshot
from wlanscope.domain.network import CurrentNetworkSnapshot
from wlanscope.domain.wifi import CurrentWifiSnapshot


class FakeFullScan:
    def __init__(self, result: FullNetworkSnapshot) -> None:
        self.result = result
        self.allow_large_range: bool | None = None
        self.calls = 0

    def execute(
        self,
        allow_large_range: bool = False,
        cancel_event: Event | None = None,
    ) -> FullNetworkSnapshot:
        self.calls += 1
        self.allow_large_range = allow_large_range
        return self.result


class InterruptedFullScan:
    def execute(
        self,
        allow_large_range: bool = False,
        cancel_event: Event | None = None,
    ) -> FullNetworkSnapshot:
        raise KeyboardInterrupt


def full_snapshot(
    statuses: dict[ScanSection, ScanSectionStatus] | None = None,
    issue_message: str | None = None,
) -> FullNetworkSnapshot:
    selected = statuses or {}
    results = tuple(
        ScanSectionResult(
            section,
            selected.get(section, ScanSectionStatus.SUCCESS),
            (FullScanIssue(section, issue_message),)
            if issue_message is not None and section is ScanSection.NEARBY_WIFI
            else (),
        )
        for section in ScanSection
    )
    started = datetime(2026, 1, 1, tzinfo=UTC)
    return FullNetworkSnapshot(
        started,
        started + timedelta(seconds=2),
        results,
        InterfaceInventory(()),
        CurrentWifiSnapshot(()),
        CurrentNetworkSnapshot((), ()),
        NearbyWifiSnapshot((), ()),
    )


def run_scan(
    fake: FakeFullScan | InterruptedFullScan,
    arguments: list[str] | None = None,
    width: int = 100,
) -> tuple[int, str]:
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=width)
    exit_code = main(
        arguments or ["scan"],
        full_scan_use_case=cast(RunFullNetworkScan, fake),
        console=console,
    )
    return exit_code, output.getvalue()


def test_scan_success_returns_zero_and_renders_summary() -> None:
    exit_code, output = run_scan(FakeFullScan(full_snapshot()))

    assert exit_code == 0
    assert "Full Network Scan" in output
    assert "Success" in output
    assert "Current Wi-Fi connected" in output
    assert "Nearby Wi-Fi networks" in output
    assert "Observed hosts" in output
    assert "PTR resolved" in output
    assert "Vendors resolved" in output


def test_scan_partial_returns_three_and_section_issue() -> None:
    statuses = {ScanSection.NEARBY_WIFI: ScanSectionStatus.FAILED}
    fake = FakeFullScan(full_snapshot(statuses, "[bold]Location denied[/bold]"))

    exit_code, output = run_scan(fake)

    assert exit_code == 3
    assert "Partial" in output
    assert "[bold]Location denied[/bold]" in output
    assert "Nearby Wi-Fi" in output
    assert "Traceback" not in output


def test_scan_failure_returns_one() -> None:
    statuses = {
        section: ScanSectionStatus.SKIPPED
        if section is ScanSection.DEVICES
        else ScanSectionStatus.FAILED
        for section in ScanSection
    }

    exit_code, output = run_scan(FakeFullScan(full_snapshot(statuses)))

    assert exit_code == 1
    assert "Failed" in output


def test_devices_skipped_is_visible_without_claiming_connected_devices() -> None:
    statuses = {ScanSection.DEVICES: ScanSectionStatus.SKIPPED}

    exit_code, output = run_scan(FakeFullScan(full_snapshot(statuses)))

    assert exit_code == 3
    assert "Skipped" in output
    assert "Observed hosts" in output
    assert "devices connected" not in output.casefold()


def test_allow_large_range_is_forwarded() -> None:
    fake = FakeFullScan(full_snapshot())

    exit_code, _ = run_scan(fake, ["scan", "--allow-large-range"])

    assert exit_code == 0
    assert fake.allow_large_range is True


def test_non_tty_output_is_deterministic_and_does_not_prompt() -> None:
    fake = FakeFullScan(full_snapshot())

    first = run_scan(fake)[1]
    second = run_scan(fake)[1]

    assert first == second
    assert "Select" not in first
    assert "Press" not in first


def test_narrow_terminal_output_remains_within_width() -> None:
    _, output = run_scan(FakeFullScan(full_snapshot()), width=80)

    assert len(max(output.splitlines(), key=len)) <= 80


def test_cancellation_returns_130_without_traceback() -> None:
    exit_code, output = run_scan(InterruptedFullScan())

    assert exit_code == 130
    assert "canceled" in output
    assert "Traceback" not in output


def test_scan_help_exposes_large_range_policy(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        main(["scan", "--help"])

    assert result.value.code == 0
    output = capsys.readouterr().out
    assert "--allow-large-range" in output
    assert "target" not in output.casefold()
    assert "output-file" not in output
