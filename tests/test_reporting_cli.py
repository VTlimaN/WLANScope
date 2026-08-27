import json
from io import StringIO
from pathlib import Path
from threading import Event
from typing import cast

import pytest
from pytest import CaptureFixture
from rich.console import Console

from tests.reporting_samples import sample_snapshot
from wlanscope.application.export_full_network_report import ExportFullNetworkReport
from wlanscope.application.run_full_network_scan import RunFullNetworkScan
from wlanscope.cli import main
from wlanscope.domain.full_scan import FullNetworkSnapshot, ScanSectionStatus
from wlanscope.reporting.writer import ReportWriteError


class FullScanSpy:
    def __init__(self, snapshot: FullNetworkSnapshot) -> None:
        self.snapshot = snapshot
        self.calls = 0

    def execute(
        self,
        allow_large_range: bool = False,
        cancel_event: Event | None = None,
    ) -> FullNetworkSnapshot:
        self.calls += 1
        return self.snapshot


class FailingExporter:
    def execute(
        self,
        snapshot: FullNetworkSnapshot,
        json_path: Path | None = None,
        markdown_path: Path | None = None,
        force: bool = False,
    ) -> tuple[()]:
        raise ReportWriteError("Access denied")


def run_reporting_cli(
    arguments: list[str],
    scan: FullScanSpy,
    exporter: ExportFullNetworkReport | FailingExporter | None = None,
) -> tuple[int, str]:
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=300)
    exit_code = main(
        arguments,
        full_scan_use_case=cast(RunFullNetworkScan, scan),
        report_export_use_case=cast(ExportFullNetworkReport, exporter or ExportFullNetworkReport()),
        console=console,
    )
    return exit_code, output.getvalue()


def test_scan_json_writes_valid_report(tmp_path: Path) -> None:
    target = tmp_path / "scan.json"
    scan = FullScanSpy(sample_snapshot())

    exit_code, output = run_reporting_cli(["scan", "--json", str(target)], scan)

    assert exit_code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["schema_version"] == "1.0"
    assert str(target) in output
    assert "Reports written" in output


def test_scan_markdown_writes_nonempty_report(tmp_path: Path) -> None:
    target = tmp_path / "scan.md"

    exit_code, _ = run_reporting_cli(
        ["scan", "--markdown", str(target)],
        FullScanSpy(sample_snapshot()),
    )

    assert exit_code == 0
    assert target.read_text(encoding="utf-8").startswith("# WLANScope Network Report")


def test_json_and_markdown_execute_full_scan_once(tmp_path: Path) -> None:
    json_path = tmp_path / "scan.json"
    markdown_path = tmp_path / "scan.md"
    scan = FullScanSpy(sample_snapshot())

    exit_code, _ = run_reporting_cli(
        ["scan", "--json", str(json_path), "--markdown", str(markdown_path)],
        scan,
    )

    assert exit_code == 0
    assert scan.calls == 1
    assert json_path.exists()
    assert markdown_path.exists()
    assert "2026-01-02T03:04:05.000000Z" in json_path.read_text(encoding="utf-8")
    assert "2026-01-02T03:04:05.000000Z" in markdown_path.read_text(encoding="utf-8")


def test_anonymized_dual_format_uses_one_scan_and_shared_aliases(tmp_path: Path) -> None:
    json_path = tmp_path / "scan.json"
    markdown_path = tmp_path / "scan.md"
    scan = FullScanSpy(sample_snapshot())

    exit_code, _ = run_reporting_cli(
        [
            "scan",
            "--json",
            str(json_path),
            "--markdown",
            str(markdown_path),
            "--anonymize",
        ],
        scan,
    )

    json_text = json_path.read_text(encoding="utf-8")
    markdown_text = markdown_path.read_text(encoding="utf-8")
    assert exit_code == 0
    assert scan.calls == 1
    assert '"anonymized": true' in json_text
    assert "IPV4-001" in json_text and "IPV4-001" in markdown_text


def test_partial_scan_exports_reports_and_preserves_exit_three(tmp_path: Path) -> None:
    target = tmp_path / "partial.json"
    scan = FullScanSpy(sample_snapshot(ScanSectionStatus.PARTIAL))

    exit_code, _ = run_reporting_cli(["scan", "--json", str(target)], scan)

    assert exit_code == 3
    assert json.loads(target.read_text(encoding="utf-8"))["scan"]["status"] == "partial"


def test_failed_snapshot_is_exported(tmp_path: Path) -> None:
    target = tmp_path / "failed.json"
    scan = FullScanSpy(sample_snapshot(ScanSectionStatus.FAILED))

    exit_code, _ = run_reporting_cli(["scan", "--json", str(target)], scan)

    assert exit_code == 1
    assert json.loads(target.read_text(encoding="utf-8"))["scan"]["status"] == "failed"


def test_report_failure_overrides_successful_scan_without_traceback(tmp_path: Path) -> None:
    target = tmp_path / "scan.json"

    exit_code, output = run_reporting_cli(
        ["scan", "--json", str(target)],
        FullScanSpy(sample_snapshot()),
        FailingExporter(),
    )

    assert exit_code == 1
    assert "Report error" in output
    assert "Access denied" in output
    assert "Traceback" not in output


def test_existing_report_requires_force(tmp_path: Path) -> None:
    target = tmp_path / "scan.json"
    target.write_text("original", encoding="utf-8")

    first_code, _ = run_reporting_cli(
        ["scan", "--json", str(target)],
        FullScanSpy(sample_snapshot()),
    )
    force_code, _ = run_reporting_cli(
        ["scan", "--json", str(target), "--force"],
        FullScanSpy(sample_snapshot()),
    )

    assert first_code == 1
    assert force_code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["schema_version"] == "1.0"


def test_conflicting_paths_are_usage_error_before_scan(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    target = tmp_path / "same.out"
    scan = FullScanSpy(sample_snapshot())

    with pytest.raises(SystemExit) as result:
        main(
            ["scan", "--json", str(target), "--markdown", str(target)],
            full_scan_use_case=cast(RunFullNetworkScan, scan),
        )

    assert result.value.code == 2
    assert scan.calls == 0
    assert "different paths" in capsys.readouterr().err


def test_missing_parent_is_operational_failure(tmp_path: Path) -> None:
    target = tmp_path / "missing" / "scan.md"

    exit_code, output = run_reporting_cli(
        ["scan", "--markdown", str(target)],
        FullScanSpy(sample_snapshot()),
    )

    assert exit_code == 1
    assert "parent directory" in output
    assert "Traceback" not in output


def test_literal_report_path_is_not_interpreted_as_rich_markup(tmp_path: Path) -> None:
    target = tmp_path / "[bold]scan.json"

    exit_code, output = run_reporting_cli(
        ["scan", "--json", str(target)],
        FullScanSpy(sample_snapshot()),
    )

    assert exit_code == 0
    assert "[bold]scan.json" in output


def test_force_without_report_is_usage_error() -> None:
    with pytest.raises(SystemExit) as result:
        main(["scan", "--force"])

    assert result.value.code == 2
