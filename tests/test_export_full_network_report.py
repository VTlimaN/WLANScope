from pathlib import Path

import pytest

from tests.reporting_samples import sample_snapshot
from wlanscope.application.export_full_network_report import (
    ExportFullNetworkReport,
    ReportFormat,
    ReportPathError,
    paths_conflict,
)
from wlanscope.domain.full_scan import FullNetworkSnapshot
from wlanscope.reporting.writer import ReportWriteError


class SerializerSpy:
    def __init__(self, content: str) -> None:
        self.content = content
        self.snapshots: list[FullNetworkSnapshot] = []

    def __call__(self, snapshot: FullNetworkSnapshot) -> str:
        self.snapshots.append(snapshot)
        return self.content


class WriterSpy:
    def __init__(self, fail_path: Path | None = None) -> None:
        self.calls: list[tuple[Path, str, bool]] = []
        self.fail_path = fail_path

    def __call__(self, path: Path, content: str, force: bool) -> int:
        self.calls.append((path, content, force))
        if path == self.fail_path:
            raise ReportWriteError("Write failed")
        return len(content)


def test_json_only_uses_json_serializer_once() -> None:
    snapshot = sample_snapshot()
    json_serializer = SerializerSpy("json")
    markdown = SerializerSpy("markdown")
    writer = WriterSpy()
    exporter = ExportFullNetworkReport(json_serializer, markdown, writer)

    result = exporter.execute(snapshot, Path("scan.json"))

    assert json_serializer.snapshots == [snapshot]
    assert not markdown.snapshots
    assert result[0].format is ReportFormat.JSON
    assert writer.calls == [(Path("scan.json"), "json", False)]


def test_markdown_only_uses_markdown_renderer_once() -> None:
    snapshot = sample_snapshot()
    json_serializer = SerializerSpy("json")
    markdown = SerializerSpy("markdown")
    writer = WriterSpy()
    exporter = ExportFullNetworkReport(json_serializer, markdown, writer)

    result = exporter.execute(snapshot, markdown_path=Path("scan.md"), force=True)

    assert not json_serializer.snapshots
    assert markdown.snapshots == [snapshot]
    assert result[0].format is ReportFormat.MARKDOWN
    assert writer.calls == [(Path("scan.md"), "markdown", True)]


def test_both_formats_receive_the_exact_same_snapshot_once() -> None:
    snapshot = sample_snapshot()
    json_serializer = SerializerSpy("json")
    markdown = SerializerSpy("markdown")
    writer = WriterSpy()
    exporter = ExportFullNetworkReport(json_serializer, markdown, writer)

    result = exporter.execute(snapshot, Path("scan.json"), Path("scan.md"))

    assert json_serializer.snapshots[0] is snapshot
    assert markdown.snapshots[0] is snapshot
    assert len(json_serializer.snapshots) == len(markdown.snapshots) == 1
    assert tuple(item.format for item in result) == (ReportFormat.JSON, ReportFormat.MARKDOWN)


def test_same_output_path_is_rejected_before_serialization() -> None:
    json_serializer = SerializerSpy("json")
    markdown = SerializerSpy("markdown")
    exporter = ExportFullNetworkReport(json_serializer, markdown, WriterSpy())

    with pytest.raises(ReportPathError, match="different paths"):
        exporter.execute(sample_snapshot(), Path("report.out"), Path.cwd() / "report.out")

    assert not json_serializer.snapshots
    assert not markdown.snapshots


def test_one_write_failure_is_preserved() -> None:
    failing = Path("scan.md")
    exporter = ExportFullNetworkReport(
        SerializerSpy("json"),
        SerializerSpy("markdown"),
        WriterSpy(failing),
    )

    with pytest.raises(ReportWriteError, match="Write failed"):
        exporter.execute(sample_snapshot(), Path("scan.json"), failing)


def test_no_requested_format_performs_no_work() -> None:
    json_serializer = SerializerSpy("json")
    markdown = SerializerSpy("markdown")
    writer = WriterSpy()
    exporter = ExportFullNetworkReport(json_serializer, markdown, writer)

    result = exporter.execute(sample_snapshot())

    assert result == ()
    assert not json_serializer.snapshots
    assert not markdown.snapshots
    assert not writer.calls


def test_path_conflict_uses_normalized_absolute_paths() -> None:
    assert paths_conflict(Path("report.json"), Path.cwd() / "report.json")
    assert not paths_conflict(Path("report.json"), Path("report.md"))
