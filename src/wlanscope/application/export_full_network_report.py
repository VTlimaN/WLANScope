from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from wlanscope.domain.full_scan import FullNetworkSnapshot
from wlanscope.reporting.anonymization import ReportAnonymizer
from wlanscope.reporting.json_report import serialize_json_report
from wlanscope.reporting.markdown_report import render_markdown_report
from wlanscope.reporting.writer import write_report


class ReportFormat(Enum):
    JSON = "JSON"
    MARKDOWN = "Markdown"


class ReportPathError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReportExport:
    format: ReportFormat
    path: Path
    characters_written: int


class ExportFullNetworkReport:
    def __init__(
        self,
        json_serializer: Callable[[FullNetworkSnapshot], str] = serialize_json_report,
        markdown_renderer: Callable[[FullNetworkSnapshot], str] = render_markdown_report,
        writer: Callable[[Path, str, bool], int] = write_report,
        anonymized_json_serializer: Callable[
            [FullNetworkSnapshot, ReportAnonymizer], str
        ] = serialize_json_report,
        anonymized_markdown_renderer: Callable[
            [FullNetworkSnapshot, ReportAnonymizer], str
        ] = render_markdown_report,
    ) -> None:
        self._json_serializer = json_serializer
        self._markdown_renderer = markdown_renderer
        self._writer = writer
        self._anonymized_json_serializer = anonymized_json_serializer
        self._anonymized_markdown_renderer = anonymized_markdown_renderer

    def execute(
        self,
        snapshot: FullNetworkSnapshot,
        json_path: Path | None = None,
        markdown_path: Path | None = None,
        force: bool = False,
        anonymize: bool = False,
    ) -> tuple[ReportExport, ...]:
        if paths_conflict(json_path, markdown_path):
            raise ReportPathError("JSON and Markdown reports must use different paths")
        anonymizer = ReportAnonymizer() if anonymize else None
        exports: list[ReportExport] = []
        if json_path is not None:
            content = (
                self._anonymized_json_serializer(snapshot, anonymizer)
                if anonymizer
                else self._json_serializer(snapshot)
            )
            written = self._writer(json_path, content, force)
            exports.append(ReportExport(ReportFormat.JSON, json_path, written))
        if markdown_path is not None:
            content = (
                self._anonymized_markdown_renderer(snapshot, anonymizer)
                if anonymizer
                else self._markdown_renderer(snapshot)
            )
            written = self._writer(markdown_path, content, force)
            exports.append(ReportExport(ReportFormat.MARKDOWN, markdown_path, written))
        return tuple(exports)


def paths_conflict(json_path: Path | None, markdown_path: Path | None) -> bool:
    if json_path is None or markdown_path is None:
        return False
    try:
        if (
            json_path.exists()
            and markdown_path.exists()
            and os.path.samefile(json_path, markdown_path)
        ):
            return True
    except OSError:
        pass
    json_key = os.path.normcase(str(json_path.resolve(strict=False)))
    markdown_key = os.path.normcase(str(markdown_path.resolve(strict=False)))
    return json_key == markdown_key
