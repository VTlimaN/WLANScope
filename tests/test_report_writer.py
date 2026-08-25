import os
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from wlanscope.reporting.writer import ReportWriteError, write_report


def test_writer_creates_utf8_file_with_final_newline(tmp_path: Path) -> None:
    target = tmp_path / "report.json"

    written = write_report(target, "São Paulo")

    assert target.read_bytes() == "São Paulo\n".encode()
    assert written == len("São Paulo\n")


def test_writer_refuses_existing_file_by_default(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("original", encoding="utf-8")

    with pytest.raises(ReportWriteError, match="--force"):
        write_report(target, "replacement")

    assert target.read_text(encoding="utf-8") == "original"


def test_writer_force_overwrites_atomically(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("original", encoding="utf-8")

    write_report(target, "replacement", force=True)

    assert target.read_text(encoding="utf-8") == "replacement\n"
    assert tuple(tmp_path.iterdir()) == (target,)


def test_writer_rejects_missing_parent(tmp_path: Path) -> None:
    target = tmp_path / "missing" / "report.json"

    with pytest.raises(ReportWriteError, match="parent directory"):
        write_report(target, "content")


def test_writer_rejects_directory_target(tmp_path: Path) -> None:
    with pytest.raises(ReportWriteError, match="directory"):
        write_report(tmp_path, "content")


def test_writer_reports_permission_failure(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    def denied(*args: object, **kwargs: object) -> tuple[int, str]:
        raise PermissionError(13, "Access denied")

    monkeypatch.setattr("wlanscope.reporting.writer.tempfile.mkstemp", denied)

    with pytest.raises(ReportWriteError, match="Access denied"):
        write_report(tmp_path / "report.json", "content")


def test_atomic_failure_removes_temporary_file(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    def fail_rename(source: Path, destination: Path) -> None:
        raise OSError(5, "Atomic rename failed")

    monkeypatch.setattr(os, "rename", fail_rename)
    target = tmp_path / "report.json"

    with pytest.raises(ReportWriteError, match="Atomic rename failed"):
        write_report(target, "content")

    assert not target.exists()
    assert not tuple(tmp_path.iterdir())


def test_writer_does_not_duplicate_existing_final_newline(tmp_path: Path) -> None:
    target = tmp_path / "report.md"

    write_report(target, "content\n")

    assert target.read_text(encoding="utf-8") == "content\n"
