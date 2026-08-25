from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from wlanscope.domain.full_scan import (
    FullNetworkSnapshot,
    FullScanIssue,
    FullScanStatus,
    ScanSection,
    ScanSectionResult,
    ScanSectionStatus,
)


def sections(status: ScanSectionStatus) -> tuple[ScanSectionResult, ...]:
    return tuple(ScanSectionResult(section, status) for section in ScanSection)


def snapshot(status: ScanSectionStatus) -> FullNetworkSnapshot:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    return FullNetworkSnapshot(started, started + timedelta(seconds=2), sections(status))


def test_all_success_sections_produce_success() -> None:
    assert snapshot(ScanSectionStatus.SUCCESS).status is FullScanStatus.SUCCESS


def test_mixed_useful_sections_produce_partial() -> None:
    results = list(sections(ScanSectionStatus.SUCCESS))
    results[1] = ScanSectionResult(ScanSection.CURRENT_WIFI, ScanSectionStatus.FAILED)
    started = datetime(2026, 1, 1, tzinfo=UTC)

    full = FullNetworkSnapshot(started, started, tuple(results))

    assert full.status is FullScanStatus.PARTIAL


def test_no_useful_sections_produce_failed() -> None:
    results = tuple(
        ScanSectionResult(
            section,
            ScanSectionStatus.SKIPPED
            if section is ScanSection.DEVICES
            else ScanSectionStatus.FAILED,
        )
        for section in ScanSection
    )
    started = datetime(2026, 1, 1, tzinfo=UTC)

    full = FullNetworkSnapshot(started, started, results)

    assert full.status is FullScanStatus.FAILED


def test_snapshot_requires_timezone_aware_timing() -> None:
    started = datetime(2026, 1, 1)

    with pytest.raises(ValueError, match="timezone-aware"):
        FullNetworkSnapshot(started, started, sections(ScanSectionStatus.SUCCESS))


def test_snapshot_rejects_completion_before_start() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)

    with pytest.raises(ValueError, match="precede"):
        FullNetworkSnapshot(
            started,
            started - timedelta(seconds=1),
            sections(ScanSectionStatus.SUCCESS),
        )


def test_section_order_is_required() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)

    with pytest.raises(ValueError, match="ordered"):
        FullNetworkSnapshot(
            started,
            started,
            tuple(reversed(sections(ScanSectionStatus.SUCCESS))),
        )


def test_issue_must_match_section() -> None:
    issue = FullScanIssue(ScanSection.CURRENT_WIFI, "Unavailable")

    with pytest.raises(ValueError, match="match"):
        ScanSectionResult(ScanSection.ADAPTERS, ScanSectionStatus.PARTIAL, (issue,))


def test_issues_are_deduplicated_and_duration_is_available() -> None:
    issue = FullScanIssue(ScanSection.ADAPTERS, "Limited")
    results = list(sections(ScanSectionStatus.SUCCESS))
    results[0] = ScanSectionResult(
        ScanSection.ADAPTERS,
        ScanSectionStatus.PARTIAL,
        (issue, issue),
    )
    started = datetime(2026, 1, 1, tzinfo=UTC)
    full = FullNetworkSnapshot(started, started + timedelta(seconds=2), tuple(results))

    assert full.issues == (issue,)
    assert full.duration_seconds == 2


def test_snapshot_is_frozen() -> None:
    full = snapshot(ScanSectionStatus.SUCCESS)
    attribute = "started_at"

    with pytest.raises(FrozenInstanceError):
        setattr(full, attribute, datetime.now(UTC))
