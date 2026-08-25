from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from wlanscope.domain.enrichment import EnrichedDeviceInventory
from wlanscope.domain.interfaces import InterfaceInventory
from wlanscope.domain.nearby_wifi import NearbyWifiSnapshot
from wlanscope.domain.network import CurrentNetworkSnapshot
from wlanscope.domain.wifi import CurrentWifiSnapshot


class FullScanStatus(Enum):
    SUCCESS = "Success"
    PARTIAL = "Partial"
    FAILED = "Failed"


class ScanSection(Enum):
    ADAPTERS = "Network interfaces"
    CURRENT_WIFI = "Current Wi-Fi"
    CURRENT_NETWORK = "Current network"
    NEARBY_WIFI = "Nearby Wi-Fi"
    DEVICES = "Observed devices"


class ScanSectionStatus(Enum):
    SUCCESS = "Success"
    PARTIAL = "Partial"
    FAILED = "Failed"
    SKIPPED = "Skipped"


@dataclass(frozen=True, slots=True)
class FullScanIssue:
    section: ScanSection
    message: str

    def __post_init__(self) -> None:
        if not self.message.strip():
            raise ValueError("A full scan issue requires a message")


@dataclass(frozen=True, slots=True)
class ScanSectionResult:
    section: ScanSection
    status: ScanSectionStatus
    issues: tuple[FullScanIssue, ...] = ()

    def __post_init__(self) -> None:
        if any(issue.section is not self.section for issue in self.issues):
            raise ValueError("Section issues must match their section result")


@dataclass(frozen=True, slots=True)
class FullNetworkSnapshot:
    started_at: datetime
    completed_at: datetime
    sections: tuple[ScanSectionResult, ...]
    interfaces: InterfaceInventory | None = None
    current_wifi: CurrentWifiSnapshot | None = None
    current_network: CurrentNetworkSnapshot | None = None
    nearby_wifi: NearbyWifiSnapshot | None = None
    devices: EnrichedDeviceInventory | None = None

    def __post_init__(self) -> None:
        if self.started_at.tzinfo is None or self.completed_at.tzinfo is None:
            raise ValueError("Full scan timestamps must be timezone-aware")
        if self.completed_at < self.started_at:
            raise ValueError("Full scan completion cannot precede its start")
        expected = tuple(ScanSection)
        actual = tuple(result.section for result in self.sections)
        if actual != expected:
            raise ValueError("Full scan sections must be complete and deterministically ordered")

    @property
    def status(self) -> FullScanStatus:
        statuses = tuple(result.status for result in self.sections)
        if all(status is ScanSectionStatus.SUCCESS for status in statuses):
            return FullScanStatus.SUCCESS
        useful = {ScanSectionStatus.SUCCESS, ScanSectionStatus.PARTIAL}
        if any(status in useful for status in statuses):
            return FullScanStatus.PARTIAL
        return FullScanStatus.FAILED

    @property
    def issues(self) -> tuple[FullScanIssue, ...]:
        unique: dict[tuple[ScanSection, str], FullScanIssue] = {}
        for result in self.sections:
            for issue in result.issues:
                unique.setdefault((issue.section, issue.message), issue)
        return tuple(unique.values())

    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()

    def section(self, section: ScanSection) -> ScanSectionResult:
        return next(result for result in self.sections if result.section is section)
