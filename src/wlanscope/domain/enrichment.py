from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from wlanscope.domain.discovery import DeviceInventory, DiscoveredHost, HostAddress


class HostnameResolutionState(Enum):
    RESOLVED = "Resolved"
    NOT_FOUND = "Not found"
    TIMEOUT = "Timeout"
    FAILED = "Failed"
    NOT_ATTEMPTED = "Not attempted"


class VendorResolutionState(Enum):
    RESOLVED = "Resolved"
    UNKNOWN = "Unknown"
    LOCALLY_ADMINISTERED = "Locally administered"
    NOT_APPLICABLE = "Not applicable"
    REGISTRY_UNAVAILABLE = "Registry unavailable"
    FAILED = "Failed"


class EnrichmentSource(Enum):
    PTR = "DNS PTR"
    LOCAL_OUI_REGISTRY = "Local IEEE OUI registry"


@dataclass(frozen=True, slots=True)
class HostnameResolution:
    address: HostAddress
    state: HostnameResolutionState
    hostname: str | None = None
    source: EnrichmentSource | None = None

    def __post_init__(self) -> None:
        if self.state is HostnameResolutionState.RESOLVED:
            if not self.hostname or self.source is not EnrichmentSource.PTR:
                raise ValueError("A resolved hostname requires a PTR name and source")
        elif self.hostname is not None or self.source is not None:
            raise ValueError("An unresolved hostname cannot contain a name or source")


@dataclass(frozen=True, slots=True)
class VendorResolution:
    interface_index: int
    address: HostAddress
    state: VendorResolutionState
    vendor: str | None = None
    source: EnrichmentSource | None = None

    def __post_init__(self) -> None:
        if self.state is VendorResolutionState.RESOLVED:
            if not self.vendor or self.source is not EnrichmentSource.LOCAL_OUI_REGISTRY:
                raise ValueError("A resolved vendor requires a name and registry source")
        elif self.vendor is not None or self.source is not None:
            raise ValueError("An unresolved vendor cannot contain a name or source")


@dataclass(frozen=True, slots=True)
class HostnameResolutionBatch:
    resolutions: tuple[HostnameResolution, ...]
    systemic_issue: str | None = None


@dataclass(frozen=True, slots=True)
class VendorResolutionBatch:
    resolutions: tuple[VendorResolution, ...]
    systemic_issue: str | None = None


@dataclass(frozen=True, slots=True)
class EnrichedHost:
    discovered: DiscoveredHost
    hostname: HostnameResolution
    vendor: VendorResolution

    def __post_init__(self) -> None:
        if self.hostname.address != self.discovered.address:
            raise ValueError("Hostname resolution must belong to the discovered host")
        if (
            self.vendor.interface_index != self.discovered.interface_index
            or self.vendor.address != self.discovered.address
        ):
            raise ValueError("Vendor resolution must belong to the discovered host")
        if (
            self.vendor.state is VendorResolutionState.RESOLVED
            and self.discovered.mac_address is None
        ):
            raise ValueError("A resolved vendor requires a discovered MAC address")


@dataclass(frozen=True, slots=True)
class EnrichmentIssue:
    source: str
    message: str


@dataclass(frozen=True, slots=True)
class EnrichedDeviceInventory:
    discovered: DeviceInventory
    hosts: tuple[EnrichedHost, ...]
    issues: tuple[EnrichmentIssue, ...] = ()

    def __post_init__(self) -> None:
        if tuple(host.discovered for host in self.hosts) != self.discovered.hosts:
            raise ValueError("Enrichment must preserve every discovered host and its ordering")

    @property
    def is_partial(self) -> bool:
        return self.discovered.is_partial or bool(self.issues)

    @property
    def ptr_attempted_count(self) -> int:
        return sum(
            host.hostname.state is not HostnameResolutionState.NOT_ATTEMPTED for host in self.hosts
        )

    @property
    def ptr_resolved_count(self) -> int:
        return sum(host.hostname.state is HostnameResolutionState.RESOLVED for host in self.hosts)

    @property
    def vendor_attempted_count(self) -> int:
        return sum(
            host.vendor.state
            not in {
                VendorResolutionState.NOT_APPLICABLE,
                VendorResolutionState.LOCALLY_ADMINISTERED,
            }
            for host in self.hosts
        )

    @property
    def vendor_resolved_count(self) -> int:
        return sum(host.vendor.state is VendorResolutionState.RESOLVED for host in self.hosts)

    @property
    def locally_administered_count(self) -> int:
        return sum(
            host.vendor.state is VendorResolutionState.LOCALLY_ADMINISTERED for host in self.hosts
        )
