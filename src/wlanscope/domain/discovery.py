from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from typing import ClassVar

from wlanscope.domain.interfaces import MacAddress

HostAddress = IPv4Address | IPv6Address


class DiscoverySource(Enum):
    SELF = "Self"
    GATEWAY = "Gateway"
    NEIGHBOR_CACHE = "Neighbor cache"
    ICMP_RESPONSE = "ICMP response"


class ReachabilityState(Enum):
    RESPONDED = "Responded"
    NO_RESPONSE = "No response"
    NOT_PROBED = "Not probed"
    PROBE_FAILED = "Probe failed"
    CANCELED = "Canceled"


@dataclass(frozen=True, slots=True)
class NeighborState:
    native_value: int
    labels: ClassVar[tuple[tuple[int, str], ...]] = (
        (0, "Unreachable"),
        (1, "Incomplete"),
        (2, "Probe"),
        (3, "Delay"),
        (4, "Stale"),
        (5, "Reachable"),
        (6, "Permanent"),
    )

    @property
    def display_name(self) -> str:
        return next(
            (label for value, label in self.labels if value == self.native_value),
            f"Unknown ({self.native_value})",
        )


@dataclass(frozen=True, slots=True)
class NeighborEntry:
    interface_index: int
    address: HostAddress
    mac_address: MacAddress | None
    state: NeighborState
    is_router: bool

    def __post_init__(self) -> None:
        if self.interface_index < 0:
            raise ValueError("Interface index cannot be negative")


@dataclass(frozen=True, slots=True)
class DiscoveryPlan:
    interface_index: int
    subnet: IPv4Network
    local_addresses: tuple[IPv4Address, ...]
    gateways: tuple[IPv4Address, ...]
    usable_host_count: int
    targets: tuple[IPv4Address, ...]
    timeout_ms: int
    worker_count: int

    def __post_init__(self) -> None:
        if self.interface_index < 0:
            raise ValueError("Interface index cannot be negative")
        if self.usable_host_count < 1:
            raise ValueError("Usable host count must be positive")
        if self.timeout_ms < 1:
            raise ValueError("Probe timeout must be positive")
        if self.worker_count < 1:
            raise ValueError("Worker count must be positive")
        if any(address not in self.subnet for address in self.local_addresses):
            raise ValueError("Local addresses must belong to the discovery subnet")
        if any(address not in self.subnet for address in self.targets):
            raise ValueError("Probe targets must belong to the discovery subnet")


@dataclass(frozen=True, slots=True)
class ProbeResult:
    address: IPv4Address
    state: ReachabilityState
    response_time_ms: int | None = None

    def __post_init__(self) -> None:
        if self.response_time_ms is not None and self.response_time_ms < 0:
            raise ValueError("Response time cannot be negative")
        if self.state is ReachabilityState.RESPONDED and self.response_time_ms is None:
            raise ValueError("An ICMP response requires a response time")


@dataclass(frozen=True, slots=True)
class DiscoveredHost:
    interface_index: int
    address: HostAddress
    mac_address: MacAddress | None
    reachability: ReachabilityState
    sources: frozenset[DiscoverySource]
    neighbor_state: NeighborState | None = None

    def __post_init__(self) -> None:
        if self.interface_index < 0:
            raise ValueError("Interface index cannot be negative")
        if not self.sources:
            raise ValueError("A discovered host requires at least one source")


@dataclass(frozen=True, slots=True)
class DiscoveryIssue:
    stage: str
    message: str


@dataclass(frozen=True, slots=True)
class DeviceInventory:
    plan: DiscoveryPlan
    hosts: tuple[DiscoveredHost, ...]
    probes_executed: int
    issues: tuple[DiscoveryIssue, ...] = ()
    canceled: bool = False

    @property
    def is_partial(self) -> bool:
        return bool(self.issues) or self.canceled


class DiscoveryError(RuntimeError):
    pass


class NoUsableSubnetError(DiscoveryError):
    pass


class RangeAuthorizationRequiredError(DiscoveryError):
    def __init__(self, usable_host_count: int) -> None:
        self.usable_host_count = usable_host_count
        super().__init__(
            f"The local subnet contains {usable_host_count} usable addresses; "
            "explicit large-range authorization is required"
        )


class RangeTooLargeError(DiscoveryError):
    def __init__(self, usable_host_count: int) -> None:
        self.usable_host_count = usable_host_count
        super().__init__(
            f"The local subnet contains {usable_host_count} usable addresses, "
            "exceeding the v1.0 limit of 4096"
        )


class NeighborCollectionError(DiscoveryError):
    pass


class IcmpUnavailableError(DiscoveryError):
    pass
