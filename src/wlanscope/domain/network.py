from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_network,
)
from typing import ClassVar

from wlanscope.domain.interfaces import NetworkInterface
from wlanscope.domain.wifi import WifiInterfaceSnapshot

IpAddress = IPv4Address | IPv6Address
IpNetwork = IPv4Network | IPv6Network
UNUSED_ROUTE_METRIC = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class NativeNetworkValue:
    native_value: int
    labels: ClassVar[tuple[tuple[int, str], ...]] = ()

    @property
    def display_name(self) -> str:
        return next(
            (label for value, label in self.labels if value == self.native_value),
            f"Unknown ({self.native_value})",
        )


class PrefixOrigin(NativeNetworkValue):
    labels = (
        (0, "Other"),
        (1, "Manual"),
        (2, "Well-known"),
        (3, "DHCP"),
        (4, "Router advertisement"),
    )


class AddressOrigin(NativeNetworkValue):
    labels = (
        (0, "Other"),
        (1, "Manual"),
        (2, "Well-known"),
        (3, "DHCP"),
        (4, "Link layer"),
        (5, "Random"),
    )


class DadState(NativeNetworkValue):
    labels = (
        (0, "Invalid"),
        (1, "Tentative"),
        (2, "Duplicate"),
        (3, "Deprecated"),
        (4, "Preferred"),
    )


class RouteProtocol(NativeNetworkValue):
    labels = (
        (2, "Local"),
        (3, "Net management"),
        (4, "ICMP"),
        (8, "EGP"),
        (9, "GGP"),
        (13, "RIP"),
        (14, "IS-IS"),
        (15, "ES-IS"),
        (16, "Cisco IGRP"),
        (17, "BBN SPF IGP"),
        (18, "OSPF"),
        (19, "BGP"),
        (10002, "NT autostatic"),
        (10006, "NT static"),
        (10007, "NT static non-DOD"),
    )


class RouteOrigin(NativeNetworkValue):
    labels = (
        (0, "Manual"),
        (1, "Well-known"),
        (2, "DHCP"),
        (3, "Router advertisement"),
        (4, "6to4"),
    )


class DhcpState(Enum):
    ENABLED = "Enabled"
    DISABLED = "Disabled"
    UNKNOWN = "Unknown"


class NetworkIssueSource(Enum):
    IP_HELPER_ENRICHMENT = "IP Helper adapter enrichment"
    DNS_AND_METRICS = "DNS and interface metrics"
    DHCP = "DHCP enrichment"
    INTERFACE_ASSOCIATION = "Interface association"
    WIFI_ASSOCIATION = "Wi-Fi association"


@dataclass(frozen=True, slots=True)
class IpAddressAssignment:
    address: IpAddress
    prefix_length: int
    interface_index: int
    prefix_origin: PrefixOrigin
    address_origin: AddressOrigin
    dad_state: DadState
    preferred_lifetime_seconds: int | None
    valid_lifetime_seconds: int | None
    skip_as_source: bool
    scope_id: int | None = None

    def __post_init__(self) -> None:
        maximum = 32 if isinstance(self.address, IPv4Address) else 128
        if not 0 <= self.prefix_length <= maximum:
            raise ValueError(f"Prefix length must be between 0 and {maximum}")
        if self.interface_index < 0:
            raise ValueError("Interface index cannot be negative")
        for lifetime in (self.preferred_lifetime_seconds, self.valid_lifetime_seconds):
            if lifetime is not None and lifetime < 0:
                raise ValueError("Address lifetime cannot be negative")
        if self.scope_id is not None and self.scope_id < 0:
            raise ValueError("Scope identifier cannot be negative")

    @property
    def network(self) -> IpNetwork:
        return ip_network((self.address, self.prefix_length), strict=False)


@dataclass(frozen=True, slots=True)
class Route:
    destination: IpNetwork
    next_hop: IpAddress
    interface_index: int
    route_metric: int
    interface_metric: int | None
    protocol: RouteProtocol
    origin: RouteOrigin
    next_hop_scope_id: int | None = None

    def __post_init__(self) -> None:
        if self.destination.version != self.next_hop.version:
            raise ValueError("Route destination and next hop must use the same address family")
        if self.interface_index < 0:
            raise ValueError("Interface index cannot be negative")
        if self.route_metric < 0:
            raise ValueError("Route metric cannot be negative")
        if self.interface_metric is not None and self.interface_metric < 0:
            raise ValueError("Interface metric cannot be negative")
        if self.next_hop_scope_id is not None and self.next_hop_scope_id < 0:
            raise ValueError("Next-hop scope identifier cannot be negative")

    @property
    def is_default(self) -> bool:
        return self.destination.prefixlen == 0

    @property
    def effective_metric(self) -> int | None:
        if self.interface_metric is None or self.route_metric == UNUSED_ROUTE_METRIC:
            return None
        return self.route_metric + self.interface_metric


@dataclass(frozen=True, slots=True)
class DnsConfiguration:
    interface_index: int
    servers: tuple[IpAddress, ...]
    suffix: str | None = None


@dataclass(frozen=True, slots=True)
class DhcpConfiguration:
    interface_index: int
    ipv4_state: DhcpState
    ipv6_state: DhcpState
    server: IPv4Address | None = None


@dataclass(frozen=True, slots=True)
class InterfaceNetworkContext:
    interface_index: int
    addresses: tuple[IpAddressAssignment, ...]
    dns: DnsConfiguration | None
    dhcp: DhcpConfiguration
    network_interface: NetworkInterface | None = None
    wifi_interface: WifiInterfaceSnapshot | None = None


@dataclass(frozen=True, slots=True)
class NetworkIssue:
    source: NetworkIssueSource
    message: str


@dataclass(frozen=True, slots=True)
class NativeNetworkData:
    addresses: tuple[IpAddressAssignment, ...]
    routes: tuple[Route, ...]
    enrichments: tuple[InterfaceNetworkEnrichment, ...] = ()
    dhcp_enrichments: tuple[DhcpEnrichment, ...] = ()
    issues: tuple[NetworkIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class InterfaceNetworkEnrichment:
    interface_index: int
    address_family: int
    interface_metric: int | None
    dhcp_state: DhcpState
    dns_servers: tuple[IpAddress, ...]
    dns_suffix: str | None

    def __post_init__(self) -> None:
        if self.address_family not in {4, 6}:
            raise ValueError("Address family must be IPv4 or IPv6")
        if self.interface_index < 0:
            raise ValueError("Interface index cannot be negative")
        if self.interface_metric is not None and self.interface_metric < 0:
            raise ValueError("Interface metric cannot be negative")


@dataclass(frozen=True, slots=True)
class DhcpEnrichment:
    interface_index: int
    enabled: bool
    server: IPv4Address | None


@dataclass(frozen=True, slots=True)
class CurrentNetworkSnapshot:
    interfaces: tuple[InterfaceNetworkContext, ...]
    routes: tuple[Route, ...]
    issues: tuple[NetworkIssue, ...] = ()

    @property
    def default_routes(self) -> tuple[Route, ...]:
        return tuple(route for route in self.routes if route.is_default)

    @property
    def is_partial(self) -> bool:
        return bool(self.issues)

    def preferred_default_route(self, ip_version: int) -> Route | None:
        candidates = tuple(
            route for route in self.default_routes if route.destination.version == ip_version
        )
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        if any(route.effective_metric is None for route in candidates):
            return None
        ordered = sorted(
            candidates,
            key=lambda route: (
                route.effective_metric,
                route.route_metric,
                route.interface_index,
                int(route.next_hop),
            ),
        )
        if ordered[0].effective_metric == ordered[1].effective_metric:
            return None
        return ordered[0]


class NetworkCollectionError(RuntimeError):
    pass


class NetworkEnrichmentError(RuntimeError):
    pass
