from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from ipaddress import IPv4Address, IPv6Address, ip_network
from typing import Protocol

from wlanscope.domain.interfaces import InterfaceCollectionError
from wlanscope.domain.network import (
    AddressOrigin,
    DadState,
    DhcpEnrichment,
    DhcpState,
    InterfaceNetworkEnrichment,
    IpAddress,
    IpAddressAssignment,
    NativeNetworkData,
    NetworkCollectionError,
    NetworkIssue,
    NetworkIssueSource,
    PrefixOrigin,
    Route,
    RouteOrigin,
    RouteProtocol,
)
from wlanscope.platform.windows.ip_helper import AdapterAddressRecord, NativeIpHelperBackend

AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 23
NO_ERROR = 0
MAX_TABLE_ENTRIES = 1_000_000
INFINITE_LIFETIME = 0xFFFFFFFF


class _SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_ushort),
        ("port", ctypes.c_ushort),
        ("address", ctypes.c_ubyte * 4),
        ("zero", ctypes.c_ubyte * 8),
    ]


class _SockaddrIn6(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_ushort),
        ("port", ctypes.c_ushort),
        ("flow_info", wintypes.ULONG),
        ("address", ctypes.c_ubyte * 16),
        ("scope_id", wintypes.ULONG),
    ]


class _SockaddrInet(ctypes.Union):
    _fields_ = [
        ("ipv4", _SockaddrIn),
        ("ipv6", _SockaddrIn6),
        ("family", ctypes.c_ushort),
    ]


class _ScopeId(ctypes.Union):
    _fields_ = [("value", wintypes.ULONG), ("alignment", wintypes.ULONG)]


class _MibUnicastIpAddressRow(ctypes.Structure):
    _fields_ = [
        ("address", _SockaddrInet),
        ("interface_luid", ctypes.c_ulonglong),
        ("interface_index", wintypes.ULONG),
        ("prefix_origin", wintypes.ULONG),
        ("suffix_origin", wintypes.ULONG),
        ("valid_lifetime", wintypes.ULONG),
        ("preferred_lifetime", wintypes.ULONG),
        ("prefix_length", ctypes.c_ubyte),
        ("skip_as_source", ctypes.c_ubyte),
        ("dad_state", wintypes.ULONG),
        ("scope_id", _ScopeId),
        ("creation_timestamp", ctypes.c_longlong),
    ]


class _MibUnicastIpAddressTable(ctypes.Structure):
    _fields_ = [
        ("number_of_entries", wintypes.ULONG),
        ("table", _MibUnicastIpAddressRow * 1),
    ]


class _IpAddressPrefix(ctypes.Structure):
    _fields_ = [("prefix", _SockaddrInet), ("prefix_length", ctypes.c_ubyte)]


class _MibIpForwardRow2(ctypes.Structure):
    _fields_ = [
        ("interface_luid", ctypes.c_ulonglong),
        ("interface_index", wintypes.ULONG),
        ("destination_prefix", _IpAddressPrefix),
        ("next_hop", _SockaddrInet),
        ("site_prefix_length", ctypes.c_ubyte),
        ("valid_lifetime", wintypes.ULONG),
        ("preferred_lifetime", wintypes.ULONG),
        ("metric", wintypes.ULONG),
        ("protocol", wintypes.ULONG),
        ("loopback", ctypes.c_ubyte),
        ("autoconfigure_address", ctypes.c_ubyte),
        ("publish", ctypes.c_ubyte),
        ("immortal", ctypes.c_ubyte),
        ("age", wintypes.ULONG),
        ("origin", wintypes.ULONG),
    ]


class _MibIpForwardTable2(ctypes.Structure):
    _fields_ = [("number_of_entries", wintypes.ULONG), ("table", _MibIpForwardRow2 * 1)]


class IpConfigurationBackend(Protocol):
    def read_addresses(self) -> tuple[IpAddressAssignment, ...]: ...

    def read_routes(self) -> tuple[Route, ...]: ...


class AdapterConfigurationBackend(Protocol):
    def read_adapter_records(self) -> tuple[AdapterAddressRecord, ...]: ...


class IpConfigurationBindings(Protocol):
    def get_addresses(self) -> tuple[int, int]: ...

    def get_routes(self) -> tuple[int, int]: ...

    def free_table(self, address: int) -> None: ...


class IpHelperConfigurationError(NetworkCollectionError):
    def __init__(self, operation: str, error_code: int) -> None:
        self.operation = operation
        self.error_code = error_code
        super().__init__(f"{operation} failed with Windows error {error_code}")


class NativeIpConfigurationBindings:
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise IpHelperConfigurationError("Load IP Helper API", 50)
        library = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        self._get_addresses = library.GetUnicastIpAddressTable
        self._get_addresses.argtypes = [
            ctypes.c_ushort,
            ctypes.POINTER(ctypes.POINTER(_MibUnicastIpAddressTable)),
        ]
        self._get_addresses.restype = wintypes.ULONG
        self._get_routes = library.GetIpForwardTable2
        self._get_routes.argtypes = [
            ctypes.c_ushort,
            ctypes.POINTER(ctypes.POINTER(_MibIpForwardTable2)),
        ]
        self._get_routes.restype = wintypes.ULONG
        self._free_table = library.FreeMibTable
        self._free_table.argtypes = [ctypes.c_void_p]
        self._free_table.restype = None

    def get_addresses(self) -> tuple[int, int]:
        table_pointer = ctypes.POINTER(_MibUnicastIpAddressTable)()
        result = int(self._get_addresses(AF_UNSPEC, ctypes.byref(table_pointer)))
        address = ctypes.cast(table_pointer, ctypes.c_void_p).value
        return result, int(address or 0)

    def get_routes(self) -> tuple[int, int]:
        table_pointer = ctypes.POINTER(_MibIpForwardTable2)()
        result = int(self._get_routes(AF_UNSPEC, ctypes.byref(table_pointer)))
        address = ctypes.cast(table_pointer, ctypes.c_void_p).value
        return result, int(address or 0)

    def free_table(self, address: int) -> None:
        self._free_table(ctypes.c_void_p(address))


class NativeIpConfigurationBackend:
    def __init__(self, bindings: IpConfigurationBindings | None = None) -> None:
        self._bindings = bindings or NativeIpConfigurationBindings()

    def read_addresses(self) -> tuple[IpAddressAssignment, ...]:
        result, address = self._bindings.get_addresses()
        if result != NO_ERROR:
            if address:
                self._bindings.free_table(address)
            raise IpHelperConfigurationError("GetUnicastIpAddressTable", result)
        if not address:
            raise IpHelperConfigurationError("GetUnicastIpAddressTable", 13)
        try:
            table = _MibUnicastIpAddressTable.from_address(address)
            count = _validated_count(table.number_of_entries)
            first_row = address + _MibUnicastIpAddressTable.table.offset
            size = ctypes.sizeof(_MibUnicastIpAddressRow)
            return tuple(
                _convert_address(_MibUnicastIpAddressRow.from_address(first_row + index * size))
                for index in range(count)
            )
        finally:
            self._bindings.free_table(address)

    def read_routes(self) -> tuple[Route, ...]:
        result, address = self._bindings.get_routes()
        if result != NO_ERROR:
            if address:
                self._bindings.free_table(address)
            raise IpHelperConfigurationError("GetIpForwardTable2", result)
        if not address:
            raise IpHelperConfigurationError("GetIpForwardTable2", 13)
        try:
            table = _MibIpForwardTable2.from_address(address)
            count = _validated_count(table.number_of_entries)
            first_row = address + _MibIpForwardTable2.table.offset
            size = ctypes.sizeof(_MibIpForwardRow2)
            return tuple(
                _convert_route(_MibIpForwardRow2.from_address(first_row + index * size))
                for index in range(count)
            )
        finally:
            self._bindings.free_table(address)


class WindowsIpConfigurationCollector:
    def __init__(
        self,
        backend: IpConfigurationBackend | None = None,
        adapter_backend: AdapterConfigurationBackend | None = None,
    ) -> None:
        self._backend = backend
        self._adapter_backend = adapter_backend

    def collect(self) -> NativeNetworkData:
        backend = self._backend or NativeIpConfigurationBackend()
        addresses = backend.read_addresses()
        routes = backend.read_routes()
        adapter_backend = self._adapter_backend or NativeIpHelperBackend()
        try:
            adapters = adapter_backend.read_adapter_records()
        except InterfaceCollectionError as error:
            issue = NetworkIssue(NetworkIssueSource.IP_HELPER_ENRICHMENT, str(error))
            return NativeNetworkData(addresses, routes, issues=(issue,))
        enrichments, dhcp = _convert_adapter_records(adapters)
        return NativeNetworkData(addresses, routes, enrichments, dhcp)


def _convert_address(row: _MibUnicastIpAddressRow) -> IpAddressAssignment:
    address, native_scope_id = _convert_sockaddr(row.address)
    scope_id = int(row.scope_id.value) or native_scope_id
    return IpAddressAssignment(
        address=address,
        prefix_length=int(row.prefix_length),
        interface_index=int(row.interface_index),
        prefix_origin=PrefixOrigin(int(row.prefix_origin)),
        address_origin=AddressOrigin(int(row.suffix_origin)),
        dad_state=DadState(int(row.dad_state)),
        preferred_lifetime_seconds=_convert_lifetime(row.preferred_lifetime),
        valid_lifetime_seconds=_convert_lifetime(row.valid_lifetime),
        skip_as_source=bool(row.skip_as_source),
        scope_id=scope_id or None,
    )


def _convert_route(row: _MibIpForwardRow2) -> Route:
    prefix_address, _ = _convert_sockaddr(row.destination_prefix.prefix)
    next_hop, scope_id = _convert_sockaddr(row.next_hop)
    prefix_length = int(row.destination_prefix.prefix_length)
    try:
        destination = ip_network((prefix_address, prefix_length), strict=False)
        return Route(
            destination=destination,
            next_hop=next_hop,
            interface_index=int(row.interface_index),
            route_metric=int(row.metric),
            interface_metric=None,
            protocol=RouteProtocol(int(row.protocol)),
            origin=RouteOrigin(int(row.origin)),
            next_hop_scope_id=scope_id or None,
        )
    except ValueError as error:
        raise NetworkCollectionError(f"Windows returned invalid route data: {error}") from error


def _convert_sockaddr(value: _SockaddrInet) -> tuple[IpAddress, int]:
    family = int(value.family)
    if family == AF_INET:
        return IPv4Address(bytes(value.ipv4.address)), 0
    if family == AF_INET6:
        return IPv6Address(bytes(value.ipv6.address)), int(value.ipv6.scope_id)
    raise NetworkCollectionError(f"Windows returned unsupported address family {family}")


def _convert_lifetime(value: int) -> int | None:
    parsed = int(value)
    return None if parsed == INFINITE_LIFETIME else parsed


def _validated_count(value: int) -> int:
    count = int(value)
    if count > MAX_TABLE_ENTRIES:
        raise NetworkCollectionError("IP Helper returned an unreasonable table size")
    return count


def _convert_adapter_records(
    adapters: tuple[AdapterAddressRecord, ...],
) -> tuple[tuple[InterfaceNetworkEnrichment, ...], tuple[DhcpEnrichment, ...]]:
    enrichments: list[InterfaceNetworkEnrichment] = []
    dhcp: list[DhcpEnrichment] = []
    for adapter in adapters:
        for version, metric in ((4, adapter.ipv4_metric), (6, adapter.ipv6_metric)):
            servers = tuple(server for server in adapter.dns_servers if server.version == version)
            state = (
                DhcpState.ENABLED
                if version == 4 and adapter.dhcp_enabled
                else DhcpState.DISABLED
                if version == 4
                else DhcpState.UNKNOWN
            )
            enrichments.append(
                InterfaceNetworkEnrichment(
                    interface_index=adapter.interface_index,
                    address_family=version,
                    interface_metric=metric,
                    dhcp_state=state,
                    dns_servers=servers,
                    dns_suffix=adapter.dns_suffix,
                )
            )
        dhcp.append(
            DhcpEnrichment(
                interface_index=adapter.interface_index,
                enabled=adapter.dhcp_enabled,
                server=adapter.dhcp_server,
            )
        )
    return tuple(enrichments), tuple(dhcp)
