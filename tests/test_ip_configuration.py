import ctypes
from ipaddress import IPv4Address, IPv6Address

import pytest

from wlanscope.domain.interfaces import InterfaceCollectionError
from wlanscope.domain.network import (
    IpAddressAssignment,
    NativeNetworkData,
    NetworkCollectionError,
    Route,
)
from wlanscope.platform.windows.ip_configuration import (
    AF_INET,
    AF_INET6,
    IpHelperConfigurationError,
    NativeIpConfigurationBackend,
    WindowsIpConfigurationCollector,
    _convert_adapter_records,
    _convert_address,
    _convert_route,
    _MibIpForwardRow2,
    _MibIpForwardTable2,
    _MibUnicastIpAddressRow,
    _MibUnicastIpAddressTable,
    _SockaddrInet,
)
from wlanscope.platform.windows.ip_helper import AdapterAddressRecord


def test_native_structure_layouts_match_windows_abi() -> None:
    assert ctypes.sizeof(_SockaddrInet) == 28
    assert ctypes.sizeof(_MibUnicastIpAddressRow) == 80
    assert _MibUnicastIpAddressTable.table.offset == 8
    assert ctypes.sizeof(_MibIpForwardRow2) == 104
    assert _MibIpForwardTable2.table.offset == 8


def test_converts_ipv4_address_assignment() -> None:
    row = _address_row(AF_INET, bytes.fromhex("C0000218"), 24, 7)

    assignment = _convert_address(row)

    assert str(assignment.address) == "192.0.2.24"
    assert str(assignment.network) == "192.0.2.0/24"
    assert assignment.interface_index == 7
    assert assignment.prefix_origin.display_name == "DHCP"
    assert assignment.dad_state.display_name == "Preferred"


def test_converts_ipv6_address_and_scope() -> None:
    row = _address_row(AF_INET6, bytes.fromhex("FE800000000000000000000000000001"), 64, 9)
    row.address.ipv6.scope_id = 9

    assignment = _convert_address(row)

    assert str(assignment.address) == "fe80::1"
    assert assignment.scope_id == 9
    assert assignment.address.is_link_local


def test_unknown_address_origins_are_preserved() -> None:
    row = _address_row(AF_INET, bytes.fromhex("C0000218"), 24, 7)
    row.prefix_origin = 99
    row.suffix_origin = 98
    row.dad_state = 97

    assignment = _convert_address(row)

    assert assignment.prefix_origin.display_name == "Unknown (99)"
    assert assignment.address_origin.display_name == "Unknown (98)"
    assert assignment.dad_state.display_name == "Unknown (97)"


def test_converts_ipv4_and_ipv6_routes() -> None:
    ipv4 = _route_row(AF_INET, b"\x00" * 4, 0, bytes.fromhex("C0000201"), 7)
    ipv6 = _route_row(
        AF_INET6,
        bytes.fromhex("20010DB8000100000000000000000000"),
        64,
        bytes.fromhex("20010DB8000000000000000000000001"),
        9,
    )

    ipv4_route = _convert_route(ipv4)
    ipv6_route = _convert_route(ipv6)

    assert str(ipv4_route.destination) == "0.0.0.0/0"
    assert str(ipv4_route.next_hop) == "192.0.2.1"
    assert ipv4_route.route_metric == 15
    assert str(ipv6_route.destination) == "2001:db8:1::/64"
    assert ipv6_route.destination.version == 6


def test_unknown_route_protocol_is_preserved() -> None:
    row = _route_row(AF_INET, b"\x00" * 4, 0, bytes.fromhex("C0000201"), 7)
    row.protocol = 8765
    row.origin = 7654

    route = _convert_route(row)

    assert route.protocol.display_name == "Unknown (8765)"
    assert route.origin.display_name == "Unknown (7654)"


def test_unsupported_sockaddr_family_is_rejected() -> None:
    row = _address_row(AF_INET, bytes.fromhex("C0000218"), 24, 7)
    row.address.family = 99

    with pytest.raises(NetworkCollectionError, match="unsupported address family"):
        _convert_address(row)


def test_native_address_table_is_freed() -> None:
    row = _address_row(AF_INET, bytes.fromhex("C0000218"), 24, 7)
    backend, freed = _backend_with_tables((row,), ())

    addresses = backend.read_addresses()

    assert len(addresses) == 1
    assert len(freed) == 1


def test_native_route_table_is_freed_when_conversion_fails() -> None:
    row = _route_row(AF_INET, b"\x00" * 4, 0, bytes.fromhex("C0000201"), 7)
    row.next_hop.family = 99
    backend, freed = _backend_with_tables((), (row,))

    with pytest.raises(NetworkCollectionError):
        backend.read_routes()

    assert len(freed) == 1


def test_native_tables_can_be_empty() -> None:
    backend, freed = _backend_with_tables((), ())

    assert backend.read_addresses() == ()
    assert backend.read_routes() == ()
    assert len(freed) == 2


def test_native_api_error_is_translated() -> None:
    backend = NativeIpConfigurationBackend(FailingBindings())

    with pytest.raises(IpHelperConfigurationError) as error:
        backend.read_addresses()

    assert error.value.operation == "GetUnicastIpAddressTable"
    assert error.value.error_code == 5


def test_collector_combines_backend_results() -> None:
    expected = NativeNetworkData((), ())

    assert (
        WindowsIpConfigurationCollector(StaticBackend(), StaticAdapterBackend()).collect()
        == expected
    )


def test_adapter_records_provide_native_dns_metrics_and_dhcp() -> None:
    adapter = AdapterAddressRecord(
        interface_index=7,
        stable_id=None,
        friendly_name=None,
        description=None,
        physical_address=b"",
        mtu=None,
        receive_link_speed_bps=None,
        transmit_link_speed_bps=None,
        dns_servers=(IPv4Address("192.0.2.53"), IPv6Address("2001:db8::53")),
        dns_suffix="example.invalid",
        ipv4_metric=20,
        ipv6_metric=30,
        dhcp_enabled=True,
        dhcp_server=IPv4Address("192.0.2.1"),
    )

    enrichments, dhcp = _convert_adapter_records((adapter,))

    assert enrichments[0].dns_servers == (IPv4Address("192.0.2.53"),)
    assert enrichments[1].dns_servers == (IPv6Address("2001:db8::53"),)
    assert enrichments[0].interface_metric == 20
    assert dhcp[0].enabled
    assert dhcp[0].server == IPv4Address("192.0.2.1")


def test_adapter_enrichment_failure_preserves_native_addresses_and_routes() -> None:
    collector = WindowsIpConfigurationCollector(StaticBackend(), FailingAdapterBackend())

    result = collector.collect()

    assert result.addresses == ()
    assert result.routes == ()
    assert len(result.issues) == 1
    assert result.issues[0].message == "Adapter details unavailable"


class StaticBackend:
    def read_addresses(self) -> tuple[IpAddressAssignment, ...]:
        return ()

    def read_routes(self) -> tuple[Route, ...]:
        return ()


class StaticAdapterBackend:
    def read_adapter_records(self) -> tuple[AdapterAddressRecord, ...]:
        return ()


class FailingAdapterBackend:
    def read_adapter_records(self) -> tuple[AdapterAddressRecord, ...]:
        raise InterfaceCollectionError("Adapter details unavailable")


def _address_row(
    family: int,
    address: bytes,
    prefix_length: int,
    interface_index: int,
) -> _MibUnicastIpAddressRow:
    row = _MibUnicastIpAddressRow()
    _set_address(row.address, family, address)
    row.interface_index = interface_index
    row.prefix_origin = 3
    row.suffix_origin = 3
    row.valid_lifetime = 7200
    row.preferred_lifetime = 3600
    row.prefix_length = prefix_length
    row.dad_state = 4
    return row


def _route_row(
    family: int,
    prefix: bytes,
    prefix_length: int,
    next_hop: bytes,
    interface_index: int,
) -> _MibIpForwardRow2:
    row = _MibIpForwardRow2()
    _set_address(row.destination_prefix.prefix, family, prefix)
    row.destination_prefix.prefix_length = prefix_length
    _set_address(row.next_hop, family, next_hop)
    row.interface_index = interface_index
    row.metric = 15
    row.protocol = 3
    row.origin = 2
    return row


def _set_address(target: _SockaddrInet, family: int, address: bytes) -> None:
    if family == AF_INET:
        target.ipv4.family = family
        target.ipv4.address[:] = address
    else:
        target.ipv6.family = family
        target.ipv6.address[:] = address


def _backend_with_tables(
    addresses: tuple[_MibUnicastIpAddressRow, ...],
    routes: tuple[_MibIpForwardRow2, ...],
) -> tuple[NativeIpConfigurationBackend, list[int]]:
    address_buffer = _table_buffer(_MibUnicastIpAddressTable, addresses)
    route_buffer = _table_buffer(_MibIpForwardTable2, routes)
    bindings = FakeBindings(address_buffer, route_buffer)
    return NativeIpConfigurationBackend(bindings), bindings.freed


class FailingBindings:
    def get_addresses(self) -> tuple[int, int]:
        return 5, 0

    def get_routes(self) -> tuple[int, int]:
        return 5, 0

    def free_table(self, address: int) -> None:
        raise AssertionError("No buffer should be freed")


class FakeBindings:
    def __init__(
        self,
        address_buffer: ctypes.Array[ctypes.c_char],
        route_buffer: ctypes.Array[ctypes.c_char],
    ) -> None:
        self._address_buffer = address_buffer
        self._route_buffer = route_buffer
        self.freed: list[int] = []

    def get_addresses(self) -> tuple[int, int]:
        return 0, ctypes.addressof(self._address_buffer)

    def get_routes(self) -> tuple[int, int]:
        return 0, ctypes.addressof(self._route_buffer)

    def free_table(self, address: int) -> None:
        self.freed.append(address)


def _table_buffer(
    table_type: type[_MibUnicastIpAddressTable] | type[_MibIpForwardTable2],
    rows: tuple[_MibUnicastIpAddressRow, ...] | tuple[_MibIpForwardRow2, ...],
) -> ctypes.Array[ctypes.c_char]:
    row_type = (
        _MibUnicastIpAddressRow if table_type is _MibUnicastIpAddressTable else _MibIpForwardRow2
    )
    size = max(
        ctypes.sizeof(table_type),
        table_type.table.offset + len(rows) * ctypes.sizeof(row_type),
    )
    buffer = ctypes.create_string_buffer(size)
    table = table_type.from_buffer(buffer)
    table.number_of_entries = len(rows)
    for index, row in enumerate(rows):
        ctypes.memmove(
            ctypes.addressof(buffer) + table_type.table.offset + index * ctypes.sizeof(row_type),
            ctypes.byref(row),
            ctypes.sizeof(row_type),
        )
    return buffer
