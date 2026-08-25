import ctypes
from ipaddress import ip_address

import pytest

from wlanscope.domain.discovery import NeighborCollectionError
from wlanscope.platform.windows.ip_configuration import AF_INET, AF_INET6
from wlanscope.platform.windows.neighbors import (
    ERROR_NOT_FOUND,
    MAX_NEIGHBOR_ENTRIES,
    NativeNeighborBindings,
    WindowsNeighborCollector,
    _convert_neighbor,
    _MibIpNetRow2,
    _MibIpNetTable2,
)


class FakeBindings:
    def __init__(self, result: int, address: int) -> None:
        self.result = result
        self.address = address
        self.freed: list[int] = []

    def get_table(self) -> tuple[int, int]:
        return self.result, self.address

    def free_table(self, address: int) -> None:
        self.freed.append(address)


def ipv4_row(address: bytes, mac: bytes = b"\x02\x00\x00\x00\x00\x10") -> _MibIpNetRow2:
    row = _MibIpNetRow2()
    row.address.ipv4.family = AF_INET
    row.address.ipv4.address[:] = address
    row.interface_index = 7
    row.physical_address_length = len(mac)
    row.physical_address[: len(mac)] = mac
    row.state = 5
    row.flags.value = 1
    return row


def ipv6_row(address: bytes) -> _MibIpNetRow2:
    row = _MibIpNetRow2()
    row.address.ipv6.family = AF_INET6
    row.address.ipv6.address[:] = address
    row.interface_index = 7
    row.state = 4
    return row


def test_convert_ipv4_neighbor() -> None:
    entry = _convert_neighbor(ipv4_row(bytes((192, 0, 2, 10))))

    assert entry is not None
    assert entry.address == ip_address("192.0.2.10")
    assert str(entry.mac_address) == "02:00:00:00:00:10"
    assert entry.state.display_name == "Reachable"
    assert entry.is_router


def test_convert_ipv6_neighbor_without_mac() -> None:
    entry = _convert_neighbor(ipv6_row(ip_address("2001:db8::10").packed))

    assert entry is not None
    assert entry.address == ip_address("2001:db8::10")
    assert entry.mac_address is None


@pytest.mark.parametrize(
    "mac",
    [b"", b"\x00" * 6, b"\xff" * 6, b"\x01\x00\x5e\x00\x00\x01", b"\x02" * 8],
)
def test_invalid_or_non_host_physical_addresses_are_not_exposed(mac: bytes) -> None:
    entry = _convert_neighbor(ipv4_row(bytes((192, 0, 2, 10)), mac))

    assert entry is not None
    assert entry.mac_address is None


def test_physical_address_length_over_native_capacity_is_rejected() -> None:
    row = ipv4_row(bytes((192, 0, 2, 10)))
    row.physical_address_length = 33

    with pytest.raises(NeighborCollectionError, match="physical address length"):
        _convert_neighbor(row)


def test_multicast_neighbor_address_is_filtered() -> None:
    assert _convert_neighbor(ipv4_row(bytes((224, 0, 0, 1)))) is None


def test_unknown_address_family_is_reported_as_malformed() -> None:
    row = _MibIpNetRow2()
    row.address.family = 99

    with pytest.raises(NeighborCollectionError, match="malformed"):
        _convert_neighbor(row)


def test_collector_converts_table_and_frees_memory() -> None:
    table = _MibIpNetTable2()
    table.number_of_entries = 1
    table.table[0] = ipv4_row(bytes((192, 0, 2, 10)))
    address = ctypes.addressof(table)
    bindings = FakeBindings(0, address)

    entries = WindowsNeighborCollector(bindings).collect()

    assert len(entries) == 1
    assert bindings.freed == [address]


def test_collector_frees_memory_after_conversion_failure() -> None:
    table = _MibIpNetTable2()
    table.number_of_entries = 1
    table.table[0].address.family = 99
    address = ctypes.addressof(table)
    bindings = FakeBindings(0, address)

    with pytest.raises(NeighborCollectionError):
        WindowsNeighborCollector(bindings).collect()

    assert bindings.freed == [address]


def test_empty_neighbor_table_result_is_valid() -> None:
    bindings = FakeBindings(ERROR_NOT_FOUND, 0)

    assert WindowsNeighborCollector(bindings).collect() == ()


def test_native_error_releases_returned_buffer() -> None:
    bindings = FakeBindings(5, 1234)

    with pytest.raises(NeighborCollectionError, match="Windows error 5"):
        WindowsNeighborCollector(bindings).collect()

    assert bindings.freed == [1234]


def test_unreasonable_table_count_is_rejected_and_freed() -> None:
    table = _MibIpNetTable2()
    table.number_of_entries = MAX_NEIGHBOR_ENTRIES + 1
    address = ctypes.addressof(table)
    bindings = FakeBindings(0, address)

    with pytest.raises(NeighborCollectionError, match="unreasonable"):
        WindowsNeighborCollector(bindings).collect()

    assert bindings.freed == [address]


def test_native_bindings_are_windows_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wlanscope.platform.windows.neighbors.sys.platform", "linux")

    with pytest.raises(NeighborCollectionError, match="require Windows"):
        NativeNeighborBindings()
