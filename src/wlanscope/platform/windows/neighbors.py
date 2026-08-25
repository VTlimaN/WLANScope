from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from ipaddress import IPv4Address
from typing import Protocol

from wlanscope.domain.discovery import NeighborCollectionError, NeighborEntry, NeighborState
from wlanscope.domain.interfaces import MacAddress
from wlanscope.domain.network import NetworkCollectionError
from wlanscope.platform.windows.ip_configuration import (
    AF_UNSPEC,
    NO_ERROR,
    _convert_sockaddr,
    _SockaddrInet,
)

ERROR_NOT_FOUND = 1168
MAX_NEIGHBOR_ENTRIES = 1_000_000
MAX_PHYSICAL_ADDRESS_LENGTH = 32


class _NeighborFlags(ctypes.Union):
    _fields_ = [("value", ctypes.c_ubyte), ("alignment", ctypes.c_ubyte)]


class _ReachabilityTime(ctypes.Union):
    _fields_ = [("last_reachable", wintypes.ULONG), ("last_unreachable", wintypes.ULONG)]


class _MibIpNetRow2(ctypes.Structure):
    _fields_ = [
        ("address", _SockaddrInet),
        ("interface_index", wintypes.ULONG),
        ("interface_luid", ctypes.c_ulonglong),
        ("physical_address", ctypes.c_ubyte * MAX_PHYSICAL_ADDRESS_LENGTH),
        ("physical_address_length", wintypes.ULONG),
        ("state", wintypes.ULONG),
        ("flags", _NeighborFlags),
        ("reachability_time", _ReachabilityTime),
    ]


class _MibIpNetTable2(ctypes.Structure):
    _fields_ = [("number_of_entries", wintypes.ULONG), ("table", _MibIpNetRow2 * 1)]


class NeighborBindings(Protocol):
    def get_table(self) -> tuple[int, int]: ...

    def free_table(self, address: int) -> None: ...


class NativeNeighborBindings:
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise NeighborCollectionError("IP Helper neighbor APIs require Windows")
        library = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        self._get_table = library.GetIpNetTable2
        self._get_table.argtypes = [
            ctypes.c_ushort,
            ctypes.POINTER(ctypes.POINTER(_MibIpNetTable2)),
        ]
        self._get_table.restype = wintypes.ULONG
        self._free_table = library.FreeMibTable
        self._free_table.argtypes = [ctypes.c_void_p]
        self._free_table.restype = None

    def get_table(self) -> tuple[int, int]:
        pointer = ctypes.POINTER(_MibIpNetTable2)()
        result = int(self._get_table(AF_UNSPEC, ctypes.byref(pointer)))
        address = ctypes.cast(pointer, ctypes.c_void_p).value
        return result, int(address or 0)

    def free_table(self, address: int) -> None:
        self._free_table(ctypes.c_void_p(address))


class WindowsNeighborCollector:
    def __init__(self, bindings: NeighborBindings | None = None) -> None:
        self._bindings = bindings

    def collect(self) -> tuple[NeighborEntry, ...]:
        bindings = self._bindings or NativeNeighborBindings()
        result, address = bindings.get_table()
        if result == ERROR_NOT_FOUND:
            if address:
                bindings.free_table(address)
            return ()
        if result != NO_ERROR:
            if address:
                bindings.free_table(address)
            raise NeighborCollectionError(f"GetIpNetTable2 failed with Windows error {result}")
        if not address:
            raise NeighborCollectionError("GetIpNetTable2 returned no table")
        try:
            table = _MibIpNetTable2.from_address(address)
            count = _validated_count(table.number_of_entries)
            first_row = address + _MibIpNetTable2.table.offset
            row_size = ctypes.sizeof(_MibIpNetRow2)
            entries: list[NeighborEntry] = []
            for index in range(count):
                row = _MibIpNetRow2.from_address(first_row + index * row_size)
                entry = _convert_neighbor(row)
                if entry is not None:
                    entries.append(entry)
            return tuple(sorted(entries, key=_neighbor_sort_key))
        finally:
            bindings.free_table(address)


def _convert_neighbor(row: _MibIpNetRow2) -> NeighborEntry | None:
    try:
        address, _ = _convert_sockaddr(row.address)
    except (NetworkCollectionError, ValueError) as error:
        raise NeighborCollectionError(
            f"Windows returned malformed neighbor data: {error}"
        ) from error
    if address.is_unspecified or address.is_multicast:
        return None
    return NeighborEntry(
        interface_index=int(row.interface_index),
        address=address,
        mac_address=_convert_mac(row),
        state=NeighborState(int(row.state)),
        is_router=bool(row.flags.value & 1),
    )


def _convert_mac(row: _MibIpNetRow2) -> MacAddress | None:
    length = int(row.physical_address_length)
    if length == 0:
        return None
    if length > MAX_PHYSICAL_ADDRESS_LENGTH:
        raise NeighborCollectionError(
            "Windows returned an invalid neighbor physical address length"
        )
    if length != 6:
        return None
    octets = bytes(row.physical_address[:length])
    if not any(octets) or octets == b"\xff" * 6 or octets[0] & 1:
        return None
    try:
        return MacAddress(octets)
    except ValueError as error:
        raise NeighborCollectionError(
            f"Windows returned an invalid neighbor MAC: {error}"
        ) from error


def _validated_count(value: int) -> int:
    count = int(value)
    if count > MAX_NEIGHBOR_ENTRIES:
        raise NeighborCollectionError("IP Helper returned an unreasonable neighbor table size")
    return count


def _neighbor_sort_key(entry: NeighborEntry) -> tuple[int, int, int]:
    family = 4 if isinstance(entry.address, IPv4Address) else 6
    return (entry.interface_index, family, int(entry.address))
