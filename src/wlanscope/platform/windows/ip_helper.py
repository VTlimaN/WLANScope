from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from wlanscope.domain.interfaces import (
    AdministrativeState,
    InterfaceCollectionError,
    InterfaceKind,
    MacAddress,
    MediaState,
    NetworkInterface,
    OperationalState,
    normalize_stable_id,
)

AF_UNSPEC = 0
ERROR_BUFFER_OVERFLOW = 111
NO_ERROR = 0
GAA_FLAG_SKIP_UNICAST = 0x0001
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100
GET_ADAPTER_FLAGS = (
    GAA_FLAG_SKIP_UNICAST
    | GAA_FLAG_SKIP_ANYCAST
    | GAA_FLAG_SKIP_MULTICAST
    | GAA_FLAG_SKIP_DNS_SERVER
    | GAA_FLAG_INCLUDE_ALL_INTERFACES
)
INITIAL_ADAPTER_BUFFER_SIZE = 15_000
MAX_ADAPTER_BUFFER_SIZE = 4 * 1024 * 1024
MAX_ADAPTER_BUFFER_ATTEMPTS = 3
IF_MAX_STRING_SIZE = 256
IF_MAX_PHYS_ADDRESS_LENGTH = 32
MAX_ADAPTER_ADDRESS_LENGTH = 8


class _Guid(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _MibIfRow2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", ctypes.c_ulonglong),
        ("InterfaceIndex", wintypes.ULONG),
        ("InterfaceGuid", _Guid),
        ("Alias", wintypes.WCHAR * (IF_MAX_STRING_SIZE + 1)),
        ("Description", wintypes.WCHAR * (IF_MAX_STRING_SIZE + 1)),
        ("PhysicalAddressLength", wintypes.ULONG),
        ("PhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("Mtu", wintypes.ULONG),
        ("Type", wintypes.ULONG),
        ("TunnelType", wintypes.ULONG),
        ("MediaType", wintypes.ULONG),
        ("PhysicalMediumType", wintypes.ULONG),
        ("AccessType", wintypes.ULONG),
        ("DirectionType", wintypes.ULONG),
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", wintypes.ULONG),
        ("AdminStatus", wintypes.ULONG),
        ("MediaConnectState", wintypes.ULONG),
        ("NetworkGuid", _Guid),
        ("ConnectionType", wintypes.ULONG),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("InOctets", ctypes.c_ulonglong),
        ("InUcastPkts", ctypes.c_ulonglong),
        ("InNUcastPkts", ctypes.c_ulonglong),
        ("InDiscards", ctypes.c_ulonglong),
        ("InErrors", ctypes.c_ulonglong),
        ("InUnknownProtos", ctypes.c_ulonglong),
        ("InUcastOctets", ctypes.c_ulonglong),
        ("InMulticastOctets", ctypes.c_ulonglong),
        ("InBroadcastOctets", ctypes.c_ulonglong),
        ("OutOctets", ctypes.c_ulonglong),
        ("OutUcastPkts", ctypes.c_ulonglong),
        ("OutNUcastPkts", ctypes.c_ulonglong),
        ("OutDiscards", ctypes.c_ulonglong),
        ("OutErrors", ctypes.c_ulonglong),
        ("OutUcastOctets", ctypes.c_ulonglong),
        ("OutMulticastOctets", ctypes.c_ulonglong),
        ("OutBroadcastOctets", ctypes.c_ulonglong),
        ("OutQLen", ctypes.c_ulonglong),
    ]


class _MibIfTable2(ctypes.Structure):
    _fields_ = [
        ("NumEntries", wintypes.ULONG),
        ("Table", _MibIfRow2 * 1),
    ]


class _AdapterLengthIndex(ctypes.Structure):
    _fields_ = [("Length", wintypes.ULONG), ("IfIndex", wintypes.DWORD)]


class _AdapterHeader(ctypes.Union):
    _fields_ = [("Alignment", ctypes.c_ulonglong), ("Fields", _AdapterLengthIndex)]


class _IpAdapterAddresses(ctypes.Structure):
    pass


_IpAdapterAddresses._fields_ = [
    ("Header", _AdapterHeader),
    ("Next", ctypes.POINTER(_IpAdapterAddresses)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.c_void_p),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", wintypes.LPWSTR),
    ("Description", wintypes.LPWSTR),
    ("FriendlyName", wintypes.LPWSTR),
    ("PhysicalAddress", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", wintypes.ULONG),
    ("Flags", wintypes.ULONG),
    ("Mtu", wintypes.ULONG),
    ("IfType", wintypes.ULONG),
    ("OperStatus", wintypes.ULONG),
    ("Ipv6IfIndex", wintypes.DWORD),
    ("ZoneIndices", wintypes.ULONG * 16),
    ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_ulonglong),
    ("ReceiveLinkSpeed", ctypes.c_ulonglong),
]


@dataclass(frozen=True, slots=True)
class InterfaceRow:
    interface_index: int
    stable_id: str | None
    alias: str
    description: str | None
    windows_interface_type: int
    operational_state: OperationalState
    administrative_state: AdministrativeState
    media_state: MediaState
    physical_address: bytes
    mtu: int | None
    receive_link_speed_bps: int | None
    transmit_link_speed_bps: int | None
    is_hardware: bool


@dataclass(frozen=True, slots=True)
class AdapterAddressRecord:
    interface_index: int
    stable_id: str | None
    friendly_name: str | None
    description: str | None
    physical_address: bytes
    mtu: int | None
    receive_link_speed_bps: int | None
    transmit_link_speed_bps: int | None


class IpHelperBackend(Protocol):
    def read_interface_rows(self) -> tuple[InterfaceRow, ...]: ...

    def read_adapter_records(self) -> tuple[AdapterAddressRecord, ...]: ...


class WindowsApiError(InterfaceCollectionError):
    def __init__(self, operation: str, error_code: int) -> None:
        self.operation = operation
        self.error_code = error_code
        super().__init__(f"{operation} failed with Windows error {error_code}")


class NativeIpHelperBackend:
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise WindowsApiError("Load IP Helper API", 50)
        self._library = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        self._get_if_table2 = self._library.GetIfTable2
        self._get_if_table2.argtypes = [ctypes.POINTER(ctypes.POINTER(_MibIfTable2))]
        self._get_if_table2.restype = wintypes.ULONG
        self._get_adapters_addresses = self._library.GetAdaptersAddresses
        self._get_adapters_addresses.argtypes = [
            wintypes.ULONG,
            wintypes.ULONG,
            ctypes.c_void_p,
            ctypes.POINTER(_IpAdapterAddresses),
            ctypes.POINTER(wintypes.ULONG),
        ]
        self._get_adapters_addresses.restype = wintypes.ULONG
        self._free_mib_table = self._library.FreeMibTable
        self._free_mib_table.argtypes = [ctypes.c_void_p]
        self._free_mib_table.restype = None

    def read_interface_rows(self) -> tuple[InterfaceRow, ...]:
        table_pointer = ctypes.POINTER(_MibIfTable2)()
        result = int(self._get_if_table2(ctypes.byref(table_pointer)))
        if result != NO_ERROR:
            raise WindowsApiError("GetIfTable2", result)
        if not table_pointer:
            raise WindowsApiError("GetIfTable2", 13)

        try:
            entry_count = int(table_pointer.contents.NumEntries)
            first_row_address = ctypes.addressof(table_pointer.contents.Table)
            row_size = ctypes.sizeof(_MibIfRow2)
            return tuple(
                _convert_interface_row(
                    ctypes.cast(
                        first_row_address + index * row_size,
                        ctypes.POINTER(_MibIfRow2),
                    ).contents
                )
                for index in range(entry_count)
            )
        finally:
            self._free_mib_table(ctypes.cast(table_pointer, ctypes.c_void_p))

    def read_adapter_records(self) -> tuple[AdapterAddressRecord, ...]:
        buffer_size = wintypes.ULONG(INITIAL_ADAPTER_BUFFER_SIZE)
        buffer: ctypes.Array[ctypes.c_char] | None = None

        for _ in range(MAX_ADAPTER_BUFFER_ATTEMPTS):
            if buffer_size.value > MAX_ADAPTER_BUFFER_SIZE:
                raise WindowsApiError("GetAdaptersAddresses", ERROR_BUFFER_OVERFLOW)
            buffer = ctypes.create_string_buffer(buffer_size.value)
            adapter_pointer = ctypes.cast(buffer, ctypes.POINTER(_IpAdapterAddresses))
            result = int(
                self._get_adapters_addresses(
                    AF_UNSPEC,
                    GET_ADAPTER_FLAGS,
                    None,
                    adapter_pointer,
                    ctypes.byref(buffer_size),
                )
            )
            if result == NO_ERROR:
                return _convert_adapter_list(ctypes.addressof(adapter_pointer.contents))
            if result != ERROR_BUFFER_OVERFLOW:
                raise WindowsApiError("GetAdaptersAddresses", result)

        raise WindowsApiError("GetAdaptersAddresses", ERROR_BUFFER_OVERFLOW)


class WindowsInterfaceCollector:
    def __init__(self, backend: IpHelperBackend | None = None) -> None:
        self._backend = backend

    def collect(self) -> tuple[NetworkInterface, ...]:
        backend = self._backend or NativeIpHelperBackend()
        rows = backend.read_interface_rows()
        adapters = backend.read_adapter_records()
        return combine_ip_helper_records(rows, adapters)


def combine_ip_helper_records(
    rows: tuple[InterfaceRow, ...],
    adapters: tuple[AdapterAddressRecord, ...],
) -> tuple[NetworkInterface, ...]:
    adapters_by_id = {
        adapter.stable_id.casefold(): adapter
        for adapter in adapters
        if adapter.stable_id is not None
    }
    adapters_by_index = {adapter.interface_index: adapter for adapter in adapters}

    return tuple(
        _create_network_interface(
            row,
            _find_adapter_record(row, adapters_by_id, adapters_by_index),
        )
        for row in rows
    )


def _find_adapter_record(
    row: InterfaceRow,
    adapters_by_id: dict[str, AdapterAddressRecord],
    adapters_by_index: dict[int, AdapterAddressRecord],
) -> AdapterAddressRecord | None:
    if row.stable_id is not None:
        return adapters_by_id.get(row.stable_id.casefold())
    return adapters_by_index.get(row.interface_index)


def _create_network_interface(
    row: InterfaceRow,
    adapter: AdapterAddressRecord | None,
) -> NetworkInterface:
    stable_id = row.stable_id
    if stable_id is None and adapter is not None:
        stable_id = adapter.stable_id
    if stable_id is None:
        stable_id = f"ifindex:{row.interface_index}"

    alias = row.alias.strip()
    if not alias and adapter is not None and adapter.friendly_name:
        alias = adapter.friendly_name.strip()
    if not alias:
        alias = stable_id

    friendly_name = alias
    if adapter is not None and adapter.friendly_name:
        friendly_name = adapter.friendly_name.strip() or alias

    physical_address = row.physical_address
    if not physical_address and adapter is not None:
        physical_address = adapter.physical_address

    return NetworkInterface(
        interface_index=row.interface_index,
        stable_id=stable_id,
        alias=alias,
        friendly_name=friendly_name,
        description=row.description or (adapter.description if adapter else None),
        windows_interface_type=row.windows_interface_type,
        kind=_classify_interface(row.windows_interface_type, row.is_hardware),
        operational_state=row.operational_state,
        administrative_state=row.administrative_state,
        media_state=row.media_state,
        mac_address=_create_mac_address(physical_address),
        mtu=row.mtu or (adapter.mtu if adapter else None),
        receive_link_speed_bps=(
            row.receive_link_speed_bps or (adapter.receive_link_speed_bps if adapter else None)
        ),
        transmit_link_speed_bps=(
            row.transmit_link_speed_bps or (adapter.transmit_link_speed_bps if adapter else None)
        ),
        is_hardware=row.is_hardware,
        is_virtual=not row.is_hardware,
    )


def _convert_interface_row(row: _MibIfRow2) -> InterfaceRow:
    physical_length = min(int(row.PhysicalAddressLength), IF_MAX_PHYS_ADDRESS_LENGTH)
    return InterfaceRow(
        interface_index=int(row.InterfaceIndex),
        stable_id=_guid_to_stable_id(row.InterfaceGuid),
        alias=str(row.Alias),
        description=_optional_text(str(row.Description)),
        windows_interface_type=int(row.Type),
        operational_state=_convert_operational_state(int(row.OperStatus)),
        administrative_state=_convert_administrative_state(int(row.AdminStatus)),
        media_state=_convert_media_state(int(row.MediaConnectState)),
        physical_address=bytes(row.PhysicalAddress[:physical_length]),
        mtu=_positive_or_none(int(row.Mtu)),
        receive_link_speed_bps=_positive_or_none(int(row.ReceiveLinkSpeed)),
        transmit_link_speed_bps=_positive_or_none(int(row.TransmitLinkSpeed)),
        is_hardware=bool(row.InterfaceAndOperStatusFlags & 0x01),
    )


def _convert_adapter_list(first_adapter_address: int) -> tuple[AdapterAddressRecord, ...]:
    adapters: list[AdapterAddressRecord] = []
    current_address: int | None = first_adapter_address
    while current_address is not None:
        adapter = ctypes.cast(
            ctypes.c_void_p(current_address),
            ctypes.POINTER(_IpAdapterAddresses),
        ).contents
        physical_length = min(int(adapter.PhysicalAddressLength), MAX_ADAPTER_ADDRESS_LENGTH)
        adapter_name = adapter.AdapterName.decode("ascii") if adapter.AdapterName else None
        adapters.append(
            AdapterAddressRecord(
                interface_index=int(adapter.Header.Fields.IfIndex),
                stable_id=(normalize_stable_id(adapter_name) if adapter_name else None),
                friendly_name=_optional_text(adapter.FriendlyName),
                description=_optional_text(adapter.Description),
                physical_address=bytes(adapter.PhysicalAddress[:physical_length]),
                mtu=_positive_or_none(int(adapter.Mtu)),
                receive_link_speed_bps=_positive_or_none(int(adapter.ReceiveLinkSpeed)),
                transmit_link_speed_bps=_positive_or_none(int(adapter.TransmitLinkSpeed)),
            )
        )
        current_address = ctypes.cast(adapter.Next, ctypes.c_void_p).value
    return tuple(adapters)


def _guid_to_stable_id(guid: _Guid) -> str | None:
    raw_guid = ctypes.string_at(ctypes.byref(guid), ctypes.sizeof(guid))
    if not any(raw_guid):
        return None
    return str(UUID(bytes_le=raw_guid))


def _classify_interface(windows_interface_type: int, is_hardware: bool) -> InterfaceKind:
    known_types = {
        6: InterfaceKind.ETHERNET,
        24: InterfaceKind.LOOPBACK,
        71: InterfaceKind.WIFI,
        131: InterfaceKind.TUNNEL,
    }
    kind = known_types.get(windows_interface_type)
    if kind is not None:
        return kind
    if not is_hardware:
        return InterfaceKind.VIRTUAL
    return InterfaceKind.OTHER


def _convert_operational_state(value: int) -> OperationalState:
    states = {
        1: OperationalState.UP,
        2: OperationalState.DOWN,
        3: OperationalState.TESTING,
        5: OperationalState.DORMANT,
        6: OperationalState.NOT_PRESENT,
        7: OperationalState.LOWER_LAYER_DOWN,
    }
    return states.get(value, OperationalState.UNKNOWN)


def _convert_administrative_state(value: int) -> AdministrativeState:
    states = {
        1: AdministrativeState.UP,
        2: AdministrativeState.DOWN,
        3: AdministrativeState.TESTING,
    }
    return states.get(value, AdministrativeState.UNKNOWN)


def _convert_media_state(value: int) -> MediaState:
    states = {1: MediaState.CONNECTED, 2: MediaState.DISCONNECTED}
    return states.get(value, MediaState.UNKNOWN)


def _create_mac_address(value: bytes) -> MacAddress | None:
    if not value:
        return None
    try:
        return MacAddress(value)
    except ValueError:
        return None


def _positive_or_none(value: int) -> int | None:
    return value if value > 0 else None


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None
