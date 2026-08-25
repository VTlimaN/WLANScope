from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass
from types import TracebackType
from typing import Literal, Protocol
from uuid import UUID

from wlanscope.domain.wifi import (
    CurrentWifiSnapshot,
    NativeWifiDataError,
    WifiAccessDeniedError,
    WifiAuthentication,
    WifiBssid,
    WifiCipher,
    WifiConnection,
    WifiConnectionMode,
    WifiInterfaceSnapshot,
    WifiInterfaceState,
    WifiIssue,
    WifiIssueCode,
    WifiPhyType,
    WifiSecurity,
    WifiSsid,
    WindowsWlanApiError,
    WlanApiUnavailableError,
    WlanServiceUnavailableError,
)

_ERROR_SUCCESS = 0
_ERROR_ACCESS_DENIED = 5
_ERROR_NOT_SUPPORTED = 50
_ERROR_CALL_NOT_IMPLEMENTED = 120
_ERROR_SERVICE_NOT_ACTIVE = 1062
_ERROR_INVALID_STATE = 5023
_WLAN_CLIENT_VERSION = 2
_WLAN_CURRENT_CONNECTION_OPCODE = 7
_WLAN_MAX_NAME_LENGTH = 256
_DOT11_SSID_MAX_LENGTH = 32
_MAX_INTERFACE_COUNT = 1024


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _Dot11Ssid(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("ssid", ctypes.c_ubyte * _DOT11_SSID_MAX_LENGTH),
    ]


class _WlanInterfaceInfo(ctypes.Structure):
    _fields_ = [
        ("interface_guid", _Guid),
        ("description", wintypes.WCHAR * _WLAN_MAX_NAME_LENGTH),
        ("state", wintypes.DWORD),
    ]


class _WlanInterfaceInfoList(ctypes.Structure):
    _fields_ = [
        ("number_of_items", wintypes.DWORD),
        ("index", wintypes.DWORD),
        ("items", _WlanInterfaceInfo * 1),
    ]


class _WlanAssociationAttributes(ctypes.Structure):
    _fields_ = [
        ("ssid", _Dot11Ssid),
        ("bss_type", wintypes.DWORD),
        ("bssid", ctypes.c_ubyte * 6),
        ("phy_type", wintypes.DWORD),
        ("phy_index", wintypes.DWORD),
        ("signal_quality", wintypes.ULONG),
        ("receive_rate_kbps", wintypes.ULONG),
        ("transmit_rate_kbps", wintypes.ULONG),
    ]


class _WlanSecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("security_enabled", wintypes.BOOL),
        ("one_x_enabled", wintypes.BOOL),
        ("authentication", wintypes.DWORD),
        ("cipher", wintypes.DWORD),
    ]


class _WlanConnectionAttributes(ctypes.Structure):
    _fields_ = [
        ("state", wintypes.DWORD),
        ("connection_mode", wintypes.DWORD),
        ("profile_name", wintypes.WCHAR * _WLAN_MAX_NAME_LENGTH),
        ("association", _WlanAssociationAttributes),
        ("security", _WlanSecurityAttributes),
    ]


class WlanBindings(Protocol):
    def open_handle(self) -> tuple[int, int]: ...

    def close_handle(self, handle: int) -> int: ...

    def enumerate_interfaces(self, handle: int) -> tuple[int, int]: ...

    def query_current_connection(self, handle: int, interface_id: str) -> tuple[int, int, int]: ...

    def free_memory(self, address: int) -> None: ...


class NativeWlanBindings:
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise WlanApiUnavailableError("The Native WLAN API is available only on Windows")
        try:
            library = ctypes.WinDLL("wlanapi.dll", use_last_error=True)
        except OSError as error:
            raise WlanApiUnavailableError("Windows could not load wlanapi.dll") from error

        self._open = library.WlanOpenHandle
        self._open.argtypes = [
            wintypes.DWORD,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self._open.restype = wintypes.DWORD

        self._close = library.WlanCloseHandle
        self._close.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        self._close.restype = wintypes.DWORD

        self._enumerate = library.WlanEnumInterfaces
        self._enumerate.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._enumerate.restype = wintypes.DWORD

        self._query = library.WlanQueryInterface
        self._query.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_Guid),
            wintypes.DWORD,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._query.restype = wintypes.DWORD

        self._scan = library.WlanScan
        self._scan.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_Guid),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.LPVOID,
        ]
        self._scan.restype = wintypes.DWORD

        self._available_networks = library.WlanGetAvailableNetworkList
        self._available_networks.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_Guid),
            wintypes.DWORD,
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._available_networks.restype = wintypes.DWORD

        self._bss_list = library.WlanGetNetworkBssList
        self._bss_list.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_Guid),
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._bss_list.restype = wintypes.DWORD

        self._register_notification = library.WlanRegisterNotification
        self._register_notification.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.BOOL,
            ctypes.c_void_p,
            wintypes.LPVOID,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._register_notification.restype = wintypes.DWORD

        self._free = library.WlanFreeMemory
        self._free.argtypes = [wintypes.LPVOID]
        self._free.restype = None

    def open_handle(self) -> tuple[int, int]:
        negotiated_version = wintypes.DWORD()
        handle = wintypes.HANDLE()
        result = self._open(
            _WLAN_CLIENT_VERSION,
            None,
            ctypes.byref(negotiated_version),
            ctypes.byref(handle),
        )
        return int(result), int(handle.value or 0)

    def close_handle(self, handle: int) -> int:
        return int(self._close(wintypes.HANDLE(handle), None))

    def enumerate_interfaces(self, handle: int) -> tuple[int, int]:
        address = ctypes.c_void_p()
        result = self._enumerate(wintypes.HANDLE(handle), None, ctypes.byref(address))
        return int(result), int(address.value or 0)

    def query_current_connection(self, handle: int, interface_id: str) -> tuple[int, int, int]:
        guid = _guid_from_text(interface_id)
        data_size = wintypes.DWORD()
        address = ctypes.c_void_p()
        opcode_value_type = wintypes.DWORD()
        result = self._query(
            wintypes.HANDLE(handle),
            ctypes.byref(guid),
            _WLAN_CURRENT_CONNECTION_OPCODE,
            None,
            ctypes.byref(data_size),
            ctypes.byref(address),
            ctypes.byref(opcode_value_type),
        )
        return int(result), int(address.value or 0), int(data_size.value)

    def free_memory(self, address: int) -> None:
        self._free(ctypes.c_void_p(address))

    def scan(self, handle: int, interface_id: str) -> int:
        guid = _guid_from_text(interface_id)
        return int(
            self._scan(
                wintypes.HANDLE(handle),
                ctypes.byref(guid),
                None,
                None,
                None,
            )
        )

    def get_available_networks(self, handle: int, interface_id: str) -> tuple[int, int]:
        guid = _guid_from_text(interface_id)
        address = ctypes.c_void_p()
        result = self._available_networks(
            wintypes.HANDLE(handle),
            ctypes.byref(guid),
            0,
            None,
            ctypes.byref(address),
        )
        return int(result), int(address.value or 0)

    def get_bss_list(self, handle: int, interface_id: str) -> tuple[int, int]:
        guid = _guid_from_text(interface_id)
        address = ctypes.c_void_p()
        result = self._bss_list(
            wintypes.HANDLE(handle),
            ctypes.byref(guid),
            None,
            3,
            False,
            None,
            ctypes.byref(address),
        )
        return int(result), int(address.value or 0)

    def register_notification(
        self,
        handle: int,
        source: int,
        callback_address: int,
    ) -> tuple[int, int]:
        previous_source = wintypes.DWORD()
        result = self._register_notification(
            wintypes.HANDLE(handle),
            source,
            True,
            ctypes.c_void_p(callback_address),
            None,
            None,
            ctypes.byref(previous_source),
        )
        return int(result), int(previous_source.value)


@dataclass(frozen=True, slots=True)
class _InterfaceRecord:
    interface_id: str
    description: str
    state: WifiInterfaceState


class NativeWifiSession:
    def __init__(self, bindings: WlanBindings) -> None:
        self._bindings = bindings
        self._handle: int | None = None

    def __enter__(self) -> NativeWifiSession:
        result, handle = self._bindings.open_handle()
        _raise_for_result("WlanOpenHandle", result)
        if not handle:
            raise NativeWifiDataError("WlanOpenHandle returned an invalid handle")
        self._handle = handle
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        handle = self._handle
        self._handle = None
        if handle is not None:
            result = self._bindings.close_handle(handle)
            if exception_type is None:
                _raise_for_result("WlanCloseHandle", result)
        return False

    def enumerate_interfaces(self) -> tuple[_InterfaceRecord, ...]:
        result, address = self._bindings.enumerate_interfaces(self._require_handle())
        if result != _ERROR_SUCCESS and address:
            self._bindings.free_memory(address)
        _raise_for_result("WlanEnumInterfaces", result)
        if not address:
            raise NativeWifiDataError("WlanEnumInterfaces returned an invalid buffer")
        try:
            return _read_interface_records(address)
        finally:
            self._bindings.free_memory(address)

    def query_current_connection(self, interface_id: str) -> WifiConnection | None:
        result, address, data_size = self._bindings.query_current_connection(
            self._require_handle(), interface_id
        )
        if result == _ERROR_INVALID_STATE:
            if address:
                self._bindings.free_memory(address)
            return None
        if result != _ERROR_SUCCESS and address:
            self._bindings.free_memory(address)
        _raise_for_result("WlanQueryInterface", result)
        if not address or data_size < ctypes.sizeof(_WlanConnectionAttributes):
            if address:
                self._bindings.free_memory(address)
            raise NativeWifiDataError("WlanQueryInterface returned an invalid buffer")
        try:
            attributes = _WlanConnectionAttributes.from_address(address)
            return _convert_connection(attributes)
        finally:
            self._bindings.free_memory(address)

    def _require_handle(self) -> int:
        if self._handle is None:
            raise RuntimeError("The Native WLAN session is not open")
        return self._handle


class NativeWifiCollector:
    def __init__(self, bindings: WlanBindings | None = None) -> None:
        self._bindings = bindings

    def collect(self) -> CurrentWifiSnapshot:
        bindings = self._bindings or NativeWlanBindings()
        interfaces: list[WifiInterfaceSnapshot] = []
        issues: list[WifiIssue] = []
        with NativeWifiSession(bindings) as session:
            for record in session.enumerate_interfaces():
                connection = None
                if record.state.is_connected:
                    try:
                        connection = session.query_current_connection(record.interface_id)
                    except WifiAccessDeniedError:
                        issues.append(_access_denied_issue(record.interface_id))
                    except (NativeWifiDataError, WindowsWlanApiError) as error:
                        issues.append(_connection_issue(record.interface_id, str(error)))
                    if connection is None and not _has_issue(issues, record.interface_id):
                        issues.append(
                            _connection_issue(
                                record.interface_id,
                                "Windows no longer reports an active connection "
                                "for this interface.",
                            )
                        )
                interfaces.append(
                    WifiInterfaceSnapshot(
                        interface_id=record.interface_id,
                        description=record.description,
                        state=record.state,
                        connection=connection,
                    )
                )
        return CurrentWifiSnapshot(tuple(interfaces), tuple(issues))


def _read_interface_records(address: int) -> tuple[_InterfaceRecord, ...]:
    header = _WlanInterfaceInfoList.from_address(address)
    count = int(header.number_of_items)
    if count > _MAX_INTERFACE_COUNT:
        raise NativeWifiDataError("WlanEnumInterfaces returned an unreasonable interface count")
    item_address = address + _WlanInterfaceInfoList.items.offset
    return tuple(
        _convert_interface(
            _WlanInterfaceInfo.from_address(
                item_address + index * ctypes.sizeof(_WlanInterfaceInfo)
            )
        )
        for index in range(count)
    )


def _convert_interface(info: _WlanInterfaceInfo) -> _InterfaceRecord:
    description = str(info.description).rstrip("\x00").strip()
    if not description:
        raise NativeWifiDataError("Windows returned a Wi-Fi interface without a description")
    return _InterfaceRecord(
        interface_id=_guid_to_text(info.interface_guid),
        description=description,
        state=WifiInterfaceState(int(info.state)),
    )


def _convert_connection(attributes: _WlanConnectionAttributes) -> WifiConnection:
    ssid_length = int(attributes.association.ssid.length)
    if ssid_length > _DOT11_SSID_MAX_LENGTH:
        raise NativeWifiDataError("Windows returned an invalid SSID length")
    bssid = bytes(attributes.association.bssid)
    try:
        return WifiConnection(
            state=WifiInterfaceState(int(attributes.state)),
            mode=WifiConnectionMode(int(attributes.connection_mode)),
            profile_name=str(attributes.profile_name).rstrip("\x00") or None,
            ssid=WifiSsid(bytes(attributes.association.ssid.ssid[:ssid_length])),
            bssid=WifiBssid(bssid),
            phy_type=WifiPhyType(int(attributes.association.phy_type)),
            signal_quality=int(attributes.association.signal_quality),
            receive_rate_kbps=_positive_or_none(attributes.association.receive_rate_kbps),
            transmit_rate_kbps=_positive_or_none(attributes.association.transmit_rate_kbps),
            security=WifiSecurity(
                enabled=bool(attributes.security.security_enabled),
                authentication=WifiAuthentication(int(attributes.security.authentication)),
                cipher=WifiCipher(int(attributes.security.cipher)),
            ),
        )
    except ValueError as error:
        raise NativeWifiDataError(
            f"Windows returned invalid Wi-Fi connection data: {error}"
        ) from error


def _positive_or_none(value: int) -> int | None:
    return int(value) or None


def _guid_from_text(value: str) -> _Guid:
    raw = UUID(value).bytes_le
    return _Guid(
        int.from_bytes(raw[0:4], "little"),
        int.from_bytes(raw[4:6], "little"),
        int.from_bytes(raw[6:8], "little"),
        (ctypes.c_ubyte * 8).from_buffer_copy(raw[8:]),
    )


def _guid_to_text(value: _Guid) -> str:
    raw = (
        int(value.data1).to_bytes(4, "little")
        + int(value.data2).to_bytes(2, "little")
        + int(value.data3).to_bytes(2, "little")
        + bytes(value.data4)
    )
    return str(UUID(bytes_le=raw))


def _raise_for_result(operation: str, result: int) -> None:
    if result == _ERROR_SUCCESS:
        return
    if result == _ERROR_ACCESS_DENIED:
        raise WifiAccessDeniedError(
            "Windows denied access to Wi-Fi connection details. "
            "Location access may be required by the operating system."
        )
    if result == _ERROR_SERVICE_NOT_ACTIVE:
        raise WlanServiceUnavailableError("The Windows WLAN service is not running")
    if result in {_ERROR_NOT_SUPPORTED, _ERROR_CALL_NOT_IMPLEMENTED}:
        raise WlanApiUnavailableError(f"{operation} is not supported by this Windows system")
    raise WindowsWlanApiError(operation, result)


def _access_denied_issue(interface_id: str) -> WifiIssue:
    return WifiIssue(
        WifiIssueCode.ACCESS_DENIED,
        "Windows denied access to Wi-Fi connection details. "
        "Location access may be required by the operating system.",
        interface_id,
    )


def _connection_issue(interface_id: str, detail: str) -> WifiIssue:
    return WifiIssue(WifiIssueCode.CONNECTION_UNAVAILABLE, detail, interface_id)


def _has_issue(issues: list[WifiIssue], interface_id: str) -> bool:
    return any(issue.interface_id == interface_id for issue in issues)
