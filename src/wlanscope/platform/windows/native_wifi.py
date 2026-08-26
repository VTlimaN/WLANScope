from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass
from types import TracebackType
from typing import Literal, Protocol, runtime_checkable
from uuid import UUID

from wlanscope.domain.wifi import (
    CurrentWifiSnapshot,
    NativeWifiDataError,
    WifiAccessDeniedError,
    WifiAuthCipherCapabilities,
    WifiAuthCipherPair,
    WifiAuthentication,
    WifiBssid,
    WifiBssType,
    WifiCapabilityState,
    WifiCipher,
    WifiConnection,
    WifiConnectionMode,
    WifiInterfaceCapabilities,
    WifiInterfaceSnapshot,
    WifiInterfaceState,
    WifiIssue,
    WifiIssueCode,
    WifiPhyRadioState,
    WifiPhyStatistics,
    WifiPhyType,
    WifiRadioState,
    WifiSecurity,
    WifiSsid,
    WifiStatistics,
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
_WLAN_RADIO_STATE_OPCODE = 4
_WLAN_CHANNEL_NUMBER_OPCODE = 8
_WLAN_INFRASTRUCTURE_AUTH_CIPHER_OPCODE = 9
_WLAN_ADHOC_AUTH_CIPHER_OPCODE = 10
_WLAN_OPERATION_MODE_OPCODE = 12
_WLAN_MFP_CAPABLE_OPCODE = 16
_WLAN_STATISTICS_OPCODE = 0x10000101
_WLAN_RSSI_OPCODE = 0x10000102
_WLAN_MAX_NAME_LENGTH = 256
_WLAN_MAX_PHY_INDEX = 64
_WLAN_MAX_AUTH_CIPHER_PAIRS = 1_024
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


class _WlanInterfaceCapability(ctypes.Structure):
    _fields_ = [
        ("interface_type", wintypes.DWORD),
        ("dot11d_supported", wintypes.BOOL),
        ("maximum_desired_ssids", wintypes.DWORD),
        ("maximum_desired_bssids", wintypes.DWORD),
        ("number_of_supported_phys", wintypes.DWORD),
        ("phy_types", wintypes.DWORD * _WLAN_MAX_PHY_INDEX),
    ]


class _WlanPhyRadioState(ctypes.Structure):
    _fields_ = [
        ("phy_index", wintypes.DWORD),
        ("software_state", wintypes.DWORD),
        ("hardware_state", wintypes.DWORD),
    ]


class _WlanRadioState(ctypes.Structure):
    _fields_ = [
        ("number_of_phys", wintypes.DWORD),
        ("states", _WlanPhyRadioState * _WLAN_MAX_PHY_INDEX),
    ]


class _Dot11AuthCipherPair(ctypes.Structure):
    _fields_ = [("authentication", wintypes.DWORD), ("cipher", wintypes.DWORD)]


class _WlanAuthCipherPairList(ctypes.Structure):
    _fields_ = [("number_of_items", wintypes.DWORD), ("items", _Dot11AuthCipherPair * 1)]


class _WlanMacFrameStatistics(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "transmitted",
            "received",
            "wep_excluded",
            "tkip_mic_failures",
            "tkip_replays",
            "tkip_icv_errors",
            "ccmp_replays",
            "ccmp_decrypt_errors",
            "wep_undecryptable",
            "wep_icv_errors",
            "decrypt_successes",
            "decrypt_failures",
        )
    ]


class _WlanPhyFrameStatistics(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "transmitted",
            "multicast_transmitted",
            "failed",
            "retry",
            "multiple_retry",
            "maximum_transmit_lifetime_exceeded",
            "transmitted_fragments",
            "rts_successes",
            "rts_failures",
            "ack_failures",
            "received",
            "multicast_received",
            "promiscuous_received",
            "maximum_receive_lifetime_exceeded",
            "duplicates",
            "received_fragments",
            "promiscuous_received_fragments",
            "fcs_errors",
        )
    ]


class _WlanStatisticsHeader(ctypes.Structure):
    _fields_ = [
        ("four_way_handshake_failures", ctypes.c_ulonglong),
        ("tkip_countermeasures", ctypes.c_ulonglong),
        ("reserved", ctypes.c_ulonglong),
        ("unicast", _WlanMacFrameStatistics),
        ("multicast", _WlanMacFrameStatistics),
        ("number_of_phys", wintypes.DWORD),
    ]


class WlanBindings(Protocol):
    def open_handle(self) -> tuple[int, int]: ...

    def close_handle(self, handle: int) -> int: ...

    def enumerate_interfaces(self, handle: int) -> tuple[int, int]: ...

    def query_current_connection(self, handle: int, interface_id: str) -> tuple[int, int, int]: ...

    def free_memory(self, address: int) -> None: ...


@runtime_checkable
class DeepWlanBindings(WlanBindings, Protocol):
    def get_interface_capability(self, handle: int, interface_id: str) -> tuple[int, int]: ...

    def query_interface(
        self, handle: int, interface_id: str, opcode: int
    ) -> tuple[int, int, int]: ...


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

        self._capability = library.WlanGetInterfaceCapability
        self._capability.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_Guid),
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._capability.restype = wintypes.DWORD

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
        return self.query_interface(handle, interface_id, _WLAN_CURRENT_CONNECTION_OPCODE)

    def query_interface(self, handle: int, interface_id: str, opcode: int) -> tuple[int, int, int]:
        guid = _guid_from_text(interface_id)
        data_size = wintypes.DWORD()
        address = ctypes.c_void_p()
        opcode_value_type = wintypes.DWORD()
        result = self._query(
            wintypes.HANDLE(handle),
            ctypes.byref(guid),
            opcode,
            None,
            ctypes.byref(data_size),
            ctypes.byref(address),
            ctypes.byref(opcode_value_type),
        )
        return int(result), int(address.value or 0), int(data_size.value)

    def get_interface_capability(self, handle: int, interface_id: str) -> tuple[int, int]:
        guid = _guid_from_text(interface_id)
        address = ctypes.c_void_p()
        result = self._capability(
            wintypes.HANDLE(handle), ctypes.byref(guid), None, ctypes.byref(address)
        )
        return int(result), int(address.value or 0)

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


@dataclass(frozen=True, slots=True)
class _InterfaceDetails:
    capabilities: WifiInterfaceCapabilities | None = None
    channel_number: int | None = None
    rssi_dbm: int | None = None
    operation_mode: int | None = None
    mfp_capable: bool | None = None
    radio_states: tuple[WifiPhyRadioState, ...] = ()
    statistics: WifiStatistics | None = None


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

    def query_details(self, interface_id: str) -> _InterfaceDetails:
        if not isinstance(self._bindings, DeepWlanBindings):
            return _InterfaceDetails()
        capabilities = self._query_capabilities(interface_id)
        return _InterfaceDetails(
            capabilities=capabilities,
            channel_number=self._query_scalar(interface_id, _WLAN_CHANNEL_NUMBER_OPCODE),
            rssi_dbm=self._query_scalar(interface_id, _WLAN_RSSI_OPCODE, signed=True),
            operation_mode=self._query_scalar(interface_id, _WLAN_OPERATION_MODE_OPCODE),
            mfp_capable=self._query_boolean(interface_id, _WLAN_MFP_CAPABLE_OPCODE),
            radio_states=self._query_radio_states(interface_id),
            statistics=self._query_statistics(interface_id),
        )

    def _query_capabilities(self, interface_id: str) -> WifiInterfaceCapabilities | None:
        bindings = self._deep_bindings()
        result, address = bindings.get_interface_capability(self._require_handle(), interface_id)
        if result in {_ERROR_NOT_SUPPORTED, _ERROR_CALL_NOT_IMPLEMENTED}:
            if address:
                bindings.free_memory(address)
            return None
        if result != _ERROR_SUCCESS or not address:
            if address:
                bindings.free_memory(address)
            return None
        try:
            value = _WlanInterfaceCapability.from_address(address)
            count = int(value.number_of_supported_phys)
            if count > _WLAN_MAX_PHY_INDEX:
                raise NativeWifiDataError("Windows returned an invalid supported PHY count")
            return WifiInterfaceCapabilities(
                int(value.interface_type),
                bool(value.dot11d_supported),
                int(value.maximum_desired_ssids),
                int(value.maximum_desired_bssids),
                tuple(WifiPhyType(int(value.phy_types[index])) for index in range(count)),
                self._query_auth_cipher_pairs(
                    interface_id, _WLAN_INFRASTRUCTURE_AUTH_CIPHER_OPCODE
                ),
                self._query_auth_cipher_pairs(interface_id, _WLAN_ADHOC_AUTH_CIPHER_OPCODE),
            )
        finally:
            bindings.free_memory(address)

    def _query_auth_cipher_pairs(
        self, interface_id: str, opcode: int
    ) -> WifiAuthCipherCapabilities:
        bindings = self._deep_bindings()
        result, address, size = bindings.query_interface(
            self._require_handle(), interface_id, opcode
        )
        if result in {_ERROR_NOT_SUPPORTED, _ERROR_CALL_NOT_IMPLEMENTED}:
            if address:
                bindings.free_memory(address)
            return WifiAuthCipherCapabilities(WifiCapabilityState.UNSUPPORTED)
        if result != _ERROR_SUCCESS or not address:
            if address:
                bindings.free_memory(address)
            return WifiAuthCipherCapabilities(WifiCapabilityState.UNAVAILABLE)
        try:
            if size < _WlanAuthCipherPairList.items.offset:
                raise NativeWifiDataError("Windows returned a truncated auth/cipher pair list")
            value = _WlanAuthCipherPairList.from_address(address)
            count = int(value.number_of_items)
            required_size = _WlanAuthCipherPairList.items.offset + count * ctypes.sizeof(
                _Dot11AuthCipherPair
            )
            if count > _WLAN_MAX_AUTH_CIPHER_PAIRS or required_size > size:
                raise NativeWifiDataError("Windows returned an invalid auth/cipher pair list")
            first_item = address + _WlanAuthCipherPairList.items.offset
            pairs: list[WifiAuthCipherPair] = []
            for index in range(count):
                item = _Dot11AuthCipherPair.from_address(
                    first_item + index * ctypes.sizeof(_Dot11AuthCipherPair)
                )
                pairs.append(
                    WifiAuthCipherPair(
                        WifiAuthentication(int(item.authentication)),
                        WifiCipher(int(item.cipher)),
                    )
                )
            return WifiAuthCipherCapabilities(WifiCapabilityState.AVAILABLE, tuple(pairs))
        finally:
            bindings.free_memory(address)

    def _query_scalar(self, interface_id: str, opcode: int, signed: bool = False) -> int | None:
        data = self._query_optional(interface_id, opcode, ctypes.sizeof(wintypes.DWORD))
        if data is None:
            return None
        address, _, bindings = data
        try:
            if signed:
                return int(wintypes.LONG.from_address(address).value)
            return int(wintypes.ULONG.from_address(address).value)
        finally:
            bindings.free_memory(address)

    def _query_boolean(self, interface_id: str, opcode: int) -> bool | None:
        value = self._query_scalar(interface_id, opcode)
        return None if value is None else bool(value)

    def _query_radio_states(self, interface_id: str) -> tuple[WifiPhyRadioState, ...]:
        data = self._query_optional(
            interface_id, _WLAN_RADIO_STATE_OPCODE, ctypes.sizeof(wintypes.DWORD)
        )
        if data is None:
            return ()
        address, _, bindings = data
        try:
            value = _WlanRadioState.from_address(address)
            count = int(value.number_of_phys)
            if count > _WLAN_MAX_PHY_INDEX:
                raise NativeWifiDataError("Windows returned an invalid radio PHY count")
            return tuple(
                WifiPhyRadioState(
                    int(value.states[index].phy_index),
                    WifiRadioState(int(value.states[index].software_state)),
                    WifiRadioState(int(value.states[index].hardware_state)),
                )
                for index in range(count)
            )
        finally:
            bindings.free_memory(address)

    def _query_statistics(self, interface_id: str) -> WifiStatistics | None:
        data = self._query_optional(
            interface_id, _WLAN_STATISTICS_OPCODE, ctypes.sizeof(_WlanStatisticsHeader)
        )
        if data is None:
            return None
        address, size, bindings = data
        try:
            value = _WlanStatisticsHeader.from_address(address)
            count = int(value.number_of_phys)
            required_size = ctypes.sizeof(_WlanStatisticsHeader) + count * ctypes.sizeof(
                _WlanPhyFrameStatistics
            )
            if count > _WLAN_MAX_PHY_INDEX or required_size > size:
                raise NativeWifiDataError("Windows returned an invalid WLAN PHY statistics list")
            first_counter = address + ctypes.sizeof(_WlanStatisticsHeader)
            phy_counters = tuple(
                _convert_phy_statistics(
                    index,
                    _WlanPhyFrameStatistics.from_address(
                        first_counter + index * ctypes.sizeof(_WlanPhyFrameStatistics)
                    ),
                )
                for index in range(count)
            )
            return WifiStatistics(
                int(value.four_way_handshake_failures),
                int(value.tkip_countermeasures),
                int(value.unicast.transmitted),
                int(value.unicast.received),
                int(value.multicast.transmitted),
                int(value.multicast.received),
                int(value.unicast.decrypt_successes + value.multicast.decrypt_successes),
                int(value.unicast.decrypt_failures + value.multicast.decrypt_failures),
                phy_counters,
            )
        finally:
            bindings.free_memory(address)

    def _query_optional(
        self, interface_id: str, opcode: int, minimum_size: int
    ) -> tuple[int, int, DeepWlanBindings] | None:
        bindings = self._deep_bindings()
        result, address, size = bindings.query_interface(
            self._require_handle(), interface_id, opcode
        )
        if result != _ERROR_SUCCESS:
            if address:
                bindings.free_memory(address)
            return None
        if not address:
            raise NativeWifiDataError("Windows returned an empty WLAN query buffer")
        if size < minimum_size:
            bindings.free_memory(address)
            raise NativeWifiDataError("Windows returned a truncated WLAN query buffer")
        return address, size, bindings

    def _deep_bindings(self) -> DeepWlanBindings:
        if not isinstance(self._bindings, DeepWlanBindings):
            raise RuntimeError("Deep WLAN bindings are unavailable")
        return self._bindings

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
                try:
                    details = session.query_details(record.interface_id)
                except NativeWifiDataError as error:
                    details = _InterfaceDetails()
                    issues.append(_connection_issue(record.interface_id, str(error)))
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
                        capabilities=details.capabilities,
                        channel_number=details.channel_number,
                        rssi_dbm=details.rssi_dbm,
                        operation_mode=details.operation_mode,
                        management_frame_protection_capable=details.mfp_capable,
                        radio_states=details.radio_states,
                        statistics=details.statistics,
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
            bss_type=WifiBssType(int(attributes.association.bss_type)),
        )
    except ValueError as error:
        raise NativeWifiDataError(
            f"Windows returned invalid Wi-Fi connection data: {error}"
        ) from error


def _convert_phy_statistics(index: int, value: _WlanPhyFrameStatistics) -> WifiPhyStatistics:
    return WifiPhyStatistics(
        phy_index=index,
        transmitted_frames=int(value.transmitted),
        received_frames=int(value.received),
        failed_transmissions=int(value.failed),
        retry_frames=int(value.retry),
        multiple_retry_frames=int(value.multiple_retry),
        fcs_errors=int(value.fcs_errors),
    )


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
