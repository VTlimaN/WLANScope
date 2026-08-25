from __future__ import annotations

import ctypes
from ctypes import wintypes
from threading import Event
from types import TracebackType
from typing import Literal, Protocol

from wlanscope.domain.nearby_wifi import (
    AvailableWifiNetwork,
    NativeNearbyWifiData,
    NearbyWifiInterface,
    WifiAccessPoint,
    WifiScanIssue,
    WifiScanIssueCode,
    WifiScanTimeoutError,
)
from wlanscope.domain.wifi import (
    NativeWifiDataError,
    WifiAccessDeniedError,
    WifiAuthentication,
    WifiBssid,
    WifiCipher,
    WifiPhyType,
    WifiSsid,
    WindowsWlanApiError,
    WlanApiUnavailableError,
    WlanServiceUnavailableError,
)
from wlanscope.platform.windows.native_wifi import (
    NativeWifiSession,
    NativeWlanBindings,
    WlanBindings,
    _Dot11Ssid,
    _Guid,
    _guid_to_text,
)

_ERROR_SUCCESS = 0
_ERROR_ACCESS_DENIED = 5
_ERROR_NOT_SUPPORTED = 50
_ERROR_CALL_NOT_IMPLEMENTED = 120
_ERROR_SERVICE_NOT_ACTIVE = 1062
_WLAN_NOTIFICATION_SOURCE_NONE = 0
_WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008
_WLAN_NOTIFICATION_ACM_SCAN_COMPLETE = 7
_WLAN_NOTIFICATION_ACM_SCAN_FAIL = 8
_WLAN_MAX_NAME_LENGTH = 256
_WLAN_MAX_PHY_TYPE_NUMBER = 8
_WLAN_RATE_SET_MAX_LENGTH = 126
_MAX_NETWORK_COUNT = 16_384
_MAX_BSS_COUNT = 65_536
DEFAULT_SCAN_TIMEOUT_SECONDS = 4.0


class _WlanNotificationData(ctypes.Structure):
    _fields_ = [
        ("notification_source", wintypes.DWORD),
        ("notification_code", wintypes.DWORD),
        ("interface_guid", _Guid),
        ("data_size", wintypes.DWORD),
        ("data", ctypes.c_void_p),
    ]


_NotificationCallback = ctypes.WINFUNCTYPE(
    None,
    ctypes.POINTER(_WlanNotificationData),
    ctypes.c_void_p,
)


class _WlanRateSet(ctypes.Structure):
    _fields_ = [
        ("rate_set_length", wintypes.ULONG),
        ("rate_set", wintypes.USHORT * _WLAN_RATE_SET_MAX_LENGTH),
    ]


class _WlanAvailableNetwork(ctypes.Structure):
    _fields_ = [
        ("profile_name", wintypes.WCHAR * _WLAN_MAX_NAME_LENGTH),
        ("ssid", _Dot11Ssid),
        ("bss_type", wintypes.DWORD),
        ("number_of_bssids", wintypes.ULONG),
        ("network_connectable", wintypes.BOOL),
        ("not_connectable_reason", wintypes.DWORD),
        ("number_of_phy_types", wintypes.ULONG),
        ("phy_types", wintypes.DWORD * _WLAN_MAX_PHY_TYPE_NUMBER),
        ("more_phy_types", wintypes.BOOL),
        ("signal_quality", wintypes.ULONG),
        ("security_enabled", wintypes.BOOL),
        ("authentication", wintypes.DWORD),
        ("cipher", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("reserved", wintypes.DWORD),
    ]


class _WlanAvailableNetworkList(ctypes.Structure):
    _fields_ = [
        ("number_of_items", wintypes.DWORD),
        ("index", wintypes.DWORD),
        ("items", _WlanAvailableNetwork * 1),
    ]


class _WlanBssEntry(ctypes.Structure):
    _fields_ = [
        ("ssid", _Dot11Ssid),
        ("phy_id", wintypes.ULONG),
        ("bssid", ctypes.c_ubyte * 6),
        ("bss_type", wintypes.DWORD),
        ("phy_type", wintypes.DWORD),
        ("rssi_dbm", wintypes.LONG),
        ("link_quality", wintypes.ULONG),
        ("in_reg_domain", wintypes.BYTE),
        ("beacon_period", wintypes.USHORT),
        ("timestamp_us", ctypes.c_ulonglong),
        ("host_timestamp", ctypes.c_ulonglong),
        ("capability_information", wintypes.USHORT),
        ("center_frequency_khz", wintypes.ULONG),
        ("rate_set", _WlanRateSet),
        ("information_element_offset", wintypes.ULONG),
        ("information_element_size", wintypes.ULONG),
    ]


class _WlanBssList(ctypes.Structure):
    _fields_ = [
        ("total_size", wintypes.DWORD),
        ("number_of_items", wintypes.DWORD),
        ("items", _WlanBssEntry * 1),
    ]


class WlanScanBindings(WlanBindings, Protocol):
    def scan(self, handle: int, interface_id: str) -> int: ...

    def get_available_networks(self, handle: int, interface_id: str) -> tuple[int, int]: ...

    def get_bss_list(self, handle: int, interface_id: str) -> tuple[int, int]: ...

    def register_notification(
        self,
        handle: int,
        source: int,
        callback_address: int,
    ) -> tuple[int, int]: ...


class _NotificationRegistration:
    def __init__(
        self,
        bindings: WlanScanBindings,
        handle: int,
        callback_address: int,
    ) -> None:
        self._bindings = bindings
        self._handle = handle
        self._callback_address = callback_address

    def __enter__(self) -> None:
        result, _ = self._bindings.register_notification(
            self._handle,
            _WLAN_NOTIFICATION_SOURCE_ACM,
            self._callback_address,
        )
        _raise_scan_result("WlanRegisterNotification", result)

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        result, _ = self._bindings.register_notification(
            self._handle,
            _WLAN_NOTIFICATION_SOURCE_NONE,
            0,
        )
        if exception_type is None:
            _raise_scan_result("WlanRegisterNotification cleanup", result)
        return False


class NativeWifiScanSession(NativeWifiSession):
    def __init__(self, bindings: WlanScanBindings, timeout_seconds: float) -> None:
        super().__init__(bindings)
        if timeout_seconds <= 0:
            raise ValueError("Scan timeout must be positive")
        self._scan_bindings = bindings
        self._timeout_seconds = timeout_seconds

    def __enter__(self) -> NativeWifiScanSession:
        super().__enter__()
        return self

    def scan_and_wait(self, interface_id: str) -> None:
        completed = Event()
        failure_codes: list[int] = []

        def receive_notification(
            data_pointer: ctypes.c_void_p,
            context: ctypes.c_void_p,
        ) -> None:
            if not data_pointer:
                return
            data = ctypes.cast(
                data_pointer,
                ctypes.POINTER(_WlanNotificationData),
            ).contents
            if int(data.notification_source) != _WLAN_NOTIFICATION_SOURCE_ACM:
                return
            if _guid_to_text(data.interface_guid) != interface_id:
                return
            code = int(data.notification_code)
            if code == _WLAN_NOTIFICATION_ACM_SCAN_FAIL:
                failure_codes.append(_read_scan_failure_code(data))
                completed.set()
            elif code == _WLAN_NOTIFICATION_ACM_SCAN_COMPLETE:
                completed.set()

        callback = _NotificationCallback(receive_notification)
        callback_address = ctypes.cast(callback, ctypes.c_void_p).value or 0
        handle = self._require_handle()
        with _NotificationRegistration(self._scan_bindings, handle, callback_address):
            _raise_scan_result("WlanScan", self._scan_bindings.scan(handle, interface_id))
            if not completed.wait(self._timeout_seconds):
                raise WifiScanTimeoutError(
                    f"Wi-Fi scan timed out after {self._timeout_seconds:g} seconds"
                )
            if failure_codes:
                raise WindowsWlanApiError("WlanScan notification", failure_codes[0])

    def available_networks(self, interface_id: str) -> tuple[AvailableWifiNetwork, ...]:
        result, address = self._scan_bindings.get_available_networks(
            self._require_handle(), interface_id
        )
        _release_error_buffer(self._scan_bindings, result, address)
        _raise_scan_result("WlanGetAvailableNetworkList", result)
        if not address:
            raise NativeWifiDataError("WlanGetAvailableNetworkList returned an invalid buffer")
        try:
            return _read_available_networks(address, interface_id)
        finally:
            self._scan_bindings.free_memory(address)

    def access_points(self, interface_id: str) -> tuple[WifiAccessPoint, ...]:
        result, address = self._scan_bindings.get_bss_list(self._require_handle(), interface_id)
        _release_error_buffer(self._scan_bindings, result, address)
        _raise_scan_result("WlanGetNetworkBssList", result)
        if not address:
            raise NativeWifiDataError("WlanGetNetworkBssList returned an invalid buffer")
        try:
            return _read_access_points(address, interface_id)
        finally:
            self._scan_bindings.free_memory(address)


class NativeNearbyWifiCollector:
    def __init__(
        self,
        bindings: WlanScanBindings | None = None,
        timeout_seconds: float = DEFAULT_SCAN_TIMEOUT_SECONDS,
    ) -> None:
        self._bindings = bindings
        self._timeout_seconds = timeout_seconds

    def collect(self) -> NativeNearbyWifiData:
        bindings = self._bindings or NativeWlanBindings()
        interfaces: list[NearbyWifiInterface] = []
        networks: list[AvailableWifiNetwork] = []
        access_points: list[WifiAccessPoint] = []
        issues: list[WifiScanIssue] = []
        with NativeWifiScanSession(bindings, self._timeout_seconds) as session:
            records = session.enumerate_interfaces()
            for record in records:
                interfaces.append(NearbyWifiInterface(record.interface_id, record.description))
                issues.extend(_request_scan(session, record.interface_id))
                collected_networks, network_issues = _collect_available_networks(
                    session, record.interface_id
                )
                collected_access_points, bss_issues = _collect_access_points(
                    session, record.interface_id
                )
                networks.extend(collected_networks)
                access_points.extend(collected_access_points)
                issues.extend(network_issues)
                issues.extend(bss_issues)
        return NativeNearbyWifiData(
            tuple(interfaces),
            tuple(networks),
            tuple(access_points),
            _deduplicate_issues(issues),
        )


def _request_scan(
    session: NativeWifiScanSession,
    interface_id: str,
) -> tuple[WifiScanIssue, ...]:
    try:
        session.scan_and_wait(interface_id)
    except WifiAccessDeniedError as error:
        return (_issue(WifiScanIssueCode.ACCESS_DENIED, interface_id, str(error)),)
    except WifiScanTimeoutError as error:
        return (_issue(WifiScanIssueCode.TIMEOUT, interface_id, str(error)),)
    except (NativeWifiDataError, WindowsWlanApiError) as error:
        return (_issue(WifiScanIssueCode.SCAN_FAILED, interface_id, str(error)),)
    return ()


def _collect_available_networks(
    session: NativeWifiScanSession,
    interface_id: str,
) -> tuple[tuple[AvailableWifiNetwork, ...], tuple[WifiScanIssue, ...]]:
    try:
        return session.available_networks(interface_id), ()
    except WifiAccessDeniedError as error:
        return (), (_issue(WifiScanIssueCode.ACCESS_DENIED, interface_id, str(error)),)
    except (NativeWifiDataError, WindowsWlanApiError) as error:
        return (), (_issue(WifiScanIssueCode.AVAILABLE_NETWORKS_FAILED, interface_id, str(error)),)


def _collect_access_points(
    session: NativeWifiScanSession,
    interface_id: str,
) -> tuple[tuple[WifiAccessPoint, ...], tuple[WifiScanIssue, ...]]:
    try:
        return session.access_points(interface_id), ()
    except WifiAccessDeniedError as error:
        return (), (_issue(WifiScanIssueCode.ACCESS_DENIED, interface_id, str(error)),)
    except (NativeWifiDataError, WindowsWlanApiError) as error:
        return (), (_issue(WifiScanIssueCode.BSS_LIST_FAILED, interface_id, str(error)),)


def _read_available_networks(
    address: int,
    interface_id: str,
) -> tuple[AvailableWifiNetwork, ...]:
    header = _WlanAvailableNetworkList.from_address(address)
    count = int(header.number_of_items)
    if count > _MAX_NETWORK_COUNT:
        raise NativeWifiDataError("Windows returned an unreasonable available network count")
    item_address = address + _WlanAvailableNetworkList.items.offset
    return tuple(
        _convert_available_network(
            _WlanAvailableNetwork.from_address(
                item_address + index * ctypes.sizeof(_WlanAvailableNetwork)
            ),
            interface_id,
        )
        for index in range(count)
    )


def _convert_available_network(
    item: _WlanAvailableNetwork,
    interface_id: str,
) -> AvailableWifiNetwork:
    try:
        return AvailableWifiNetwork(
            interface_id=interface_id,
            ssid=_convert_ssid(item.ssid),
            connectable=bool(item.network_connectable),
            profile_name=str(item.profile_name).rstrip("\x00") or None,
            signal_quality=int(item.signal_quality),
            security_enabled=bool(item.security_enabled),
            authentication=WifiAuthentication(int(item.authentication)),
            cipher=WifiCipher(int(item.cipher)),
            reported_bss_count=int(item.number_of_bssids),
        )
    except ValueError as error:
        raise NativeWifiDataError(
            f"Windows returned invalid available network data: {error}"
        ) from error


def _read_access_points(address: int, interface_id: str) -> tuple[WifiAccessPoint, ...]:
    header = _WlanBssList.from_address(address)
    count = int(header.number_of_items)
    total_size = int(header.total_size)
    if count > _MAX_BSS_COUNT:
        raise NativeWifiDataError("Windows returned an unreasonable BSS count")
    required_size = _WlanBssList.items.offset + count * ctypes.sizeof(_WlanBssEntry)
    if total_size < required_size:
        raise NativeWifiDataError("Windows returned a truncated BSS list")
    item_address = address + _WlanBssList.items.offset
    return tuple(
        _convert_access_point(
            _WlanBssEntry.from_address(item_address + index * ctypes.sizeof(_WlanBssEntry)),
            interface_id,
        )
        for index in range(count)
    )


def _convert_access_point(item: _WlanBssEntry, interface_id: str) -> WifiAccessPoint:
    try:
        return WifiAccessPoint(
            interface_id=interface_id,
            ssid=_convert_ssid(item.ssid),
            bssid=WifiBssid(bytes(item.bssid)),
            phy_type=WifiPhyType(int(item.phy_type)),
            signal_quality=int(item.link_quality),
            rssi_dbm=int(item.rssi_dbm),
            center_frequency_khz=int(item.center_frequency_khz),
            beacon_period_tu=int(item.beacon_period) or None,
            capability_information=int(item.capability_information),
            timestamp_us=int(item.timestamp_us),
            host_timestamp=int(item.host_timestamp),
        )
    except ValueError as error:
        raise NativeWifiDataError(f"Windows returned invalid BSS data: {error}") from error


def _convert_ssid(value: _Dot11Ssid) -> WifiSsid:
    length = int(value.length)
    if length > len(value.ssid):
        raise NativeWifiDataError("Windows returned an invalid SSID length")
    return WifiSsid(bytes(value.ssid[:length]))


def _read_scan_failure_code(data: _WlanNotificationData) -> int:
    if int(data.data_size) < ctypes.sizeof(wintypes.DWORD) or not data.data:
        return 0
    return int(wintypes.DWORD.from_address(int(data.data)).value)


def _release_error_buffer(bindings: WlanScanBindings, result: int, address: int) -> None:
    if result != _ERROR_SUCCESS and address:
        bindings.free_memory(address)


def _raise_scan_result(operation: str, result: int) -> None:
    if result == _ERROR_SUCCESS:
        return
    if result == _ERROR_ACCESS_DENIED:
        raise WifiAccessDeniedError(
            "Windows denied access to nearby Wi-Fi data. "
            "Location access may be required by the operating system."
        )
    if result == _ERROR_SERVICE_NOT_ACTIVE:
        raise WlanServiceUnavailableError("The Windows WLAN service is not running")
    if result in {_ERROR_NOT_SUPPORTED, _ERROR_CALL_NOT_IMPLEMENTED}:
        raise WlanApiUnavailableError(f"{operation} is not supported by this Windows system")
    raise WindowsWlanApiError(operation, result)


def _issue(code: WifiScanIssueCode, interface_id: str, message: str) -> WifiScanIssue:
    return WifiScanIssue(code, message, interface_id)


def _deduplicate_issues(issues: list[WifiScanIssue]) -> tuple[WifiScanIssue, ...]:
    return tuple(dict.fromkeys(issues))
