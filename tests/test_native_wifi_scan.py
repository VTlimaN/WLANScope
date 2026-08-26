import ctypes

import pytest

from wlanscope.domain.nearby_wifi import WifiScanIssueCode
from wlanscope.domain.wifi import NativeWifiDataError
from wlanscope.platform.windows.native_wifi import (
    _guid_from_text,
    _WlanInterfaceInfo,
    _WlanInterfaceInfoList,
)
from wlanscope.platform.windows.native_wifi_scan import (
    NativeNearbyWifiCollector,
    _convert_access_point,
    _NotificationCallback,
    _read_access_points,
    _WlanAvailableNetwork,
    _WlanAvailableNetworkList,
    _WlanBssEntry,
    _WlanBssList,
    _WlanNotificationData,
)

_FIRST_ID = "aaaaaaaa-0000-0000-0000-000000000001"
_SECOND_ID = "bbbbbbbb-0000-0000-0000-000000000002"


def test_scan_struct_layouts_match_windows_abi() -> None:
    assert ctypes.sizeof(_WlanNotificationData) == 40
    assert ctypes.sizeof(_WlanAvailableNetwork) == 628
    assert _WlanAvailableNetworkList.items.offset == 8
    assert ctypes.sizeof(_WlanBssEntry) == 360
    assert _WlanBssEntry.in_reg_domain.offset == 64
    assert _WlanBssEntry.beacon_period.offset == 66
    assert _WlanBssEntry.timestamp_us.offset == 72
    assert _WlanBssList.items.offset == 8


def test_bss_conversion_preserves_fixed_fields_rates_and_information_elements() -> None:
    item = _bss(b"SANITIZED", 11, 5_180_000)
    item.phy_id = 3
    item.bss_type = 1
    item.in_reg_domain = 1
    item.capability_information = 0x0431
    item.rate_set.rate_set_length = 4
    item.rate_set.rate_set[0] = 0x8002
    item.rate_set.rate_set[1] = 0x0004
    rsn = bytes.fromhex("0100 000fac04 0100 000fac04 0100 000fac02 c000")
    blob = bytes((7, 3)) + b"US " + bytes((48, len(rsn))) + rsn
    item.information_element_offset = ctypes.sizeof(_WlanBssEntry)
    item.information_element_size = len(blob)
    buffer = ctypes.create_string_buffer(ctypes.sizeof(item) + len(blob))
    address = ctypes.addressof(buffer)
    ctypes.memmove(address, ctypes.byref(item), ctypes.sizeof(item))
    ctypes.memmove(address + ctypes.sizeof(item), blob, len(blob))

    access_point = _convert_access_point(
        _WlanBssEntry.from_address(address), _FIRST_ID, address, address + len(buffer)
    )

    assert access_point.phy_id == 3
    assert access_point.bss_type == 1
    assert access_point.in_reg_domain
    assert access_point.supported_rates_mbps == (1.0, 2.0)
    assert access_point.basic_rates_mbps == (1.0,)
    assert access_point.capability_flags == (
        "ESS",
        "Privacy",
        "Short preamble",
        "Short slot time",
    )
    assert access_point.information_elements.country_code == "US"
    assert access_point.information_elements.rsn is not None


@pytest.mark.parametrize(
    ("offset", "size"),
    [(1, 4), (ctypes.sizeof(_WlanBssEntry), 2325), (ctypes.sizeof(_WlanBssEntry), 4)],
)
def test_bss_information_element_bounds_are_validated(offset: int, size: int) -> None:
    item = _bss(b"SANITIZED", 11, 5_180_000)
    item.information_element_offset = offset
    item.information_element_size = size
    buffer = ctypes.create_string_buffer(ctypes.sizeof(item) + 2)
    address = ctypes.addressof(buffer)
    ctypes.memmove(address, ctypes.byref(item), ctypes.sizeof(item))

    with pytest.raises(NativeWifiDataError):
        _convert_access_point(
            _WlanBssEntry.from_address(address), _FIRST_ID, address, address + len(buffer)
        )


def test_multiple_bss_information_elements_are_read_after_fixed_entry_array() -> None:
    first = _bss(b"ONE", 11, 2_437_000)
    second = _bss(b"TWO", 12, 5_180_000)
    first_blob = bytes((7, 3)) + b"US "
    second_blob = bytes((7, 3)) + b"BR "
    fixed_size = _WlanBssList.items.offset + 2 * ctypes.sizeof(_WlanBssEntry)
    total_size = fixed_size + len(first_blob) + len(second_blob)
    buffer = ctypes.create_string_buffer(total_size)
    address = ctypes.addressof(buffer)
    header = _WlanBssList.from_address(address)
    header.total_size = total_size
    header.number_of_items = 2
    first_address = address + _WlanBssList.items.offset
    second_address = first_address + ctypes.sizeof(_WlanBssEntry)
    first.information_element_offset = address + fixed_size - first_address
    first.information_element_size = len(first_blob)
    second.information_element_offset = address + fixed_size + len(first_blob) - second_address
    second.information_element_size = len(second_blob)
    ctypes.memmove(first_address, ctypes.byref(first), ctypes.sizeof(first))
    ctypes.memmove(second_address, ctypes.byref(second), ctypes.sizeof(second))
    ctypes.memmove(address + fixed_size, first_blob, len(first_blob))
    ctypes.memmove(address + fixed_size + len(first_blob), second_blob, len(second_blob))

    access_points = _read_access_points(address, _FIRST_ID)

    assert [item.information_elements.country_code for item in access_points] == ["US", "BR"]


def test_bss_information_element_cannot_overlap_fixed_entry_array() -> None:
    first = _bss(b"ONE", 11, 2_437_000)
    second = _bss(b"TWO", 12, 5_180_000)
    size = _WlanBssList.items.offset + 2 * ctypes.sizeof(_WlanBssEntry)
    buffer = ctypes.create_string_buffer(size)
    address = ctypes.addressof(buffer)
    header = _WlanBssList.from_address(address)
    header.total_size = size
    header.number_of_items = 2
    first.information_element_offset = ctypes.sizeof(_WlanBssEntry)
    first.information_element_size = 2
    _write_items(address, _WlanBssList.items.offset, (first, second))

    with pytest.raises(NativeWifiDataError):
        _read_access_points(address, _FIRST_ID)


def test_scan_registers_notification_waits_and_cleans_up() -> None:
    bindings = FakeScanBindings(interfaces=(_interface(_FIRST_ID),))

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert len(snapshot.interfaces) == 1
    assert bindings.scan_calls == [_FIRST_ID]
    assert bindings.notification_sources == [8, 0]
    assert bindings.closed_handles == [73]


def test_scan_timeout_is_partial_and_notification_is_removed() -> None:
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID),),
        notification_mode="timeout",
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.001).collect()

    assert snapshot.issues[0].code is WifiScanIssueCode.TIMEOUT
    assert bindings.notification_sources == [8, 0]
    assert bindings.closed_handles == [73]


def test_scan_failure_notification_is_reported() -> None:
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID),),
        notification_mode="failure",
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert snapshot.issues[0].code is WifiScanIssueCode.SCAN_FAILED
    assert "87" in snapshot.issues[0].message


def test_scan_access_denied_does_not_prevent_cached_list_collection() -> None:
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID),),
        scan_results={_FIRST_ID: 5},
        available={_FIRST_ID: (_network(b"SANITIZED"),)},
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert snapshot.issues[0].code is WifiScanIssueCode.ACCESS_DENIED
    assert len(snapshot.available_networks) == 1


def test_zero_interfaces_returns_empty_data() -> None:
    bindings = FakeScanBindings()

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert snapshot.interfaces == ()
    assert snapshot.available_networks == ()
    assert snapshot.access_points == ()


def test_multiple_interfaces_are_scanned_independently() -> None:
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID), _interface(_SECOND_ID)),
        available={
            _FIRST_ID: (_network(b"FIRST"),),
            _SECOND_ID: (_network(b"SECOND"),),
        },
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert bindings.scan_calls == [_FIRST_ID, _SECOND_ID]
    assert {network.interface_id for network in snapshot.available_networks} == {
        _FIRST_ID,
        _SECOND_ID,
    }


def test_available_network_conversion_preserves_security_and_hidden_ssid() -> None:
    visible = _network(b"SANITIZED", signal=81, bss_count=2)
    hidden = _network(b"", signal=52)
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID),),
        available={_FIRST_ID: (visible, hidden)},
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert snapshot.available_networks[0].ssid.raw == b"SANITIZED"
    assert snapshot.available_networks[0].reported_bss_count == 2
    assert snapshot.available_networks[0].authentication.display_name == "RSNA"
    assert snapshot.available_networks[1].ssid.is_empty


def test_bss_conversion_preserves_radio_measurements() -> None:
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID),),
        access_points={_FIRST_ID: (_bss(b"SANITIZED", 11, 5_180_000),)},
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()
    access_point = snapshot.access_points[0]

    assert access_point.ssid.raw == b"SANITIZED"
    assert access_point.bssid.octets[-1] == 11
    assert access_point.signal_quality == 78
    assert access_point.rssi_dbm == -48
    assert access_point.center_frequency_khz == 5_180_000
    assert access_point.phy_type.display_name == "VHT"


def test_ssid_uses_explicit_length_in_scan_lists() -> None:
    network = _network(b"AB\x00CD", trailing=b"SECRET")
    bss = _bss(b"AB\x00CD", 11, 2_437_000, trailing=b"SECRET")
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID),),
        available={_FIRST_ID: (network,)},
        access_points={_FIRST_ID: (bss,)},
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert snapshot.available_networks[0].ssid.raw == b"AB\x00CD"
    assert snapshot.access_points[0].ssid.raw == b"AB\x00CD"


def test_unknown_native_values_are_preserved() -> None:
    network = _network(b"SANITIZED")
    network.authentication = 900
    network.cipher = 901
    bss = _bss(b"SANITIZED", 11, 5_180_000)
    bss.phy_type = 902
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID),),
        available={_FIRST_ID: (network,)},
        access_points={_FIRST_ID: (bss,)},
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert snapshot.available_networks[0].authentication.display_name == "Unknown (900)"
    assert snapshot.available_networks[0].cipher.display_name == "Unknown (901)"
    assert snapshot.access_points[0].phy_type.display_name == "Unknown (902)"


def test_source_failure_with_buffer_releases_memory() -> None:
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID),),
        available={_FIRST_ID: (_network(b"SANITIZED"),)},
        available_results={_FIRST_ID: 9001},
        bss_results={_FIRST_ID: 9002},
        access_points={_FIRST_ID: (_bss(b"SANITIZED", 11, 5_180_000),)},
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert {issue.code for issue in snapshot.issues} == {
        WifiScanIssueCode.AVAILABLE_NETWORKS_FAILED,
        WifiScanIssueCode.BSS_LIST_FAILED,
    }
    assert len(bindings.freed_addresses) == 3


def test_truncated_bss_list_is_rejected_and_released() -> None:
    bindings = FakeScanBindings(
        interfaces=(_interface(_FIRST_ID),),
        access_points={_FIRST_ID: (_bss(b"SANITIZED", 11, 5_180_000),)},
        truncate_bss=True,
    )

    snapshot = NativeNearbyWifiCollector(bindings, timeout_seconds=0.01).collect()

    assert snapshot.issues[0].code is WifiScanIssueCode.BSS_LIST_FAILED
    assert "truncated" in snapshot.issues[0].message
    assert len(bindings.freed_addresses) == 3


class FakeScanBindings:
    def __init__(
        self,
        interfaces: tuple[tuple[str, str, int], ...] = (),
        available: dict[str, tuple[_WlanAvailableNetwork, ...]] | None = None,
        access_points: dict[str, tuple[_WlanBssEntry, ...]] | None = None,
        scan_results: dict[str, int] | None = None,
        available_results: dict[str, int] | None = None,
        bss_results: dict[str, int] | None = None,
        notification_mode: str = "success",
        truncate_bss: bool = False,
    ) -> None:
        self.interfaces = interfaces
        self.available = available or {}
        self.access_points = access_points or {}
        self.scan_results = scan_results or {}
        self.available_results = available_results or {}
        self.bss_results = bss_results or {}
        self.notification_mode = notification_mode
        self.truncate_bss = truncate_bss
        self.scan_calls: list[str] = []
        self.notification_sources: list[int] = []
        self.closed_handles: list[int] = []
        self.freed_addresses: list[int] = []
        self._callback_address = 0
        self._allocations: dict[int, object] = {}

    def open_handle(self) -> tuple[int, int]:
        return 0, 73

    def close_handle(self, handle: int) -> int:
        self.closed_handles.append(handle)
        return 0

    def enumerate_interfaces(self, handle: int) -> tuple[int, int]:
        size = _WlanInterfaceInfoList.items.offset + len(self.interfaces) * ctypes.sizeof(
            _WlanInterfaceInfo
        )
        buffer = ctypes.create_string_buffer(size)
        address = ctypes.addressof(buffer)
        header = _WlanInterfaceInfoList.from_address(address)
        header.number_of_items = len(self.interfaces)
        for index, (interface_id, description, state) in enumerate(self.interfaces):
            item = _WlanInterfaceInfo(
                interface_guid=_guid_from_text(interface_id),
                description=description,
                state=state,
            )
            target = address + _WlanInterfaceInfoList.items.offset + index * ctypes.sizeof(item)
            ctypes.memmove(target, ctypes.byref(item), ctypes.sizeof(item))
        self._allocations[address] = buffer
        return 0, address

    def query_current_connection(self, handle: int, interface_id: str) -> tuple[int, int, int]:
        return 5023, 0, 0

    def scan(self, handle: int, interface_id: str) -> int:
        self.scan_calls.append(interface_id)
        result = self.scan_results.get(interface_id, 0)
        if result == 0 and self.notification_mode != "timeout":
            self._send_notification(interface_id)
        return result

    def get_available_networks(self, handle: int, interface_id: str) -> tuple[int, int]:
        address = self._available_buffer(self.available.get(interface_id, ()))
        return self.available_results.get(interface_id, 0), address

    def get_bss_list(self, handle: int, interface_id: str) -> tuple[int, int]:
        address = self._bss_buffer(self.access_points.get(interface_id, ()))
        return self.bss_results.get(interface_id, 0), address

    def register_notification(
        self,
        handle: int,
        source: int,
        callback_address: int,
    ) -> tuple[int, int]:
        self.notification_sources.append(source)
        self._callback_address = callback_address
        return 0, 0

    def free_memory(self, address: int) -> None:
        self.freed_addresses.append(address)
        self._allocations.pop(address)

    def _send_notification(self, interface_id: str) -> None:
        notification = _WlanNotificationData()
        notification.notification_source = 8
        notification.notification_code = 8 if self.notification_mode == "failure" else 7
        notification.interface_guid = _guid_from_text(interface_id)
        failure_code = ctypes.c_ulong(87)
        if self.notification_mode == "failure":
            notification.data_size = ctypes.sizeof(failure_code)
            notification.data = ctypes.addressof(failure_code)
        callback = _NotificationCallback(self._callback_address)
        callback(ctypes.byref(notification), None)

    def _available_buffer(self, items: tuple[_WlanAvailableNetwork, ...]) -> int:
        size = _WlanAvailableNetworkList.items.offset + len(items) * ctypes.sizeof(
            _WlanAvailableNetwork
        )
        buffer = ctypes.create_string_buffer(size)
        address = ctypes.addressof(buffer)
        header = _WlanAvailableNetworkList.from_address(address)
        header.number_of_items = len(items)
        _write_items(address, _WlanAvailableNetworkList.items.offset, items)
        self._allocations[address] = buffer
        return address

    def _bss_buffer(self, items: tuple[_WlanBssEntry, ...]) -> int:
        size = _WlanBssList.items.offset + len(items) * ctypes.sizeof(_WlanBssEntry)
        buffer = ctypes.create_string_buffer(size)
        address = ctypes.addressof(buffer)
        header = _WlanBssList.from_address(address)
        header.number_of_items = len(items)
        header.total_size = size - 1 if self.truncate_bss else size
        _write_items(address, _WlanBssList.items.offset, items)
        self._allocations[address] = buffer
        return address


def _write_items(address: int, offset: int, items: tuple[ctypes.Structure, ...]) -> None:
    for index, item in enumerate(items):
        ctypes.memmove(
            address + offset + index * ctypes.sizeof(item),
            ctypes.byref(item),
            ctypes.sizeof(item),
        )


def _interface(interface_id: str) -> tuple[str, str, int]:
    return interface_id, "Sanitized adapter", 4


def _network(
    ssid: bytes,
    signal: int = 70,
    bss_count: int = 1,
    trailing: bytes = b"",
) -> _WlanAvailableNetwork:
    item = _WlanAvailableNetwork()
    item.profile_name = "SANITIZED"
    item.ssid.length = len(ssid)
    for index, octet in enumerate(ssid + trailing):
        item.ssid.ssid[index] = octet
    item.number_of_bssids = bss_count
    item.network_connectable = 1
    item.signal_quality = signal
    item.security_enabled = 1
    item.authentication = 6
    item.cipher = 4
    return item


def _bss(
    ssid: bytes,
    bssid: int,
    frequency_khz: int,
    trailing: bytes = b"",
) -> _WlanBssEntry:
    item = _WlanBssEntry()
    item.ssid.length = len(ssid)
    for index, octet in enumerate(ssid + trailing):
        item.ssid.ssid[index] = octet
    for index, octet in enumerate(bytes.fromhex(f"0200000000{bssid:02x}")):
        item.bssid[index] = octet
    item.phy_type = 8
    item.rssi_dbm = -48
    item.link_quality = 78
    item.beacon_period = 100
    item.timestamp_us = 1_000
    item.host_timestamp = 2_000
    item.capability_information = 1
    item.center_frequency_khz = frequency_khz
    return item
