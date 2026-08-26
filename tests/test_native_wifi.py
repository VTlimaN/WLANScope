import ctypes

import pytest

from wlanscope.domain.wifi import (
    NativeWifiDataError,
    WifiAccessDeniedError,
    WifiIssueCode,
    WindowsWlanApiError,
    WlanServiceUnavailableError,
)
from wlanscope.platform.windows.native_wifi import (
    NativeWifiCollector,
    NativeWifiSession,
    _Dot11AuthCipherPair,
    _Guid,
    _guid_from_text,
    _WlanAuthCipherPairList,
    _WlanConnectionAttributes,
    _WlanInterfaceCapability,
    _WlanInterfaceInfo,
    _WlanInterfaceInfoList,
    _WlanMacFrameStatistics,
    _WlanPhyFrameStatistics,
    _WlanPhyRadioState,
    _WlanRadioState,
    _WlanStatisticsHeader,
)

_FIRST_ID = "aaaaaaaa-0000-0000-0000-000000000001"
_SECOND_ID = "bbbbbbbb-0000-0000-0000-000000000002"


def test_native_struct_layouts_match_windows_abi() -> None:
    assert ctypes.sizeof(_Guid) == 16
    assert ctypes.sizeof(_WlanInterfaceInfo) == 532
    assert _WlanInterfaceInfoList.items.offset == 8
    assert ctypes.sizeof(_WlanConnectionAttributes) == 604
    assert ctypes.sizeof(_Dot11AuthCipherPair) == 8
    assert _WlanAuthCipherPairList.items.offset == 4
    assert ctypes.sizeof(_WlanPhyFrameStatistics) == 144


def test_session_opens_and_closes_handle() -> None:
    bindings = FakeBindings()

    with NativeWifiSession(bindings):
        pass

    assert bindings.open_calls == 1
    assert bindings.closed_handles == [73]


@pytest.mark.parametrize(
    ("result", "error_type"),
    [(5, WifiAccessDeniedError), (1062, WlanServiceUnavailableError), (9001, WindowsWlanApiError)],
)
def test_open_handle_translates_failures(result: int, error_type: type[Exception]) -> None:
    bindings = FakeBindings(open_result=result)

    with pytest.raises(error_type), NativeWifiSession(bindings):
        pass

    assert bindings.closed_handles == []


def test_handle_closes_when_conversion_raises() -> None:
    bindings = FakeBindings(interfaces=((_FIRST_ID, "", 4),))

    with pytest.raises(NativeWifiDataError):
        NativeWifiCollector(bindings).collect()

    assert bindings.closed_handles == [73]
    assert len(bindings.freed_addresses) == 1


def test_collector_handles_zero_interfaces() -> None:
    bindings = FakeBindings(interfaces=())

    snapshot = NativeWifiCollector(bindings).collect()

    assert snapshot.interfaces == ()
    assert len(bindings.freed_addresses) == 1


def test_collector_converts_one_disconnected_interface_without_query() -> None:
    bindings = FakeBindings(interfaces=((_FIRST_ID, "Sanitized adapter", 4),))

    snapshot = NativeWifiCollector(bindings).collect()

    assert len(snapshot.interfaces) == 1
    assert snapshot.interfaces[0].state.display_name == "Disconnected"
    assert snapshot.interfaces[0].connection is None
    assert bindings.query_calls == []


def test_collector_preserves_multiple_interfaces() -> None:
    bindings = FakeBindings(
        interfaces=(
            (_FIRST_ID, "Sanitized adapter A", 4),
            (_SECOND_ID, "Sanitized adapter B", 4),
        )
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert [interface.interface_id for interface in snapshot.interfaces] == [_FIRST_ID, _SECOND_ID]


def test_collector_converts_current_connection() -> None:
    attributes = _connection_attributes()
    bindings = FakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 1),),
        connections={_FIRST_ID: (0, attributes)},
    )

    snapshot = NativeWifiCollector(bindings).collect()
    connection = snapshot.interfaces[0].connection

    assert connection is not None
    assert connection.ssid.raw == b"SANITIZED"
    assert str(connection.bssid) == "02:00:00:00:00:11"
    assert connection.phy_type.display_name == "VHT"
    assert connection.signal_quality == 78
    assert connection.receive_rate_kbps == 866_700
    assert connection.transmit_rate_kbps == 433_300
    assert connection.security.authentication.display_name == "RSNA"
    assert connection.security.cipher.display_name == "CCMP"
    assert connection.bss_type is not None
    assert connection.bss_type.display_name == "Infrastructure"
    assert len(bindings.freed_addresses) == 2


def test_ssid_conversion_uses_explicit_length() -> None:
    attributes = _connection_attributes(ssid=b"AB\x00CD", trailing=b"SECRET")
    bindings = FakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 1),),
        connections={_FIRST_ID: (0, attributes)},
    )

    connection = NativeWifiCollector(bindings).collect().interfaces[0].connection

    assert connection is not None
    assert connection.ssid.raw == b"AB\x00CD"


def test_invalid_ssid_length_becomes_partial_and_releases_native_resources() -> None:
    attributes = _connection_attributes()
    attributes.association.ssid.length = 33
    bindings = FakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 1),),
        connections={_FIRST_ID: (0, attributes)},
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert snapshot.issues[0].code is WifiIssueCode.CONNECTION_UNAVAILABLE
    assert len(bindings.freed_addresses) == 2
    assert bindings.closed_handles == [73]


def test_access_denied_preserves_interface_as_partial_result() -> None:
    bindings = FakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 1),),
        connections={_FIRST_ID: (5, None)},
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert snapshot.interfaces[0].connection is None
    assert snapshot.issues[0].code is WifiIssueCode.ACCESS_DENIED
    assert "Location access may be required" in snapshot.issues[0].message


def test_unknown_query_error_preserves_other_interfaces() -> None:
    bindings = FakeBindings(
        interfaces=(
            (_FIRST_ID, "Sanitized adapter A", 1),
            (_SECOND_ID, "Sanitized adapter B", 4),
        ),
        connections={_FIRST_ID: (9001, None)},
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert len(snapshot.interfaces) == 2
    assert snapshot.issues[0].code is WifiIssueCode.CONNECTION_UNAVAILABLE
    assert "9001" in snapshot.issues[0].message


def test_invalid_state_race_becomes_partial_result() -> None:
    bindings = FakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 1),),
        connections={_FIRST_ID: (5023, None)},
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert snapshot.interfaces[0].connection is None
    assert snapshot.is_partial


def test_error_result_with_buffer_releases_memory() -> None:
    attributes = _connection_attributes()
    bindings = FakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 1),),
        connections={_FIRST_ID: (9001, attributes)},
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert snapshot.is_partial
    assert len(bindings.freed_addresses) == 2


def test_collector_reads_optional_deep_wifi_details() -> None:
    bindings = DeepFakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 1),),
        connections={_FIRST_ID: (0, _connection_attributes())},
    )

    interface = NativeWifiCollector(bindings).collect().interfaces[0]

    assert interface.capabilities is not None
    assert interface.capabilities.dot11d_supported
    assert [item.display_name for item in interface.capabilities.supported_phy_types] == [
        "HT",
        "VHT",
    ]
    assert interface.channel_number == 36
    assert interface.rssi_dbm == -51
    assert interface.operation_mode == 1
    assert interface.management_frame_protection_capable
    assert interface.radio_states[0].software_state.display_name == "On"
    assert interface.capabilities.infrastructure_security.pairs[0].authentication.display_name == (
        "RSNA-PSK"
    )
    assert interface.capabilities.adhoc_security.pairs[0].cipher.display_name == "CCMP"
    assert interface.statistics is not None
    assert interface.statistics.unicast_transmitted_frames == 10
    assert interface.statistics.decrypt_successes == 15
    assert interface.statistics.phy_counters[0].retry_frames == 4
    assert interface.statistics.phy_counters[0].fcs_errors == 6
    assert len(bindings.freed_addresses) == 11


def test_malformed_optional_capability_is_localized_and_memory_is_freed() -> None:
    bindings = DeepFakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 4),),
        malformed_capability=True,
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert snapshot.interfaces[0].capabilities is None
    assert snapshot.is_partial
    assert "supported PHY count" in snapshot.issues[0].message
    assert len(bindings.freed_addresses) == 2


def test_malformed_auth_cipher_list_is_localized_and_memory_is_freed() -> None:
    bindings = DeepFakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 4),),
        malformed_auth_pairs=True,
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert snapshot.interfaces[0].capabilities is None
    assert "auth/cipher" in snapshot.issues[0].message
    assert bindings._allocations == {}


def test_unsupported_auth_cipher_capability_is_explicit() -> None:
    bindings = DeepFakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 4),),
        unsupported_auth_pairs=True,
    )

    interface = NativeWifiCollector(bindings).collect().interfaces[0]

    assert interface.capabilities is not None
    assert interface.capabilities.infrastructure_security.state.name == "UNSUPPORTED"
    assert interface.capabilities.adhoc_security.state.name == "UNSUPPORTED"
    assert bindings._allocations == {}


def test_malformed_phy_statistics_is_localized_and_memory_is_freed() -> None:
    bindings = DeepFakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 4),),
        malformed_phy_statistics=True,
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert snapshot.interfaces[0].statistics is None
    assert "PHY statistics" in snapshot.issues[0].message
    assert bindings._allocations == {}


def test_short_optional_query_buffer_is_localized_and_freed() -> None:
    bindings = DeepFakeBindings(
        interfaces=((_FIRST_ID, "Sanitized adapter", 4),),
        short_channel_buffer=True,
    )

    snapshot = NativeWifiCollector(bindings).collect()

    assert snapshot.interfaces[0].channel_number is None
    assert "truncated WLAN query buffer" in snapshot.issues[0].message
    assert bindings._allocations == {}


class FakeBindings:
    def __init__(
        self,
        open_result: int = 0,
        interfaces: tuple[tuple[str, str, int], ...] = (),
        connections: dict[str, tuple[int, _WlanConnectionAttributes | None]] | None = None,
    ) -> None:
        self.open_result = open_result
        self.interfaces = interfaces
        self.connections = connections or {}
        self.open_calls = 0
        self.closed_handles: list[int] = []
        self.freed_addresses: list[int] = []
        self.query_calls: list[str] = []
        self._allocations: dict[int, object] = {}

    def open_handle(self) -> tuple[int, int]:
        self.open_calls += 1
        return self.open_result, 73

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
            info = _WlanInterfaceInfo(
                interface_guid=_guid_from_text(interface_id),
                description=description,
                state=state,
            )
            target = address + _WlanInterfaceInfoList.items.offset + index * ctypes.sizeof(info)
            ctypes.memmove(target, ctypes.byref(info), ctypes.sizeof(info))
        self._allocations[address] = buffer
        return 0, address

    def query_current_connection(self, handle: int, interface_id: str) -> tuple[int, int, int]:
        self.query_calls.append(interface_id)
        result, attributes = self.connections.get(interface_id, (5023, None))
        if attributes is None:
            return result, 0, 0
        buffer = ctypes.create_string_buffer(ctypes.sizeof(attributes))
        ctypes.memmove(buffer, ctypes.byref(attributes), ctypes.sizeof(attributes))
        address = ctypes.addressof(buffer)
        self._allocations[address] = buffer
        return result, address, ctypes.sizeof(attributes)

    def free_memory(self, address: int) -> None:
        self.freed_addresses.append(address)
        self._allocations.pop(address)


class DeepFakeBindings(FakeBindings):
    def __init__(
        self,
        open_result: int = 0,
        interfaces: tuple[tuple[str, str, int], ...] = (),
        connections: dict[str, tuple[int, _WlanConnectionAttributes | None]] | None = None,
        malformed_capability: bool = False,
        malformed_auth_pairs: bool = False,
        unsupported_auth_pairs: bool = False,
        malformed_phy_statistics: bool = False,
        short_channel_buffer: bool = False,
    ) -> None:
        super().__init__(open_result, interfaces, connections)
        self.malformed_capability = malformed_capability
        self.malformed_auth_pairs = malformed_auth_pairs
        self.unsupported_auth_pairs = unsupported_auth_pairs
        self.malformed_phy_statistics = malformed_phy_statistics
        self.short_channel_buffer = short_channel_buffer

    def get_interface_capability(self, handle: int, interface_id: str) -> tuple[int, int]:
        value = _WlanInterfaceCapability()
        value.interface_type = 0
        value.dot11d_supported = 1
        value.maximum_desired_ssids = 16
        value.maximum_desired_bssids = 16
        value.number_of_supported_phys = 65 if self.malformed_capability else 2
        value.phy_types[0] = 7
        value.phy_types[1] = 8
        return 0, self._allocate(value)

    def query_interface(self, handle: int, interface_id: str, opcode: int) -> tuple[int, int, int]:
        value: _WlanRadioState | ctypes.c_ulong | ctypes.c_long | _WlanStatisticsHeader
        if opcode == 4:
            value = _WlanRadioState()
            value.number_of_phys = 1
            value.states[0] = _WlanPhyRadioState(0, 1, 1)
        elif opcode == 8:
            value = ctypes.c_ulong(36)
            if self.short_channel_buffer:
                address = self._allocate(value)
                return 0, address, 1
        elif opcode in {9, 10}:
            if self.unsupported_auth_pairs:
                return 50, 0, 0
            return self._auth_cipher_pairs(opcode == 9 and self.malformed_auth_pairs)
        elif opcode == 12:
            value = ctypes.c_ulong(1)
        elif opcode == 16:
            value = ctypes.c_long(1)
        elif opcode == 0x10000101:
            return self._statistics()
        elif opcode == 0x10000102:
            value = ctypes.c_long(-51)
        else:
            return 50, 0, 0
        address = self._allocate(value)
        return 0, address, ctypes.sizeof(value)

    def _auth_cipher_pairs(self, malformed: bool) -> tuple[int, int, int]:
        size = _WlanAuthCipherPairList.items.offset + ctypes.sizeof(_Dot11AuthCipherPair)
        buffer = ctypes.create_string_buffer(size)
        address = ctypes.addressof(buffer)
        value = _WlanAuthCipherPairList.from_address(address)
        value.number_of_items = 2 if malformed else 1
        item = _Dot11AuthCipherPair.from_address(address + _WlanAuthCipherPairList.items.offset)
        item.authentication = 7
        item.cipher = 4
        self._allocations[address] = buffer
        return 0, address, size

    def _statistics(self) -> tuple[int, int, int]:
        size = ctypes.sizeof(_WlanStatisticsHeader) + ctypes.sizeof(_WlanPhyFrameStatistics)
        buffer = ctypes.create_string_buffer(size)
        address = ctypes.addressof(buffer)
        value = _WlanStatisticsHeader.from_address(address)
        value.four_way_handshake_failures = 1
        value.tkip_countermeasures = 2
        value.unicast = _mac_statistics(10, 11, 12, 13)
        value.multicast = _mac_statistics(20, 21, 3, 4)
        value.number_of_phys = 1
        phy = _WlanPhyFrameStatistics.from_address(address + ctypes.sizeof(_WlanStatisticsHeader))
        phy.transmitted = 1
        phy.received = 2
        phy.failed = 3
        phy.retry = 4
        phy.multiple_retry = 5
        phy.fcs_errors = 6
        if self.malformed_phy_statistics:
            value.number_of_phys = 2
        self._allocations[address] = buffer
        return 0, address, size

    def _allocate(
        self,
        value: (
            _WlanInterfaceCapability
            | _WlanRadioState
            | ctypes.c_ulong
            | ctypes.c_long
            | _WlanStatisticsHeader
        ),
    ) -> int:
        buffer = ctypes.create_string_buffer(ctypes.sizeof(value))
        ctypes.memmove(buffer, ctypes.byref(value), ctypes.sizeof(value))
        address = ctypes.addressof(buffer)
        self._allocations[address] = buffer
        return address


def _mac_statistics(
    transmitted: int, received: int, decrypt_successes: int, decrypt_failures: int
) -> _WlanMacFrameStatistics:
    value = _WlanMacFrameStatistics()
    value.transmitted = transmitted
    value.received = received
    value.decrypt_successes = decrypt_successes
    value.decrypt_failures = decrypt_failures
    return value


def _connection_attributes(
    ssid: bytes = b"SANITIZED",
    trailing: bytes = b"",
) -> _WlanConnectionAttributes:
    attributes = _WlanConnectionAttributes()
    attributes.state = 1
    attributes.connection_mode = 0
    attributes.profile_name = "SANITIZED"
    attributes.association.ssid.length = len(ssid)
    for index, octet in enumerate(ssid + trailing):
        attributes.association.ssid.ssid[index] = octet
    for index, octet in enumerate(bytes.fromhex("020000000011")):
        attributes.association.bssid[index] = octet
    attributes.association.bss_type = 1
    attributes.association.phy_type = 8
    attributes.association.signal_quality = 78
    attributes.association.receive_rate_kbps = 866_700
    attributes.association.transmit_rate_kbps = 433_300
    attributes.security.security_enabled = 1
    attributes.security.authentication = 6
    attributes.security.cipher = 4
    return attributes
