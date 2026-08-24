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
    _Guid,
    _guid_from_text,
    _WlanConnectionAttributes,
    _WlanInterfaceInfo,
    _WlanInterfaceInfoList,
)

_FIRST_ID = "aaaaaaaa-0000-0000-0000-000000000001"
_SECOND_ID = "bbbbbbbb-0000-0000-0000-000000000002"


def test_native_struct_layouts_match_windows_abi() -> None:
    assert ctypes.sizeof(_Guid) == 16
    assert ctypes.sizeof(_WlanInterfaceInfo) == 532
    assert _WlanInterfaceInfoList.items.offset == 8
    assert ctypes.sizeof(_WlanConnectionAttributes) == 604


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
    attributes.association.phy_type = 8
    attributes.association.signal_quality = 78
    attributes.association.receive_rate_kbps = 866_700
    attributes.association.transmit_rate_kbps = 433_300
    attributes.security.security_enabled = 1
    attributes.security.authentication = 6
    attributes.security.cipher = 4
    return attributes
