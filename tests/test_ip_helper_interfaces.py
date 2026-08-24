import ctypes

import pytest

from wlanscope.domain.interfaces import (
    AdministrativeState,
    InterfaceKind,
    MediaState,
    OperationalState,
)
from wlanscope.platform.windows.ip_helper import (
    AdapterAddressRecord,
    InterfaceRow,
    WindowsInterfaceCollector,
    _MibIfRow2,
    combine_ip_helper_records,
)


def test_mib_if_row2_layout_matches_64_bit_windows_contract() -> None:
    assert ctypes.sizeof(_MibIfRow2) == 1352
    assert _MibIfRow2.TransmitLinkSpeed.offset == 1192
    assert _MibIfRow2.ReceiveLinkSpeed.offset == 1200
    assert _MibIfRow2.OutQLen.offset == 1344


@pytest.mark.parametrize(
    ("windows_type", "is_hardware", "expected_kind"),
    [
        (6, True, InterfaceKind.ETHERNET),
        (71, True, InterfaceKind.WIFI),
        (24, False, InterfaceKind.LOOPBACK),
        (131, False, InterfaceKind.TUNNEL),
        (53, False, InterfaceKind.VIRTUAL),
        (53, True, InterfaceKind.OTHER),
    ],
)
def test_structured_windows_type_classification(
    windows_type: int,
    is_hardware: bool,
    expected_kind: InterfaceKind,
) -> None:
    interface = combine_ip_helper_records(
        (_row(windows_interface_type=windows_type, is_hardware=is_hardware),),
        (),
    )[0]

    assert interface.kind is expected_kind


def test_adapter_record_enriches_primary_interface_fields() -> None:
    adapter = AdapterAddressRecord(
        interface_index=7,
        stable_id="aaaaaaaa-0000-0000-0000-000000000001",
        friendly_name="Friendly Adapter",
        description="Structured adapter description",
        physical_address=bytes.fromhex("02A1B2C3D4E5"),
        mtu=1500,
        receive_link_speed_bps=1_000_000_000,
        transmit_link_speed_bps=1_000_000_000,
    )

    interface = combine_ip_helper_records(
        (
            _row(
                alias="",
                description=None,
                physical_address=b"",
                mtu=None,
                receive_link_speed_bps=None,
                transmit_link_speed_bps=None,
            ),
        ),
        (adapter,),
    )[0]

    assert interface.friendly_name == "Friendly Adapter"
    assert interface.description == "Structured adapter description"
    assert str(interface.mac_address) == "02:A1:B2:C3:D4:E5"
    assert interface.mtu == 1500
    assert interface.receive_link_speed_bps == 1_000_000_000


def test_interface_without_physical_address_has_no_mac() -> None:
    interface = combine_ip_helper_records((_row(physical_address=b""),), ())[0]

    assert interface.mac_address is None


def test_invalid_physical_address_is_not_exposed_as_mac() -> None:
    interface = combine_ip_helper_records((_row(physical_address=b"\x01\x02"),), ())[0]

    assert interface.mac_address is None


def test_unknown_operational_state_is_preserved() -> None:
    interface = combine_ip_helper_records(
        (_row(operational_state=OperationalState.UNKNOWN),),
        (),
    )[0]

    assert interface.operational_state is OperationalState.UNKNOWN


def test_multiple_interfaces_preserve_primary_order_for_application_sorting() -> None:
    rows = (
        _row(interface_index=18, stable_id="bbbbbbbb-0000-0000-0000-000000000002"),
        _row(interface_index=7, stable_id="aaaaaaaa-0000-0000-0000-000000000001"),
    )

    interfaces = combine_ip_helper_records(rows, ())

    assert [interface.interface_index for interface in interfaces] == [18, 7]


def test_collector_reads_both_ip_helper_sources() -> None:
    backend = FakeIpHelperBackend(
        rows=(_row(),),
        adapters=(
            AdapterAddressRecord(
                interface_index=7,
                stable_id="aaaaaaaa-0000-0000-0000-000000000001",
                friendly_name="Adapter A",
                description=None,
                physical_address=b"",
                mtu=None,
                receive_link_speed_bps=None,
                transmit_link_speed_bps=None,
            ),
        ),
    )

    interfaces = WindowsInterfaceCollector(backend).collect()

    assert len(interfaces) == 1
    assert backend.rows_read
    assert backend.adapters_read


class FakeIpHelperBackend:
    def __init__(
        self,
        rows: tuple[InterfaceRow, ...],
        adapters: tuple[AdapterAddressRecord, ...],
    ) -> None:
        self._rows = rows
        self._adapters = adapters
        self.rows_read = False
        self.adapters_read = False

    def read_interface_rows(self) -> tuple[InterfaceRow, ...]:
        self.rows_read = True
        return self._rows

    def read_adapter_records(self) -> tuple[AdapterAddressRecord, ...]:
        self.adapters_read = True
        return self._adapters


def _row(
    interface_index: int = 7,
    stable_id: str | None = "aaaaaaaa-0000-0000-0000-000000000001",
    alias: str = "Adapter A",
    description: str | None = "Adapter description",
    windows_interface_type: int = 6,
    operational_state: OperationalState = OperationalState.UP,
    physical_address: bytes = bytes.fromhex("02A1B2C3D4E5"),
    mtu: int | None = 1500,
    receive_link_speed_bps: int | None = 1_000_000_000,
    transmit_link_speed_bps: int | None = 1_000_000_000,
    is_hardware: bool = True,
) -> InterfaceRow:
    return InterfaceRow(
        interface_index=interface_index,
        stable_id=stable_id,
        alias=alias,
        description=description,
        windows_interface_type=windows_interface_type,
        operational_state=operational_state,
        administrative_state=AdministrativeState.UP,
        media_state=MediaState.CONNECTED,
        physical_address=physical_address,
        mtu=mtu,
        receive_link_speed_bps=receive_link_speed_bps,
        transmit_link_speed_bps=transmit_link_speed_bps,
        is_hardware=is_hardware,
    )
