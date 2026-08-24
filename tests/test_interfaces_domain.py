import pytest

from wlanscope.domain.interfaces import (
    AdministrativeState,
    InterfaceKind,
    MacAddress,
    MediaState,
    NetworkInterface,
    OperationalState,
    normalize_stable_id,
)

DEFAULT_MAC_ADDRESS = MacAddress.from_text("02:00:00:00:00:01")


def test_mac_address_normalizes_text() -> None:
    address = MacAddress.from_text("02-a1-b2-c3-d4-e5")

    assert str(address) == "02:A1:B2:C3:D4:E5"


@pytest.mark.parametrize(
    "value",
    ["", "02:00:00:00:00", "02:00:00:00:00:GG", "00:00:00:00:00:00"],
)
def test_mac_address_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        MacAddress.from_text(value)


def test_interface_accepts_absent_mac_and_unknown_states() -> None:
    interface = _interface(mac_address=None)

    assert interface.mac_address is None
    assert interface.operational_state is OperationalState.UNKNOWN
    assert interface.administrative_state is AdministrativeState.UNKNOWN
    assert interface.media_state is MediaState.UNKNOWN


def test_interface_rejects_invalid_measurements() -> None:
    with pytest.raises(ValueError, match="positive"):
        _interface(mtu=0)


def test_stable_identifier_normalizes_guid() -> None:
    assert normalize_stable_id("{AAAAAAAA-0000-0000-0000-000000000001}") == (
        "aaaaaaaa-0000-0000-0000-000000000001"
    )


def _interface(
    mac_address: MacAddress | None = DEFAULT_MAC_ADDRESS,
    mtu: int | None = 1500,
) -> NetworkInterface:
    return NetworkInterface(
        interface_index=7,
        stable_id="aaaaaaaa-0000-0000-0000-000000000001",
        alias="Adapter A",
        friendly_name="Adapter A",
        description=None,
        windows_interface_type=6,
        kind=InterfaceKind.ETHERNET,
        operational_state=OperationalState.UNKNOWN,
        administrative_state=AdministrativeState.UNKNOWN,
        media_state=MediaState.UNKNOWN,
        mac_address=mac_address,
        mtu=mtu,
        receive_link_speed_bps=None,
        transmit_link_speed_bps=None,
        is_hardware=True,
    )
