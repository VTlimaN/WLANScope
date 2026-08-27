import random

from wlanscope.domain.nearby_wifi import WifiWpsParseStatus, WifiWpsPresence
from wlanscope.platform.windows.wifi_ie import (
    MAX_INFORMATION_ELEMENT_BLOB_SIZE,
    parse_information_elements,
)


def tlv(attribute_id: int, value: bytes) -> bytes:
    return attribute_id.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def wps_ie(*attributes: bytes) -> bytes:
    payload = b"\x00\x50\xf2\x04" + b"".join(attributes)
    return bytes((221, len(payload))) + payload


def test_no_wps_is_distinct_from_unavailable_ie_data() -> None:
    absent = parse_information_elements(b"\x01\x01\x82").wps
    unavailable = parse_information_elements(b"").wps

    assert absent.presence is WifiWpsPresence.NOT_PRESENT
    assert unavailable.presence is WifiWpsPresence.UNAVAILABLE


def test_valid_wps_decodes_high_value_attributes() -> None:
    summary = parse_information_elements(
        wps_ie(
            tlv(0x104A, b"\x20"),
            tlv(0x1044, b"\x02"),
            tlv(0x1057, b"\x01"),
            tlv(0x1041, b"\x00"),
            tlv(0x1008, b"\x01\x80"),
            tlv(0x1012, b"\x00\x04"),
            tlv(0x1021, b"Example Corp"),
            tlv(0x1023, b"Router X"),
            tlv(0x1024, b"2"),
            tlv(0x1011, b"Example AP"),
        )
    )
    wps = summary.wps

    assert wps.presence is WifiWpsPresence.PRESENT
    assert wps.parse_status is WifiWpsParseStatus.COMPLETE
    assert wps.version == 0x20
    assert wps.state == 2
    assert wps.ap_setup_locked is True
    assert wps.selected_registrar is False
    assert wps.config_methods == ("Keypad", "Push Button")
    assert wps.device_password_id == 4
    assert wps.manufacturer == "Example Corp"
    assert wps.model_name == "Router X"
    assert wps.model_number == "2"
    assert wps.device_name == "Example AP"


def test_wps_not_configured_state_is_preserved() -> None:
    assert parse_information_elements(wps_ie(tlv(0x1044, b"\x01"))).wps.state == 1


def test_unknown_and_zero_length_attributes_are_tolerated() -> None:
    wps = parse_information_elements(wps_ie(tlv(0xFFFF, b""))).wps

    assert wps.presence is WifiWpsPresence.PRESENT
    assert wps.parse_status is WifiWpsParseStatus.COMPLETE


def test_zero_length_known_scalar_is_partial() -> None:
    wps = parse_information_elements(wps_ie(tlv(0x1044, b""))).wps

    assert wps.state is None
    assert wps.parse_status is WifiWpsParseStatus.PARTIAL


def test_truncated_tlv_header_and_length_overflow_are_partial() -> None:
    truncated = parse_information_elements(wps_ie(b"\x10\x44\x00")).wps
    overflow = parse_information_elements(wps_ie(b"\x10\x44\x00\x05\x02")).wps

    assert truncated.parse_status is WifiWpsParseStatus.PARTIAL
    assert overflow.parse_status is WifiWpsParseStatus.PARTIAL


def test_wrong_oui_and_wrong_type_are_not_wps() -> None:
    wrong_oui = bytes((221, 4)) + b"\x00\x50\xf3\x04"
    wrong_type = bytes((221, 4)) + b"\x00\x50\xf2\x05"

    assert parse_information_elements(wrong_oui).wps.presence is WifiWpsPresence.NOT_PRESENT
    assert parse_information_elements(wrong_type).wps.presence is WifiWpsPresence.NOT_PRESENT


def test_malformed_wps_vendor_header_does_not_claim_presence() -> None:
    summary = parse_information_elements(bytes((221, 3)) + b"\x00\x50\xf2")

    assert summary.malformed
    assert summary.wps.presence is WifiWpsPresence.NOT_PRESENT


def test_duplicate_wps_ies_merge_identical_values_and_count_ies() -> None:
    attribute = tlv(0x1044, b"\x02")
    wps = parse_information_elements(wps_ie(attribute) + wps_ie(attribute)).wps

    assert wps.ie_count == 2
    assert wps.state == 2
    assert wps.parse_status is WifiWpsParseStatus.COMPLETE


def test_conflicting_duplicate_wps_values_keep_first_and_mark_partial() -> None:
    wps = parse_information_elements(
        wps_ie(tlv(0x1044, b"\x01")) + wps_ie(tlv(0x1044, b"\x02"))
    ).wps

    assert wps.state == 1
    assert wps.parse_status is WifiWpsParseStatus.PARTIAL


def test_config_method_qualifiers_and_unknown_bits_are_preserved() -> None:
    wps = parse_information_elements(wps_ie(tlv(0x1008, b"\x0a\x80"))).wps

    assert wps.config_methods == ("Virtual Push Button",)
    assert wps.config_methods_unknown_bits == 0x0800


def test_arbitrary_bytes_are_deterministic_and_bounded() -> None:
    generator = random.Random(109)
    for length in range(0, 257, 17):
        blob = bytes(generator.randrange(256) for _ in range(length))
        assert parse_information_elements(blob) == parse_information_elements(blob)
    oversized = b"\x00" * (MAX_INFORMATION_ELEMENT_BLOB_SIZE + 1)
    assert parse_information_elements(oversized).malformed
