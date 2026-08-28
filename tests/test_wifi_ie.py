import random

from wlanscope.platform.windows.wifi_ie import (
    MAX_INFORMATION_ELEMENT_BLOB_SIZE,
    capability_flags,
    decode_rate_set,
    parse_information_elements,
)


def test_parses_high_value_information_elements() -> None:
    rsn = bytes.fromhex("0100 000fac04 0100 000fac04 0100 000fac08 c000")
    blob = b"".join(
        (
            bytes((0, 4)) + b"TEST",
            bytes((1, 2, 0x82, 0x84)),
            bytes((7, 3)) + b"US ",
            bytes((45, 1, 0)),
            bytes((48, len(rsn))) + rsn,
            bytes((50, 1, 0x8B)),
            bytes((61, 1, 0)),
            bytes((127, 1, 0)),
            bytes((191, 1, 0)),
            bytes((192, 1, 0)),
            bytes((221, 4)) + bytes.fromhex("00112201"),
            bytes((255, 2, 35, 0)),
        )
    )

    summary = parse_information_elements(blob)

    assert summary.supported_rates_mbps == (1.0, 2.0, 5.5)
    assert summary.country_code == "US"
    assert summary.ht_capabilities_present
    assert summary.ht_operation_present
    assert summary.vht_capabilities_present
    assert summary.vht_operation_present
    assert summary.extended_capabilities_present
    assert summary.extension_element_ids == (35,)
    assert summary.vendor_specific_ouis == ("00:11:22",)
    assert not summary.malformed
    assert summary.rsn is not None
    assert summary.rsn.group_cipher == "CCMP-128"
    assert summary.rsn.pairwise_ciphers == ("CCMP-128",)
    assert summary.rsn.akm_suites == ("SAE",)
    assert summary.rsn.mfp_capable
    assert summary.rsn.mfp_required


def test_zero_length_and_unknown_elements_are_preserved_safely() -> None:
    summary = parse_information_elements(bytes((99, 0, 99, 0, 3, 1, 6)))

    assert summary.unknown_element_ids == (99,)
    assert not summary.malformed


def test_truncated_header_is_marked_malformed() -> None:
    assert parse_information_elements(b"\x01").malformed


def test_declared_length_beyond_blob_is_marked_malformed() -> None:
    assert parse_information_elements(b"\x01\x05\x82").malformed


def test_malformed_rsn_is_marked_without_crashing() -> None:
    summary = parse_information_elements(b"\x30\x04\x01\x00\x00\x0f")

    assert summary.rsn is None
    assert summary.malformed


def test_unsupported_rsn_version_is_rejected() -> None:
    rsn = bytes.fromhex("0200 000fac04 0100 000fac04 0100 000fac08")

    summary = parse_information_elements(bytes((48, len(rsn))) + rsn)

    assert summary.rsn is None
    assert summary.malformed


def test_unknown_rsn_suites_are_preserved_as_selectors() -> None:
    rsn = bytes.fromhex("0100 00112209 0100 00112208 0100 00112207")
    summary = parse_information_elements(bytes((48, len(rsn))) + rsn)

    assert summary.rsn is not None
    assert summary.rsn.group_cipher == "00:11:22:09"
    assert summary.rsn.pairwise_ciphers == ("00:11:22:08",)
    assert summary.rsn.akm_suites == ("00:11:22:07",)
    assert summary.rsn.mfp_capable is None


def test_rsn_optional_pmkid_and_group_management_cipher_are_validated() -> None:
    rsn = bytes.fromhex(
        "0100 000fac04 0100 000fac04 0100 000fac08 c000 "
        "0100 000102030405060708090a0b0c0d0e0f 000fac06"
    )
    summary = parse_information_elements(bytes((48, len(rsn))) + rsn)

    assert summary.rsn is not None
    assert summary.rsn.group_management_cipher == "BIP-CMAC-128"


def test_truncated_rsn_optional_section_is_malformed() -> None:
    rsn = bytes.fromhex("0100 000fac04 0100 000fac04 0100 000fac08 c000 0100 00")

    assert parse_information_elements(bytes((48, len(rsn))) + rsn).malformed


def test_invalid_country_and_short_vendor_ie_are_safe() -> None:
    summary = parse_information_elements(b"\x07\x03\x00\xff \xdd\x02\x00\x11")

    assert summary.country_code is None
    assert summary.malformed


def test_empty_extension_is_malformed() -> None:
    assert parse_information_elements(b"\xff\x00").malformed


def test_oversized_blob_is_rejected_before_parsing() -> None:
    summary = parse_information_elements(b"\x00" * (MAX_INFORMATION_ELEMENT_BLOB_SIZE + 1))

    assert summary.malformed


def test_rate_set_decoding_separates_basic_rates() -> None:
    supported, basic = decode_rate_set((0x8002, 0x0004, 0, 0x800B))

    assert supported == (1.0, 2.0, 5.5)
    assert basic == (1.0, 5.5)


def test_capability_flags_decode_only_documented_bits() -> None:
    assert capability_flags(0xFFFF) == (
        "ESS",
        "IBSS",
        "Privacy",
        "Short preamble",
        "Short slot time",
    )


def test_deterministic_arbitrary_bytes_do_not_raise() -> None:
    randomizer = random.Random(106)

    for length in range(128):
        blob = bytes(randomizer.randrange(256) for _ in range(length))
        first = parse_information_elements(blob)
        second = parse_information_elements(blob)
        assert first == second
