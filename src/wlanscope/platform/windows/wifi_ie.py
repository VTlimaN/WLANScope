from __future__ import annotations

from dataclasses import dataclass

from wlanscope.domain.nearby_wifi import WifiInformationElementSummary, WifiRsnDetails

MAX_INFORMATION_ELEMENT_BLOB_SIZE = 2324


@dataclass(frozen=True, slots=True)
class _Elements:
    rates: tuple[float, ...]
    country: str | None
    rsn: WifiRsnDetails | None
    ht_capabilities: bool
    ht_operation: bool
    vht_capabilities: bool
    vht_operation: bool
    extended_capabilities: bool
    extensions: tuple[int, ...]
    vendor_ouis: tuple[str, ...]
    unknown: tuple[int, ...]
    malformed: bool


def parse_information_elements(blob: bytes) -> WifiInformationElementSummary:
    if len(blob) > MAX_INFORMATION_ELEMENT_BLOB_SIZE:
        return WifiInformationElementSummary(available=True, malformed=True)
    rates: list[float] = []
    country: str | None = None
    rsn: WifiRsnDetails | None = None
    flags: set[int] = set()
    extensions: set[int] = set()
    vendors: set[str] = set()
    unknown: set[int] = set()
    malformed = False
    offset = 0
    while offset < len(blob):
        if len(blob) - offset < 2:
            malformed = True
            break
        element_id = blob[offset]
        length = blob[offset + 1]
        offset += 2
        end = offset + length
        if end > len(blob):
            malformed = True
            break
        payload = blob[offset:end]
        offset = end
        if element_id in {1, 50}:
            rates.extend(_rates(payload))
        elif element_id == 7:
            country = _country(payload) or country
        elif element_id == 48:
            parsed_rsn = _parse_rsn(payload)
            if parsed_rsn is None:
                malformed = True
            elif rsn is None:
                rsn = parsed_rsn
        elif element_id in {45, 61, 127, 191, 192}:
            flags.add(element_id)
        elif element_id == 221:
            if len(payload) >= 3:
                vendors.add(":".join(f"{value:02X}" for value in payload[:3]))
            else:
                malformed = True
        elif element_id == 255:
            if payload:
                extensions.add(payload[0])
            else:
                malformed = True
        elif element_id not in {0, 3}:
            unknown.add(element_id)
    return WifiInformationElementSummary(
        available=bool(blob),
        supported_rates_mbps=tuple(dict.fromkeys(rates)),
        country_code=country,
        rsn=rsn,
        ht_capabilities_present=45 in flags,
        ht_operation_present=61 in flags,
        vht_capabilities_present=191 in flags,
        vht_operation_present=192 in flags,
        extended_capabilities_present=127 in flags,
        extension_element_ids=tuple(sorted(extensions)),
        vendor_specific_ouis=tuple(sorted(vendors)),
        unknown_element_ids=tuple(sorted(unknown)),
        malformed=malformed,
    )


def decode_rate_set(values: tuple[int, ...]) -> tuple[tuple[float, ...], tuple[float, ...]]:
    supported = tuple(dict.fromkeys((value & 0x7FFF) * 0.5 for value in values if value & 0x7FFF))
    basic = tuple(
        rate
        for value, rate in zip(values, ((value & 0x7FFF) * 0.5 for value in values), strict=True)
        if value & 0x8000 and rate > 0
    )
    return supported, tuple(dict.fromkeys(basic))


def capability_flags(value: int) -> tuple[str, ...]:
    names = (
        (0x0001, "ESS"),
        (0x0002, "IBSS"),
        (0x0010, "Privacy"),
        (0x0020, "Short preamble"),
        (0x0400, "Short slot time"),
    )
    return tuple(name for mask, name in names if value & mask)


def _rates(payload: bytes) -> tuple[float, ...]:
    return tuple((value & 0x7F) * 0.5 for value in payload if value & 0x7F)


def _country(payload: bytes) -> str | None:
    if len(payload) < 3:
        return None
    code = payload[:2]
    if not all(0x20 <= value <= 0x7E for value in code):
        return None
    return code.decode("ascii")


def _parse_rsn(payload: bytes) -> WifiRsnDetails | None:
    if len(payload) < 8:
        return None
    offset = 0
    version, offset = _u16(payload, offset)
    group, offset = _suite(payload, offset, "cipher")
    pairwise_count, offset = _u16(payload, offset)
    pairwise, offset = _suites(payload, offset, pairwise_count, "cipher")
    akm_count, offset = _u16(payload, offset)
    akm, offset = _suites(payload, offset, akm_count, "akm")
    if (
        version is None
        or group is None
        or pairwise_count is None
        or pairwise is None
        or akm_count is None
        or akm is None
    ):
        return None
    capabilities = None
    if len(payload) - offset >= 2:
        capabilities, offset = _u16(payload, offset)
    if capabilities is None:
        mfp_capable = None
        mfp_required = None
    else:
        mfp_capable = bool(capabilities & 0x0080)
        mfp_required = bool(capabilities & 0x0040)
    group_management_cipher = None
    if offset < len(payload):
        pmkid_count, offset = _u16(payload, offset)
        if pmkid_count is None or pmkid_count > 64:
            return None
        pmkid_size = pmkid_count * 16
        if len(payload) - offset < pmkid_size:
            return None
        offset += pmkid_size
        if len(payload) - offset == 4:
            group_management_cipher, offset = _suite(payload, offset, "cipher")
        elif offset != len(payload):
            return None
    if offset != len(payload):
        return None
    return WifiRsnDetails(
        version=version,
        group_cipher=group,
        pairwise_ciphers=pairwise,
        akm_suites=akm,
        mfp_capable=mfp_capable,
        mfp_required=mfp_required,
        group_management_cipher=group_management_cipher,
    )


def _u16(payload: bytes, offset: int) -> tuple[int | None, int]:
    if len(payload) - offset < 2:
        return None, offset
    return int.from_bytes(payload[offset : offset + 2], "little"), offset + 2


def _suite(payload: bytes, offset: int, kind: str) -> tuple[str | None, int]:
    if len(payload) - offset < 4:
        return None, offset
    selector = payload[offset : offset + 4]
    return _suite_name(selector, kind), offset + 4


def _suites(
    payload: bytes,
    offset: int,
    count: int | None,
    kind: str,
) -> tuple[tuple[str, ...] | None, int]:
    if count is None or count > 64 or len(payload) - offset < count * 4:
        return None, offset
    values: list[str] = []
    for _ in range(count):
        value, offset = _suite(payload, offset, kind)
        if value is None:
            return None, offset
        values.append(value)
    return tuple(values), offset


def _suite_name(selector: bytes, kind: str) -> str:
    oui = selector[:3]
    suite_type = selector[3]
    if oui != b"\x00\x0f\xac":
        return f"{oui.hex(':').upper()}:{suite_type:02X}"
    mappings = {
        "cipher": {
            0: "Use group",
            1: "WEP-40",
            2: "TKIP",
            4: "CCMP-128",
            5: "WEP-104",
            6: "BIP-CMAC-128",
            8: "GCMP-128",
            9: "GCMP-256",
            10: "CCMP-256",
        },
        "akm": {
            1: "802.1X",
            2: "PSK",
            3: "FT-802.1X",
            4: "FT-PSK",
            8: "SAE",
            12: "Suite-B-192",
            18: "OWE",
        },
    }
    return mappings[kind].get(suite_type, f"00:0F:AC:{suite_type:02X}")
