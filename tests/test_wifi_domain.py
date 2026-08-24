import pytest

from wlanscope.domain.wifi import (
    WifiAuthentication,
    WifiBssid,
    WifiCipher,
    WifiConnection,
    WifiConnectionMode,
    WifiInterfaceSnapshot,
    WifiInterfaceState,
    WifiPhyType,
    WifiSecurity,
    WifiSsid,
)


@pytest.mark.parametrize(
    ("raw", "display"),
    [
        (b"SANITIZED", "SANITIZED"),
        (b"Rede de teste", "Rede de teste"),
        (b"invalid-\xff", "invalid-\\xff"),
        (b"", ""),
        (b"prefix\x00suffix", "prefix\\x00suffix"),
    ],
)
def test_ssid_preserves_bytes_and_produces_safe_text(raw: bytes, display: str) -> None:
    ssid = WifiSsid(raw)

    assert ssid.raw == raw
    assert ssid.display_text == display
    assert ssid.is_empty is (not raw)


def test_ssid_accepts_maximum_length() -> None:
    assert len(WifiSsid(b"x" * 32).raw) == 32


def test_ssid_rejects_excessive_length() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        WifiSsid(b"x" * 33)


def test_bssid_has_distinct_validated_representation() -> None:
    bssid = WifiBssid(bytes.fromhex("020000000011"))

    assert str(bssid) == "02:00:00:00:00:11"


@pytest.mark.parametrize("octets", [b"", b"\x00" * 6, b"\x02" * 7])
def test_bssid_rejects_invalid_values(octets: bytes) -> None:
    with pytest.raises(ValueError):
        WifiBssid(octets)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (WifiConnectionMode(0), "Profile"),
        (WifiPhyType(10), "HE"),
        (WifiPhyType(11), "EHT"),
        (WifiAuthentication(6), "RSNA"),
        (WifiAuthentication(9), "WPA3-SAE"),
        (WifiCipher(4), "CCMP"),
        (WifiPhyType(99), "Unknown (99)"),
        (WifiAuthentication(200), "Unknown (200)"),
        (WifiCipher(201), "Unknown (201)"),
    ],
)
def test_native_values_preserve_known_and_unknown_values(value: object, expected: str) -> None:
    assert isinstance(value, (WifiConnectionMode, WifiPhyType, WifiAuthentication, WifiCipher))
    assert value.display_name == expected


@pytest.mark.parametrize("quality", [-1, 101])
def test_connection_rejects_signal_outside_windows_range(quality: int) -> None:
    with pytest.raises(ValueError, match="Signal quality"):
        _connection(signal_quality=quality)


@pytest.mark.parametrize("rate", [-1, 0])
def test_connection_rejects_nonpositive_rates(rate: int) -> None:
    with pytest.raises(ValueError, match="Receive rate"):
        _connection(receive_rate_kbps=rate)


def test_disconnected_interface_rejects_connection_details() -> None:
    with pytest.raises(ValueError, match="disconnected"):
        WifiInterfaceSnapshot(
            interface_id="aaaaaaaa-0000-0000-0000-000000000001",
            description="Sanitized wireless adapter",
            state=WifiInterfaceState(4),
            connection=_connection(),
        )


def _connection(
    signal_quality: int = 75,
    receive_rate_kbps: int | None = 866_700,
) -> WifiConnection:
    return WifiConnection(
        state=WifiInterfaceState(1),
        mode=WifiConnectionMode(0),
        profile_name="SANITIZED",
        ssid=WifiSsid(b"SANITIZED"),
        bssid=WifiBssid(bytes.fromhex("020000000011")),
        phy_type=WifiPhyType(8),
        signal_quality=signal_quality,
        receive_rate_kbps=receive_rate_kbps,
        transmit_rate_kbps=866_700,
        security=WifiSecurity(True, WifiAuthentication(6), WifiCipher(4)),
    )
