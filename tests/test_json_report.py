import json
from typing import cast

from tests.reporting_samples import sample_snapshot
from wlanscope.domain.full_scan import ScanSectionStatus
from wlanscope.domain.wifi import WifiSsid
from wlanscope.reporting.json_report import (
    REPORT_SCHEMA_VERSION,
    JsonValue,
    serialize_json_report,
)
from wlanscope.version import __version__


def parse_report(
    section_status: ScanSectionStatus = ScanSectionStatus.SUCCESS,
    external_text: str = "Example Network",
    ssid: WifiSsid | None = None,
) -> dict[str, JsonValue]:
    content = serialize_json_report(sample_snapshot(section_status, external_text, ssid))
    return cast(dict[str, JsonValue], json.loads(content))


def at(value: JsonValue, *path: str | int) -> JsonValue:
    current = value
    for part in path:
        if isinstance(part, int):
            assert isinstance(current, list)
            current = current[part]
        else:
            assert isinstance(current, dict)
            current = current[part]
    return current


def test_json_contract_has_independent_schema_and_tool_version() -> None:
    report = parse_report()

    assert report["schema_version"] == REPORT_SCHEMA_VERSION == "1.0"
    assert report["tool"] == {"name": "WLANScope", "version": __version__}
    assert tuple(report) == ("schema_version", "tool", "scan", "sections", "data", "issues")


def test_json_serializes_utc_timing_and_global_status() -> None:
    report = parse_report()

    assert at(report, "scan", "started_at") == "2026-01-02T03:04:05.000000Z"
    assert at(report, "scan", "completed_at") == "2026-01-02T03:04:07.000000Z"
    assert at(report, "scan", "status") == "success"


def test_json_preserves_section_status_and_partial_issues() -> None:
    report = parse_report(section_status=ScanSectionStatus.PARTIAL)

    assert at(report, "sections", "nearby_wifi", "status") == "partial"
    assert at(report, "scan", "status") == "partial"
    assert at(report, "issues", 0, "section") == "adapters"


def test_json_supports_failed_snapshot() -> None:
    report = parse_report(section_status=ScanSectionStatus.FAILED)

    assert at(report, "scan", "status") == "failed"


def test_json_maps_ip_routes_wifi_and_devices_explicitly() -> None:
    report = parse_report()

    assert (
        at(report, "data", "current_network", "interfaces", 0, "addresses", 0, "address")
        == "192.0.2.10"
    )
    assert (
        at(report, "data", "current_network", "interfaces", 0, "addresses", 1, "address")
        == "2001:db8::10"
    )
    assert at(report, "data", "current_network", "routes", 0, "destination") == "0.0.0.0/0"
    assert (
        at(report, "data", "nearby_wifi", "networks", 0, "access_points", 0, "bssid")
        == "00:11:22:33:44:77"
    )
    assert at(report, "data", "devices", "hosts", 0, "hostname", "value") == "Example Network"
    assert at(report, "data", "devices", "hosts", 0, "vendor", "source") == "local_oui_registry"
    assert at(report, "data", "devices", "hosts", 0, "discovery_sources") == [
        "icmp_response",
        "neighbor_cache",
    ]


def test_json_preserves_utf8_ssid_as_display_and_raw_hex() -> None:
    report = parse_report(ssid=WifiSsid("Caf\u00e9".encode()))
    ssid = at(report, "data", "current_wifi", "interfaces", 0, "connection", "ssid")

    assert ssid == {"display": "Caf\u00e9", "raw_hex": "436166c3a9", "hidden": False}


def test_json_preserves_hidden_ssid() -> None:
    report = parse_report(ssid=WifiSsid(b""))
    ssid = at(report, "data", "nearby_wifi", "networks", 0, "ssid")

    assert ssid == {"display": "<Hidden>", "raw_hex": "", "hidden": True}


def test_json_preserves_non_utf8_ssid_reversibly() -> None:
    report = parse_report(ssid=WifiSsid(b"lab\xff\x00"))
    ssid = at(report, "data", "current_wifi", "interfaces", 0, "connection", "ssid")

    assert at(ssid, "raw_hex") == "6c6162ff00"
    assert "\\xff" in cast(str, at(ssid, "display"))
    assert "\\x00" in cast(str, at(ssid, "display"))


def test_json_uses_stable_enum_contracts() -> None:
    report = parse_report()

    assert at(report, "data", "interfaces", "items", 0, "kind") == "wifi"
    assert (
        at(
            report,
            "data",
            "current_wifi",
            "interfaces",
            0,
            "connection",
            "phy_type",
        )
        == "he"
    )


def test_json_exports_deep_inspection_fields_without_raw_native_data() -> None:
    report = parse_report()

    assert at(report, "data", "interfaces", "items", 0, "statistics", "received_bytes") == 1000
    assert at(report, "data", "interfaces", "items", 0, "hardware", "connector_present")
    assert at(report, "data", "current_wifi", "interfaces", 0, "channel_number") == 36
    assert at(report, "data", "current_wifi", "interfaces", 0, "rssi_dbm") == -51
    assert (
        at(report, "data", "current_wifi", "interfaces", 0, "connection", "bss_type")
        == "infrastructure"
    )
    assert (
        at(
            report,
            "data",
            "current_wifi",
            "interfaces",
            0,
            "capabilities",
            "infrastructure_security",
            "state",
        )
        == "available"
    )
    assert (
        at(report, "data", "current_wifi", "interfaces", 0, "statistics", "phy_counters", 0)
        is not None
    )
    assert (
        at(report, "data", "current_network", "interfaces", 0, "profile", "category") == "Private"
    )
    assert at(report, "data", "current_network", "interfaces", 0, "addresses", 0, "classifications")
    assert at(report, "data", "current_network", "routes", 0, "is_on_link") is False
    access_point = at(report, "data", "nearby_wifi", "networks", 0, "access_points", 0)
    assert at(access_point, "supported_rates_mbps") == [1.0, 2.0, 5.5]
    assert at(access_point, "information_elements", "rsn", "akm_suites") == ["PSK"]
    assert "raw_blob" not in str(access_point)
    assert at(report, "data", "devices", "hosts", 0, "router_indication") is True
    assert at(report, "data", "devices", "hosts", 0, "address_classifications")


def test_unknown_native_values_have_stable_textual_representation() -> None:
    snapshot = sample_snapshot()
    assert snapshot.current_wifi is not None
    interface = snapshot.current_wifi.interfaces[0]
    connection = interface.connection
    assert connection is not None
    unknown = type(connection.phy_type)(999)
    replaced_connection = type(connection)(
        connection.state,
        connection.mode,
        connection.profile_name,
        connection.ssid,
        connection.bssid,
        unknown,
        connection.signal_quality,
        connection.receive_rate_kbps,
        connection.transmit_rate_kbps,
        connection.security,
    )
    replaced_interface = type(interface)(
        interface.interface_id,
        interface.description,
        interface.state,
        replaced_connection,
        interface.network_interface,
    )
    current_wifi = type(snapshot.current_wifi)((replaced_interface,))
    altered = type(snapshot)(
        snapshot.started_at,
        snapshot.completed_at,
        snapshot.sections,
        snapshot.interfaces,
        current_wifi,
        snapshot.current_network,
        snapshot.nearby_wifi,
        snapshot.devices,
    )
    report = parse_report()
    report = cast(dict[str, JsonValue], json.loads(serialize_json_report(altered)))

    assert (
        at(report, "data", "current_wifi", "interfaces", 0, "connection", "phy_type")
        == "unknown_999"
    )


def test_json_is_deterministic_utf8_and_has_final_newline() -> None:
    snapshot = sample_snapshot(external_text="Rede S\u00e3o Paulo")

    first = serialize_json_report(snapshot)
    second = serialize_json_report(snapshot)

    assert first == second
    assert "Rede S\u00e3o Paulo" in first
    assert first.endswith("\n")
    assert "\x1b" not in first


def test_json_sanitizes_local_paths_from_issue_messages() -> None:
    report = parse_report(
        section_status=ScanSectionStatus.PARTIAL,
        external_text=r"C:\Users\Example\private.txt",
    )

    assert at(report, "issues", 0, "message") == "<local-path> issue"
