import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from tests.reporting_samples import sample_snapshot
from wlanscope.application.export_full_network_report import ExportFullNetworkReport
from wlanscope.cli import main
from wlanscope.domain.enrichment import EnrichmentSource, VendorResolution
from wlanscope.domain.full_scan import FullNetworkSnapshot, ScanSectionStatus
from wlanscope.domain.interfaces import InterfaceInventory
from wlanscope.domain.nearby_wifi import WifiAccessPointVendor
from wlanscope.domain.wifi import WifiSsid
from wlanscope.reporting.anonymization import ReportAnonymizer
from wlanscope.reporting.json_report import JsonValue, serialize_json_report
from wlanscope.reporting.markdown_report import render_markdown_report


def sanitized_fixture(
    status: ScanSectionStatus = ScanSectionStatus.SUCCESS,
) -> FullNetworkSnapshot:
    snapshot = sample_snapshot(
        status,
        "host.unique.corp.example",
        WifiSsid(b"Unique Wireless Name"),
    )
    assert snapshot.interfaces is not None
    interface = replace(
        snapshot.interfaces.interfaces[0],
        manufacturer="Example Vendor",
        driver_description="Example Driver",
    )
    assert snapshot.nearby_wifi is not None
    network = snapshot.nearby_wifi.networks[0]
    access_point = network.access_points[0]
    access_point = replace(
        access_point,
        vendor=WifiAccessPointVendor(
            access_point.vendor.state,
            "Example Vendor",
            EnrichmentSource.LOCAL_OUI_REGISTRY,
        ),
        information_elements=replace(
            access_point.information_elements,
            wps=replace(
                access_point.information_elements.wps,
                manufacturer="Example Vendor",
            ),
        ),
    )
    nearby = replace(
        snapshot.nearby_wifi,
        networks=(replace(network, access_points=(access_point,)),),
    )
    assert snapshot.devices is not None
    enriched = snapshot.devices.hosts[0]
    vendor = VendorResolution(
        enriched.vendor.interface_index,
        enriched.vendor.address,
        enriched.vendor.state,
        "Example Vendor",
        EnrichmentSource.LOCAL_OUI_REGISTRY,
    )
    devices = replace(snapshot.devices, hosts=(replace(enriched, vendor=vendor),))
    return replace(
        snapshot,
        interfaces=InterfaceInventory((interface,)),
        nearby_wifi=nearby,
        devices=devices,
    )


def parsed(snapshot: FullNetworkSnapshot, anonymizer: ReportAnonymizer) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], json.loads(serialize_json_report(snapshot, anonymizer)))


def nested(value: JsonValue, *path: str | int) -> JsonValue:
    current = value
    for part in path:
        if isinstance(part, int):
            assert isinstance(current, list)
            current = current[part]
        else:
            assert isinstance(current, dict)
            current = current[part]
    return current


def test_anonymized_json_covers_direct_identifier_categories() -> None:
    report = parsed(sanitized_fixture(), ReportAnonymizer())

    assert report["anonymized"] is True
    assert nested(report, "data", "interfaces", "items", 0, "stable_id") == "ID-001"
    assert nested(report, "data", "interfaces", "items", 0, "alias") == "INTERFACE-001"
    assert nested(report, "data", "interfaces", "items", 0, "mac_address") == "MAC-001"
    assert nested(report, "data", "current_wifi", "interfaces", 0, "connection", "ssid") == {
        "display": "WIFI-001",
        "raw_hex": None,
        "hidden": False,
    }
    assert (
        nested(report, "data", "current_wifi", "interfaces", 0, "connection", "bssid")
        == "BSSID-001"
    )
    assert nested(report, "data", "devices", "hosts", 0, "address") == "IPV4-006"
    assert nested(report, "data", "devices", "hosts", 0, "hostname", "value") == "HOST-001"
    assert (
        nested(report, "data", "current_network", "interfaces", 0, "dns", "suffix") == "DOMAIN-001"
    )


def test_anonymized_dual_format_has_no_direct_identifier_leaks(tmp_path: Path) -> None:
    snapshot = sanitized_fixture()
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"

    ExportFullNetworkReport().execute(
        snapshot,
        json_path,
        markdown_path,
        anonymize=True,
    )

    json_text = json_path.read_text(encoding="utf-8")
    markdown_text = markdown_path.read_text(encoding="utf-8")
    combined = json_text + markdown_text
    for original in (
        "host.unique.corp.example",
        "Example Driver",
        "Unique Wireless Name",
        "556e6971756520576972656c657373204e616d65".lower(),
        "11111111-1111-1111-1111-111111111111",
        "00:11:22:33:44:55",
        "00:11:22:33:44:66",
        "00:11:22:33:44:77",
        "192.0.2.10",
        "192.0.2.20",
        "2001:db8::10",
    ):
        assert original not in combined
    assert "Example Vendor" in combined
    assert "Identifiers: anonymized" in markdown_text


def test_dual_format_reuses_alias_mapping_and_snapshot_is_unchanged(tmp_path: Path) -> None:
    snapshot = sanitized_fixture()
    original = snapshot
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"

    ExportFullNetworkReport().execute(
        snapshot,
        json_path,
        markdown_path,
        anonymize=True,
    )

    json_text = json_path.read_text(encoding="utf-8")
    markdown_text = markdown_path.read_text(encoding="utf-8")
    assert "IPV4-001" in json_text and "IPV4-001" in markdown_text
    assert "BSSID-001" in json_text and "BSSID-001" in markdown_text
    assert snapshot == original


def test_hidden_ssid_remains_hidden_without_raw_leak() -> None:
    report = parsed(
        sample_snapshot(ssid=WifiSsid(b"")),
        ReportAnonymizer(),
    )

    assert nested(report, "data", "nearby_wifi", "networks", 0, "ssid") == {
        "display": "<Hidden>",
        "raw_hex": "",
        "hidden": True,
    }


@pytest.mark.parametrize("status", [ScanSectionStatus.PARTIAL, ScanSectionStatus.FAILED])
def test_partial_and_failed_snapshots_anonymize(status: ScanSectionStatus) -> None:
    report = parsed(sanitized_fixture(status), ReportAnonymizer())

    assert report["anonymized"] is True
    assert nested(report, "scan", "status") == status.name.lower()


def test_fresh_contexts_have_deterministic_first_seen_aliases() -> None:
    snapshot = sanitized_fixture()

    first = serialize_json_report(snapshot, ReportAnonymizer())
    second = serialize_json_report(snapshot, ReportAnonymizer())

    assert first == second


def test_issue_text_sanitizes_embedded_ipv6_address() -> None:
    anonymizer = ReportAnonymizer()

    sanitized = anonymizer.sanitize_text("lookup failed for 2001:db8:ffff::1234")

    assert sanitized == "lookup failed for IPV6-001"


def test_alias_never_equals_the_original_identifier() -> None:
    anonymizer = ReportAnonymizer()

    assert anonymizer.ssid("WIFI-001") == "WIFI-002"


def test_finalized_aliases_do_not_collide_with_other_identifier_categories() -> None:
    anonymizer = ReportAnonymizer()
    anonymizer.hostname("internal-host")
    anonymizer.ssid("HOST-001")

    anonymizer.finalize_aliases()

    assert anonymizer.hostname("internal-host") != "HOST-001"
    assert anonymizer.hostname("internal-host") != anonymizer.ssid("HOST-001")


def test_issue_text_replaces_registered_identifier_inside_message() -> None:
    anonymizer = ReportAnonymizer()
    alias = anonymizer.interface("SecretAdapter")

    assert anonymizer.sanitize_text("Failure on adapter SecretAdapter") == (
        f"Failure on adapter {alias}"
    )


def test_issue_text_sanitizes_windows_path_containing_spaces() -> None:
    anonymizer = ReportAnonymizer()

    sanitized = anonymizer.sanitize_text(
        "Failed at 'C:\\Users\\Example User\\Private\\report.json'"
    )

    assert sanitized == "Failed at PATH-001"


def test_normal_report_preserves_identifiers_and_false_metadata() -> None:
    snapshot = sanitized_fixture()
    json_text = serialize_json_report(snapshot)
    markdown = render_markdown_report(snapshot)

    assert '"anonymized": false' in json_text
    assert "host.unique.corp.example" in json_text
    assert "Identifiers: not anonymized" in markdown


def test_anonymize_without_report_is_usage_error_before_scan() -> None:
    with pytest.raises(SystemExit) as error:
        main(["scan", "--anonymize"])

    assert error.value.code == 2
