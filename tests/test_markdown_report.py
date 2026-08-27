from tests.reporting_samples import sample_snapshot
from wlanscope.domain.full_scan import ScanSectionStatus
from wlanscope.domain.wifi import WifiSsid
from wlanscope.reporting.markdown_report import escape_markdown, render_markdown_report


def test_markdown_contains_fixed_report_structure() -> None:
    report = render_markdown_report(sample_snapshot())

    for heading in (
        "# WLANScope Network Report",
        "## Scan Summary",
        "## Network Interfaces",
        "## Current Wi-Fi",
        "## Current Network",
        "## Nearby Wi-Fi",
        "## Observed Devices",
        "## Issues",
        "## Limitations and Interpretation",
    ):
        assert heading in report


def test_markdown_contains_snapshot_data_and_status() -> None:
    report = render_markdown_report(sample_snapshot(ScanSectionStatus.PARTIAL))

    assert "Global status: Partial" in report
    assert "192.0.2.10" in report
    assert "2001:db8::10" in report
    assert "00:11:22:33:44:77" in report
    assert "Observed hosts: 1" in report
    assert "Example Network issue" in report


def test_markdown_contains_grouped_deep_inspection_data() -> None:
    report = render_markdown_report(sample_snapshot())

    assert "received 1000 bytes" in report
    assert "RSSI: -51 dBm" in report
    assert "Network category: Private" in report
    assert "supported rates: 1, 2, 5.5 Mbps" in report
    assert "RSN: Present" in report
    assert "router indication reported by neighbor cache" in report
    assert "vendor: Example Network" in report
    assert "WPS present: Yes" in report
    assert "State: Configured" in report
    assert "AP Setup Locked: Yes" in report
    assert "Selected Registrar: No" in report


def test_markdown_escapes_external_values() -> None:
    external = r"pipe| tick` star* under_ [brackets] slash\ angle<>"
    report = render_markdown_report(sample_snapshot(external_text=external))

    for expected in (
        r"pipe\|",
        r"tick\`",
        r"star\*",
        r"under\_",
        r"\[brackets\]",
        r"slash\\",
        r"angle\<\>",
    ):
        assert expected in report
    assert f"| {external} |" not in report


def test_markdown_hidden_ssid_is_explicit() -> None:
    report = render_markdown_report(sample_snapshot(ssid=WifiSsid(b"")))

    assert r"\<Hidden\>" in report
    assert "SSID raw hex: ``" in report


def test_markdown_non_utf8_ssid_has_safe_display_and_raw_hex() -> None:
    report = render_markdown_report(sample_snapshot(ssid=WifiSsid(b"lab\xff")))

    assert r"lab\\xff" in report
    assert "SSID raw hex: `6c6162ff`" in report
    assert "b'lab" not in report


def test_markdown_strips_ansi_and_preserves_literal_rich_like_text() -> None:
    report = render_markdown_report(
        sample_snapshot(external_text="\x1b[31m[bold]literal[/bold]\x1b[0m")
    )

    assert "\x1b" not in report
    assert r"\[bold\]literal\[/bold\]" in report


def test_markdown_newlines_do_not_break_tables() -> None:
    escaped = escape_markdown("line one\nline two")

    assert escaped == "line one<br>line two"


def test_markdown_is_deterministic_and_has_final_newline() -> None:
    snapshot = sample_snapshot()

    first = render_markdown_report(snapshot)
    second = render_markdown_report(snapshot)

    assert first == second
    assert first.endswith("\n")


def test_markdown_sanitizes_local_paths_from_issue_messages() -> None:
    report = render_markdown_report(
        sample_snapshot(
            ScanSectionStatus.PARTIAL,
            external_text=r"C:\Users\Example\private.txt",
        )
    )

    assert "C:\\Users" not in report
    assert r"\<local-path\> issue" in report
