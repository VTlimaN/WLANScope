from dataclasses import replace
from io import StringIO

import pytest
from rich.console import Console

from tests.reporting_samples import sample_snapshot
from wlanscope.cli import (
    _create_device_table,
    _create_interface_table,
    _create_nearby_wifi_table,
)
from wlanscope.domain.network import CurrentNetworkSnapshot
from wlanscope.domain.wifi import CurrentWifiSnapshot, WifiIssue, WifiIssueCode
from wlanscope.presentation.rendering import (
    create_full_scan_overview,
    create_full_scan_section_table,
    create_full_scan_summary,
    render_current_network_overview,
)


def render(renderable: object, width: int) -> str:
    output = StringIO()
    Console(file=output, force_terminal=False, width=width).print(renderable)
    rendered = output.getvalue()
    assert max(map(len, rendered.splitlines())) <= width
    return rendered


@pytest.mark.parametrize("width", (80, 120, 160))
def test_current_network_overview_at_supported_widths(width: int) -> None:
    snapshot = sample_snapshot(external_text="[red]danger[/red]")
    output = render(
        render_current_network_overview(snapshot.current_wifi, snapshot.current_network, width),
        width,
    )

    assert "Connection" in output
    assert "Addressing" in output
    assert "Wireless" in output
    assert "192.0.2.10/24" in output
    assert "[red]danger[/red]" in output


def test_current_network_overview_handles_partial_and_unavailable_data() -> None:
    snapshot = sample_snapshot()
    assert snapshot.current_wifi is not None
    partial_wifi = CurrentWifiSnapshot(
        snapshot.current_wifi.interfaces,
        (WifiIssue(WifiIssueCode.ACCESS_DENIED, "Optional source unavailable"),),
    )

    partial = render(
        render_current_network_overview(partial_wifi, snapshot.current_network, 120),
        120,
    )
    unavailable = render(render_current_network_overview(None, None, 80), 80)
    assert "[ Partial ]" in partial
    assert "[ Unavailable ]" in unavailable


@pytest.mark.parametrize("version", (4, 6))
def test_current_network_overview_handles_single_ip_family_without_profile(version: int) -> None:
    snapshot = sample_snapshot()
    assert snapshot.current_network is not None
    context = snapshot.current_network.interfaces[0]
    addresses = tuple(item for item in context.addresses if item.address.version == version)
    routes = tuple(
        item for item in snapshot.current_network.routes if item.destination.version == version
    )
    network = CurrentNetworkSnapshot((replace(context, addresses=addresses, profile=None),), routes)

    output = render(render_current_network_overview(snapshot.current_wifi, network, 120), 120)
    assert f"Primary IPv{version}" in output
    assert "Profile" in output
    assert "Unavailable" in output


@pytest.mark.parametrize("width", (80, 120, 160))
def test_lists_keep_critical_fields_and_adapt_secondary_fields(width: int) -> None:
    snapshot = sample_snapshot()
    assert snapshot.interfaces is not None
    assert snapshot.nearby_wifi is not None
    assert snapshot.devices is not None

    interfaces = render(_create_interface_table(snapshot.interfaces.interfaces, width), width)
    nearby = render(_create_nearby_wifi_table(snapshot.nearby_wifi.networks, width), width)
    devices = render(_create_device_table(snapshot.devices, width), width)
    assert "Idx" in interfaces and "Name" in interfaces
    assert "SSID" in nearby and "Signal" in nearby and "BSS" in nearby
    assert "IP" in devices and "MAC" in devices
    if width == 80:
        assert "Manufacturer" not in interfaces
        assert "Security" not in nearby
        assert "Hostname" not in devices
    elif width == 120:
        assert "Speed" in interfaces
        assert "Security" in nearby
        assert "Hostname" in devices
        assert "Role evidence" not in devices
    else:
        assert "Manufacturer" in interfaces
        assert "PHY" in nearby
        assert "Neighbor" in devices
        assert "Role evidence" in devices


@pytest.mark.parametrize("width", (80, 120, 160))
def test_full_scan_has_explicit_width_adaptation(width: int) -> None:
    snapshot = sample_snapshot()
    output = "".join(
        (
            render(create_full_scan_overview(snapshot), width),
            render(create_full_scan_section_table(snapshot), width),
            render(create_full_scan_summary(snapshot, width), width),
        )
    )

    assert "Overall Status" in output
    assert "Section Status" in output
    assert "Network Summary" in output
    assert "Observed hosts" in output
    if width == 80:
        assert "PTR resolved" not in output
    elif width == 120:
        assert "PTR resolved" in output
        assert "IPv4 default route" not in output
    else:
        assert "IPv4 default route" in output
