from __future__ import annotations

import re
from datetime import UTC, datetime

from wlanscope.domain.full_scan import FullNetworkSnapshot
from wlanscope.domain.nearby_wifi import WifiNetwork
from wlanscope.domain.wifi import WifiSsid
from wlanscope.reporting.json_report import REPORT_SCHEMA_VERSION
from wlanscope.version import __version__

_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LOCAL_PATH = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\s\"']+")
_MARKDOWN_SPECIAL = frozenset("\\|`*_[]<>")


def render_markdown_report(snapshot: FullNetworkSnapshot) -> str:
    lines = [
        "# WLANScope Network Report",
        "",
        f"- Tool version: {escape_markdown(__version__)}",
        f"- Report schema: {REPORT_SCHEMA_VERSION}",
        f"- Scan started: {_timestamp(snapshot.started_at)}",
        f"- Scan completed: {_timestamp(snapshot.completed_at)}",
        f"- Global status: {snapshot.status.value}",
        "",
        "## Scan Summary",
        "",
        "| Section | Status |",
        "|---|---|",
    ]
    lines.extend(
        f"| {escape_markdown(result.section.value)} | {result.status.value} |"
        for result in snapshot.sections
    )
    lines.extend(("", "## Network Interfaces", ""))
    _render_interfaces(snapshot, lines)
    lines.extend(("", "## Current Wi-Fi", ""))
    _render_current_wifi(snapshot, lines)
    lines.extend(("", "## Current Network", ""))
    _render_current_network(snapshot, lines)
    lines.extend(("", "## Nearby Wi-Fi", ""))
    _render_nearby_wifi(snapshot, lines)
    lines.extend(("", "## Observed Devices", ""))
    _render_devices(snapshot, lines)
    lines.extend(("", "## Issues", ""))
    if snapshot.issues:
        lines.extend(
            f"- **{escape_markdown(issue.section.value)}:** "
            f"{escape_markdown(_sanitize_issue(issue.message))}"
            for issue in snapshot.issues
        )
    else:
        lines.append("No scan issues were reported.")
    lines.extend(
        (
            "",
            "## Limitations and Interpretation",
            "",
            "This report is a point-in-time composition of observations collected sequentially. "
            "Wi-Fi, routing, and device state can change during or after the scan.",
            "",
            "Observed hosts are not a complete router client list. Firewalls, privacy controls, "
            "radio conditions, stale neighbor entries, and unavailable enrichment sources can "
            "limit results.",
            "",
        )
    )
    return "\n".join(lines)


def escape_markdown(value: str) -> str:
    cleaned = _CONTROL.sub("", _ANSI_ESCAPE.sub("", value)).replace("\r\n", "\n")
    escaped = "".join(
        f"\\{character}" if character in _MARKDOWN_SPECIAL else character for character in cleaned
    )
    return escaped.replace("\n", "<br>")


def _render_interfaces(snapshot: FullNetworkSnapshot, lines: list[str]) -> None:
    if snapshot.interfaces is None:
        lines.append("Unavailable.")
        return
    lines.extend(
        (
            "| Index | Name | Kind | State | MAC | MTU |",
            "|---:|---|---|---|---|---:|",
        )
    )
    for item in snapshot.interfaces.interfaces:
        lines.append(
            _row(
                str(item.interface_index),
                item.friendly_name,
                item.kind.value,
                item.operational_state.value,
                str(item.mac_address) if item.mac_address else "Unknown",
                str(item.mtu) if item.mtu else "Unknown",
            )
        )


def _render_current_wifi(snapshot: FullNetworkSnapshot, lines: list[str]) -> None:
    if snapshot.current_wifi is None:
        lines.append("Unavailable.")
        return
    if not snapshot.current_wifi.interfaces:
        lines.append("No WLAN interfaces were reported.")
        return
    for interface in snapshot.current_wifi.interfaces:
        lines.extend(
            (
                f"### {escape_markdown(interface.description)}",
                "",
                f"- Interface ID: {escape_markdown(interface.interface_id)}",
                f"- State: {escape_markdown(interface.state.display_name)}",
            )
        )
        connection = interface.connection
        if connection is None:
            lines.extend(("- Connection: Unavailable", ""))
            continue
        lines.extend(
            (
                f"- SSID: {_ssid_display(connection.ssid)}",
                f"- SSID raw hex: `{connection.ssid.raw.hex()}`",
                f"- BSSID: {connection.bssid}",
                f"- Profile: {_value(connection.profile_name)}",
                f"- PHY: {escape_markdown(connection.phy_type.display_name)}",
                f"- Signal quality: {connection.signal_quality}%",
                "- Authentication: "
                f"{escape_markdown(connection.security.authentication.display_name)}",
                f"- Cipher: {escape_markdown(connection.security.cipher.display_name)}",
                "",
            )
        )


def _render_current_network(snapshot: FullNetworkSnapshot, lines: list[str]) -> None:
    network = snapshot.current_network
    if network is None:
        lines.append("Unavailable.")
        return
    lines.extend(
        (
            "### IP Assignments",
            "",
            "| Interface | Address | Prefix | Network | DAD state |",
            "|---:|---|---:|---|---|",
        )
    )
    for context in network.interfaces:
        for assignment in context.addresses:
            lines.append(
                _row(
                    str(context.interface_index),
                    str(assignment.address),
                    str(assignment.prefix_length),
                    str(assignment.network),
                    assignment.dad_state.display_name,
                )
            )
    lines.extend(("", "### DNS and DHCP", ""))
    for context in network.interfaces:
        servers = (
            ", ".join(str(server) for server in context.dns.servers)
            if context.dns
            else "Unavailable"
        )
        suffix = _value(context.dns.suffix if context.dns else None)
        lines.extend(
            (
                f"- Interface {context.interface_index}",
                f"  - DNS servers: {escape_markdown(servers)}",
                f"  - DNS suffix: {suffix}",
                f"  - DHCP IPv4: {context.dhcp.ipv4_state.value}",
                f"  - DHCP IPv6: {context.dhcp.ipv6_state.value}",
                "  - DHCP server: "
                f"{_value(str(context.dhcp.server) if context.dhcp.server else None)}",
            )
        )
    lines.extend(("", "### Default Routes", ""))
    if not network.default_routes:
        lines.append("No default routes were reported.")
    else:
        lines.extend(
            (
                "| Destination | Next hop | Interface | Route metric | Effective metric |",
                "|---|---|---:|---:|---:|",
            )
        )
        for route in network.default_routes:
            lines.append(
                _row(
                    str(route.destination),
                    str(route.next_hop),
                    str(route.interface_index),
                    str(route.route_metric),
                    str(route.effective_metric)
                    if route.effective_metric is not None
                    else "Unknown",
                )
            )


def _render_nearby_wifi(snapshot: FullNetworkSnapshot, lines: list[str]) -> None:
    nearby = snapshot.nearby_wifi
    if nearby is None:
        lines.append("Unavailable.")
        return
    if not nearby.networks:
        lines.append("No nearby Wi-Fi networks were reported.")
        return
    lines.extend(
        (
            "| SSID | Interface | Signal | Security | Reported BSS | Observed BSS |",
            "|---|---|---:|---|---:|---:|",
        )
    )
    for network in nearby.networks:
        lines.append(
            _row(
                _ssid_plain(network.ssid),
                network.interface_description,
                f"{network.signal_quality}%",
                f"{network.authentication.display_name} / {network.cipher.display_name}",
                str(network.reported_bss_count),
                str(len(network.access_points)),
            )
        )
    for index, network in enumerate(nearby.networks, 1):
        _render_access_points(index, network, lines)


def _render_access_points(index: int, network: WifiNetwork, lines: list[str]) -> None:
    lines.extend(("", f"### Network {index}: {_ssid_display(network.ssid)}", ""))
    if not network.access_points:
        lines.append("No BSS observations were reported.")
        return
    lines.extend(
        (
            "| BSSID | PHY | Signal | RSSI | Frequency kHz | Band | Channel |",
            "|---|---|---:|---:|---:|---|---:|",
        )
    )
    for access_point in network.access_points:
        lines.append(
            _row(
                str(access_point.bssid),
                access_point.phy_type.display_name,
                f"{access_point.signal_quality}%",
                f"{access_point.rssi_dbm} dBm",
                str(access_point.center_frequency_khz),
                access_point.band.value,
                str(access_point.channel) if access_point.channel is not None else "Unknown",
            )
        )


def _render_devices(snapshot: FullNetworkSnapshot, lines: list[str]) -> None:
    devices = snapshot.devices
    if devices is None:
        lines.append("Unavailable.")
        return
    lines.extend(
        (
            f"- Discovery subnet: {devices.discovered.plan.subnet}",
            f"- Probes executed: {devices.discovered.probes_executed}",
            f"- Observed hosts: {len(devices.hosts)}",
            "",
            "| IP | Interface | MAC | Hostname | Vendor | Reachability | Sources |",
            "|---|---:|---|---|---|---|---|",
        )
    )
    for item in devices.hosts:
        host = item.discovered
        lines.append(
            _row(
                str(host.address),
                str(host.interface_index),
                str(host.mac_address) if host.mac_address else "Unknown",
                item.hostname.hostname or item.hostname.state.value,
                item.vendor.vendor or item.vendor.state.value,
                host.reachability.value,
                ", ".join(
                    source.value for source in sorted(host.sources, key=lambda source: source.name)
                ),
            )
        )


def _row(*values: str) -> str:
    return "| " + " | ".join(escape_markdown(value) for value in values) + " |"


def _ssid_plain(ssid: WifiSsid) -> str:
    return ssid.display_text if not ssid.is_empty else "<Hidden>"


def _ssid_display(ssid: WifiSsid) -> str:
    return escape_markdown(_ssid_plain(ssid))


def _value(value: str | None) -> str:
    return escape_markdown(value) if value else "Unavailable"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sanitize_issue(value: str) -> str:
    return _LOCAL_PATH.sub("<local-path>", value)
