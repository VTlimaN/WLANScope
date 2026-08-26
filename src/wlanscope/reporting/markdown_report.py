from __future__ import annotations

import re
from datetime import UTC, datetime

from wlanscope.domain.full_scan import FullNetworkSnapshot
from wlanscope.domain.nearby_wifi import WifiNetwork
from wlanscope.domain.wifi import WifiAuthCipherCapabilities, WifiSsid
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
        if item.statistics is not None:
            received = _value(
                str(item.statistics.received_bytes)
                if item.statistics.received_bytes is not None
                else None
            )
            sent = _value(
                str(item.statistics.sent_bytes) if item.statistics.sent_bytes is not None else None
            )
            errors = (
                item.statistics.received_errors + item.statistics.outbound_errors
                if item.statistics.received_errors is not None
                and item.statistics.outbound_errors is not None
                else None
            )
            lines.extend(
                (
                    f"- Interface {item.interface_index} counters: "
                    f"received {received} bytes; sent {sent} bytes; "
                    f"errors {_value(str(errors) if errors is not None else None)}",
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
                "- BSS type: "
                f"{_value(connection.bss_type.display_name if connection.bss_type else None)}",
                f"- Profile: {_value(connection.profile_name)}",
                f"- PHY: {escape_markdown(connection.phy_type.display_name)}",
                f"- Signal quality: {connection.signal_quality}%",
                f"- RSSI: {interface.rssi_dbm} dBm"
                if interface.rssi_dbm is not None
                else "- RSSI: Unavailable",
                f"- Channel: {interface.channel_number}"
                if interface.channel_number is not None
                else "- Channel: Unavailable",
                f"- Operation mode: native value `0x{interface.operation_mode:08X}`"
                if interface.operation_mode is not None
                else "- Operation mode: Unavailable",
                "- Authentication: "
                f"{escape_markdown(connection.security.authentication.display_name)}",
                f"- Cipher: {escape_markdown(connection.security.cipher.display_name)}",
                "",
            )
        )
        if interface.capabilities is not None:
            phys = ", ".join(phy.display_name for phy in interface.capabilities.supported_phy_types)
            lines.extend(
                (
                    f"- Supported PHY types: {escape_markdown(phys) or 'Unknown'}",
                    "- 802.11d supported: "
                    f"{'Yes' if interface.capabilities.dot11d_supported else 'No'}",
                    "- Infrastructure auth/cipher capabilities: "
                    f"{_markdown_auth_cipher(interface.capabilities.infrastructure_security)}",
                    "- Ad hoc auth/cipher capabilities: "
                    f"{_markdown_auth_cipher(interface.capabilities.adhoc_security)}",
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
            "| Interface | Address | Prefix | Network | Classification | Origin | DAD state |",
            "|---:|---|---:|---|---|---|---|",
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
                    ", ".join(assignment.classifications) or "Unknown",
                    f"{assignment.prefix_origin.display_name} / "
                    f"{assignment.address_origin.display_name}",
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
        dns_registration = (
            _optional_boolean(context.dns.registration_enabled) if context.dns else "Unavailable"
        )
        dns_suffix_registration = (
            _optional_boolean(context.dns.suffix_registration_enabled)
            if context.dns
            else "Unavailable"
        )
        lease_obtained = _value(
            context.dhcp.lease_obtained.isoformat() if context.dhcp.lease_obtained else None
        )
        lease_expires = _value(
            context.dhcp.lease_expires.isoformat() if context.dhcp.lease_expires else None
        )
        lines.extend(
            (
                f"- Interface {context.interface_index}",
                f"  - DNS servers: {escape_markdown(servers)}",
                f"  - DNS suffix: {suffix}",
                f"  - DNS address registration: {dns_registration}",
                f"  - DNS suffix registration: {dns_suffix_registration}",
                f"  - DHCP IPv4: {context.dhcp.ipv4_state.value}",
                f"  - DHCP IPv6: {context.dhcp.ipv6_state.value}",
                "  - DHCP server: "
                f"{_value(str(context.dhcp.server) if context.dhcp.server else None)}",
                f"  - DHCP lease obtained: {lease_obtained}",
                f"  - DHCP lease expires: {lease_expires}",
            )
        )
        if context.profile is not None:
            lines.extend(
                (
                    f"  - Network profile: {_value(context.profile.name)}",
                    f"  - Profile interface alias: {_value(context.profile.interface_alias)}",
                    f"  - Network category: {_value(context.profile.category)}",
                    f"  - IPv4 connectivity: {context.profile.ipv4_connectivity.value}",
                    f"  - IPv6 connectivity: {context.profile.ipv6_connectivity.value}",
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
        rates = ", ".join(f"{rate:g}" for rate in access_point.supported_rates_mbps)
        flags = ", ".join(access_point.capability_flags)
        rsn = access_point.information_elements.rsn
        lines.extend(
            (
                f"- {access_point.bssid} supported rates: "
                f"{escape_markdown(rates) if rates else 'Unavailable'} Mbps",
                f"- {access_point.bssid} capabilities: "
                f"{escape_markdown(flags) if flags else 'None reported'}",
                f"- {access_point.bssid} RSN: {'Present' if rsn is not None else 'Unavailable'}",
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
        if host.is_router:
            lines.append(f"- {host.address}: router indication reported by neighbor cache")
        lines.append(
            f"- {host.address}: address classification "
            f"{escape_markdown(', '.join(host.address_classifications) or 'Unknown')}"
        )
        if host.mac_address is not None:
            lines.append(
                f"- {host.address}: locally administered MAC "
                f"{'Yes' if host.mac_address.is_locally_administered else 'No'}"
            )


def _row(*values: str) -> str:
    return "| " + " | ".join(escape_markdown(value) for value in values) + " |"


def _markdown_auth_cipher(item: WifiAuthCipherCapabilities) -> str:
    if not item.pairs:
        return item.state.value
    return escape_markdown(
        ", ".join(
            f"{pair.authentication.display_name} / {pair.cipher.display_name}"
            for pair in item.pairs
        )
    )


def _ssid_plain(ssid: WifiSsid) -> str:
    return ssid.display_text if not ssid.is_empty else "<Hidden>"


def _ssid_display(ssid: WifiSsid) -> str:
    return escape_markdown(_ssid_plain(ssid))


def _value(value: str | None) -> str:
    return escape_markdown(value) if value else "Unavailable"


def _optional_boolean(value: bool | None) -> str:
    if value is None:
        return "Unavailable"
    return "Yes" if value else "No"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sanitize_issue(value: str) -> str:
    return _LOCAL_PATH.sub("<local-path>", value)
