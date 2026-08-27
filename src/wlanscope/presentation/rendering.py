from __future__ import annotations

from rich.console import Group, RenderableType
from rich.panel import Panel

from wlanscope.domain.full_scan import FullNetworkSnapshot
from wlanscope.domain.interfaces import OperationalState
from wlanscope.domain.network import CurrentNetworkSnapshot, InterfaceNetworkContext
from wlanscope.domain.wifi import CurrentWifiSnapshot, WifiInterfaceSnapshot
from wlanscope.presentation.components import (
    create_empty_state,
    create_key_value_table,
    create_notice,
    create_status_badge,
)
from wlanscope.presentation.formatting import LayoutMode, format_duration, layout_mode, literal_text
from wlanscope.presentation.theme import BORDER


def render_current_network_overview(
    wifi: CurrentWifiSnapshot | None,
    network: CurrentNetworkSnapshot | None,
    terminal_width: int,
) -> RenderableType:
    context = _primary_context(network)
    wireless = _primary_wifi(wifi, context)
    has_data = context is not None or wireless is not None
    partial = bool(
        (wifi is not None and wifi.is_partial) or (network is not None and network.is_partial)
    )
    status = "Unavailable" if not has_data else "Partial" if partial else "Success"
    connection = create_key_value_table(
        (
            ("Medium", _medium(context, wireless)),
            ("Interface", _interface_name(context, wireless)),
            ("Profile", _profile_name(context, wireless)),
            ("IPv4 connectivity", _connectivity(context, 4)),
            ("IPv6 connectivity", _connectivity(context, 6)),
        )
    )
    addressing = create_key_value_table(
        (
            ("Primary IPv4", _primary_address(context, 4)),
            ("Primary IPv6", _primary_address(context, 6)),
            ("Default gateway", _default_gateways(network, context)),
            ("DNS", _dns_servers(context)),
        )
    )
    wireless_table = create_key_value_table(
        (
            ("SSID", _ssid(wireless)),
            ("Signal", _signal(wireless)),
            ("Channel", _channel(wireless)),
            ("PHY", _phy(wireless)),
            ("Security", _security(wireless)),
        )
    )
    panels = (
        Panel(connection, title="Connection", title_align="left", border_style=BORDER),
        Panel(addressing, title="Addressing", title_align="left", border_style=BORDER),
        Panel(wireless_table, title="Wireless", title_align="left", border_style=BORDER),
    )
    if layout_mode(terminal_width) is LayoutMode.WIDE:
        from rich.columns import Columns

        body: RenderableType = Columns(panels, equal=True, expand=True)
    else:
        body = Group(*panels)
    return Group(create_status_badge(status), body)


def create_full_scan_overview(snapshot: FullNetworkSnapshot) -> RenderableType:
    return Panel(
        create_key_value_table(
            (
                ("Overall status", create_status_badge(snapshot.status.value)),
                ("Duration", format_duration(snapshot.duration_seconds)),
                ("Issues", str(len(snapshot.issues))),
            )
        ),
        title="Overall Status",
        title_align="left",
        border_style=BORDER,
        expand=False,
    )


def create_full_scan_section_table(snapshot: FullNetworkSnapshot) -> RenderableType:
    table = create_key_value_table(())
    for result in snapshot.sections:
        table.add_row(result.section.value, create_status_badge(result.status.value))
    return Panel(
        table,
        title="Section Status",
        title_align="left",
        border_style=BORDER,
        expand=False,
    )


def create_full_scan_summary(
    snapshot: FullNetworkSnapshot,
    terminal_width: int = 120,
) -> RenderableType:
    mode = layout_mode(terminal_width)
    interfaces = snapshot.interfaces.interfaces if snapshot.interfaces is not None else ()
    connected_wifi = (
        any(interface.state.is_connected for interface in snapshot.current_wifi.interfaces)
        if snapshot.current_wifi is not None
        else False
    )
    contexts = snapshot.current_network.interfaces if snapshot.current_network is not None else ()
    addresses = tuple(address for context in contexts for address in context.addresses)
    routes = snapshot.current_network.default_routes if snapshot.current_network is not None else ()
    nearby_networks = snapshot.nearby_wifi.networks if snapshot.nearby_wifi is not None else ()
    devices = snapshot.devices
    rows: list[tuple[str, RenderableType]] = [
        ("Interfaces", str(len(interfaces))),
        (
            "Interfaces up",
            str(sum(item.operational_state is OperationalState.UP for item in interfaces)),
        ),
        ("Current Wi-Fi connected", "Yes" if connected_wifi else "No"),
        (
            "IPv4",
            "Present" if any(item.address.version == 4 for item in addresses) else "Unavailable",
        ),
        (
            "IPv6",
            "Present" if any(item.address.version == 6 for item in addresses) else "Unavailable",
        ),
        ("Nearby Wi-Fi networks", str(len(nearby_networks))),
        ("Observed hosts", str(len(devices.hosts)) if devices is not None else "Unavailable"),
    ]
    if mode is not LayoutMode.COMPACT:
        rows.extend(
            (
                ("Default routes", str(len(routes))),
                ("BSS observations", str(sum(len(item.access_points) for item in nearby_networks))),
                (
                    "PTR resolved",
                    str(devices.ptr_resolved_count) if devices is not None else "Unavailable",
                ),
                (
                    "Vendors resolved",
                    str(devices.vendor_resolved_count) if devices is not None else "Unavailable",
                ),
            )
        )
    if mode is LayoutMode.WIDE:
        rows.extend(
            (
                (
                    "IPv4 default route",
                    "Yes" if any(route.destination.version == 4 for route in routes) else "No",
                ),
                (
                    "IPv6 default route",
                    "Yes" if any(route.destination.version == 6 for route in routes) else "No",
                ),
            )
        )
    return Panel(
        create_key_value_table(rows),
        title="Network Summary",
        title_align="left",
        border_style=BORDER,
        expand=False,
    )


def create_full_scan_issues(snapshot: FullNetworkSnapshot) -> RenderableType:
    if not snapshot.issues:
        return create_empty_state("No issues reported.")
    messages = tuple(dict.fromkeys(issue.message for issue in snapshot.issues))
    status = "Failed" if snapshot.status.value == "Failed" else "Partial"
    return create_notice(status, "\n".join(messages), "Optional sections may be unavailable.")


def _primary_context(snapshot: CurrentNetworkSnapshot | None) -> InterfaceNetworkContext | None:
    if snapshot is None or not snapshot.interfaces:
        return None
    default_indices = {route.interface_index for route in snapshot.default_routes}
    return next(
        (context for context in snapshot.interfaces if context.interface_index in default_indices),
        snapshot.interfaces[0],
    )


def _primary_wifi(
    snapshot: CurrentWifiSnapshot | None,
    context: InterfaceNetworkContext | None,
) -> WifiInterfaceSnapshot | None:
    if context is not None and context.wifi_interface is not None:
        return context.wifi_interface
    if snapshot is None or not snapshot.interfaces:
        return None
    return next(
        (interface for interface in snapshot.interfaces if interface.state.is_connected),
        snapshot.interfaces[0],
    )


def _medium(
    context: InterfaceNetworkContext | None,
    wireless: WifiInterfaceSnapshot | None,
) -> str:
    if wireless is not None:
        return "Wi-Fi"
    if context is not None and context.network_interface is not None:
        return context.network_interface.kind.value
    return "Unavailable"


def _interface_name(
    context: InterfaceNetworkContext | None,
    wireless: WifiInterfaceSnapshot | None,
) -> RenderableType:
    if context is not None and context.network_interface is not None:
        return literal_text(context.network_interface.friendly_name)
    if wireless is not None:
        return literal_text(wireless.description)
    return "Unavailable"


def _profile_name(
    context: InterfaceNetworkContext | None,
    wireless: WifiInterfaceSnapshot | None,
) -> RenderableType:
    if context is not None and context.profile is not None and context.profile.name:
        return literal_text(context.profile.name)
    if (
        wireless is not None
        and wireless.connection is not None
        and wireless.connection.profile_name
    ):
        return literal_text(wireless.connection.profile_name)
    return "Unavailable"


def _connectivity(context: InterfaceNetworkContext | None, version: int) -> str:
    if context is None or context.profile is None:
        return "Unknown"
    value = context.profile.ipv4_connectivity if version == 4 else context.profile.ipv6_connectivity
    return value.value


def _primary_address(context: InterfaceNetworkContext | None, version: int) -> str:
    if context is None:
        return "Unavailable"
    assignment = next((item for item in context.addresses if item.address.version == version), None)
    if assignment is None:
        return "Unavailable"
    scope = f"%{assignment.scope_id}" if assignment.scope_id else ""
    return f"{assignment.address}{scope}/{assignment.prefix_length}"


def _default_gateways(
    snapshot: CurrentNetworkSnapshot | None,
    context: InterfaceNetworkContext | None,
) -> str:
    if snapshot is None:
        return "Unavailable"
    gateways = tuple(
        route.next_hop
        for route in snapshot.default_routes
        if context is None or route.interface_index == context.interface_index
    )
    return ", ".join(str(item) for item in gateways) or "Unavailable"


def _dns_servers(context: InterfaceNetworkContext | None) -> str:
    if context is None or context.dns is None:
        return "Unavailable"
    return ", ".join(str(item) for item in context.dns.servers) or "None configured"


def _ssid(wireless: WifiInterfaceSnapshot | None) -> RenderableType:
    if wireless is None or wireless.connection is None:
        return "Unavailable"
    return literal_text(wireless.connection.ssid.display_text or "<Hidden>")


def _signal(wireless: WifiInterfaceSnapshot | None) -> str:
    if wireless is None or wireless.connection is None:
        return "Unavailable"
    return f"{wireless.connection.signal_quality}%"


def _channel(wireless: WifiInterfaceSnapshot | None) -> str:
    if wireless is None or wireless.channel_number is None:
        return "Unavailable"
    return str(wireless.channel_number)


def _phy(wireless: WifiInterfaceSnapshot | None) -> str:
    if wireless is None or wireless.connection is None:
        return "Unavailable"
    return wireless.connection.phy_type.display_name


def _security(wireless: WifiInterfaceSnapshot | None) -> str:
    if wireless is None or wireless.connection is None:
        return "Unavailable"
    security = wireless.connection.security
    if not security.enabled:
        return "Open"
    return f"{security.authentication.display_name} / {security.cipher.display_name}"
