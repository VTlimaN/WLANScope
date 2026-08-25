import argparse
from collections.abc import Sequence

from rich.console import Console
from rich.table import Table
from rich.text import Text

from wlanscope.application.inspect_current_network import InspectCurrentNetwork
from wlanscope.application.inspect_current_wifi import InspectCurrentWifi
from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.application.scan_nearby_wifi import ScanNearbyWifi
from wlanscope.domain.interfaces import InterfaceCollectionError, NetworkInterface
from wlanscope.domain.nearby_wifi import WifiNetwork
from wlanscope.domain.network import (
    UNUSED_ROUTE_METRIC,
    CurrentNetworkSnapshot,
    InterfaceNetworkContext,
    NetworkCollectionError,
    Route,
)
from wlanscope.domain.wifi import (
    CurrentWifiSnapshot,
    WifiCollectionError,
    WifiConnection,
    WifiInterfaceSnapshot,
)
from wlanscope.version import __version__

PROJECT_NAME = "WLANScope"
PROJECT_TAGLINE = "Windows Wireless & Network Reconnaissance"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wlanscope",
        description=f"{PROJECT_NAME} — {PROJECT_TAGLINE}",
        epilog="Created by sasser",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROJECT_NAME} {__version__}",
    )
    subcommands = parser.add_subparsers(dest="command")
    subcommands.add_parser(
        "adapters",
        help="List Windows network interfaces",
        description="List network interfaces reported by Windows.",
    )
    wifi_parser = subcommands.add_parser(
        "wifi",
        help="Inspect the current Wi-Fi connection",
        description="Inspect current Wi-Fi connection details reported by Windows.",
    )
    wifi_subcommands = wifi_parser.add_subparsers(dest="wifi_command")
    wifi_subcommands.add_parser(
        "scan",
        help="Discover nearby Wi-Fi networks",
        description="Discover nearby Wi-Fi networks and access points reported by Windows.",
    )
    subcommands.add_parser(
        "current",
        help="Inspect the current IP and routing context",
        description="Inspect current IP, routing, DNS, and DHCP context reported by Windows.",
    )
    return parser


def main(
    arguments: Sequence[str] | None = None,
    interface_use_case: ListNetworkInterfaces | None = None,
    wifi_use_case: InspectCurrentWifi | None = None,
    nearby_wifi_use_case: ScanNearbyWifi | None = None,
    current_use_case: InspectCurrentNetwork | None = None,
    console: Console | None = None,
) -> int:
    parser = build_parser()
    parsed_arguments = parser.parse_args(arguments)
    if parsed_arguments.command == "adapters":
        return _list_adapters(
            interface_use_case or _create_interface_use_case(),
            console or Console(),
        )
    if parsed_arguments.command == "wifi":
        if parsed_arguments.wifi_command == "scan":
            return _scan_nearby_wifi(
                nearby_wifi_use_case or _create_nearby_wifi_use_case(),
                console or Console(),
            )
        return _inspect_wifi(
            wifi_use_case or _create_wifi_use_case(),
            console or Console(),
        )
    if parsed_arguments.command == "current":
        return _inspect_current_network(
            current_use_case or _create_current_use_case(),
            console or Console(),
        )
    return 0


def _create_interface_use_case() -> ListNetworkInterfaces:
    from wlanscope.composition import create_list_network_interfaces

    return create_list_network_interfaces()


def _create_wifi_use_case() -> InspectCurrentWifi:
    from wlanscope.composition import create_inspect_current_wifi

    return create_inspect_current_wifi()


def _create_nearby_wifi_use_case() -> ScanNearbyWifi:
    from wlanscope.composition import create_scan_nearby_wifi

    return create_scan_nearby_wifi()


def _create_current_use_case() -> InspectCurrentNetwork:
    from wlanscope.composition import create_inspect_current_network

    return create_inspect_current_network()


def _list_adapters(use_case: ListNetworkInterfaces, console: Console) -> int:
    try:
        inventory = use_case.execute()
    except InterfaceCollectionError as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        return 1

    console.print(f"[bold]{PROJECT_NAME}[/bold]")
    console.print("Network Interfaces", style="dim")

    if not inventory.interfaces:
        console.print("No network interfaces were returned by Windows.")
    else:
        console.print(_create_interface_table(inventory.interfaces))

    for warning in inventory.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")

    return 3 if inventory.is_partial else 0


def _create_interface_table(interfaces: tuple[NetworkInterface, ...]) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Index", justify="right", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Name", overflow="fold")
    table.add_column("MAC", no_wrap=True)
    table.add_column("Link", justify="right", no_wrap=True)

    for interface in interfaces:
        table.add_row(
            str(interface.interface_index),
            interface.kind.value,
            interface.operational_state.value,
            interface.friendly_name,
            str(interface.mac_address) if interface.mac_address else "Unknown",
            _format_link_speed(interface),
        )
    return table


def _format_link_speed(interface: NetworkInterface) -> str:
    receive_speed = interface.receive_link_speed_bps
    transmit_speed = interface.transmit_link_speed_bps
    if receive_speed is None and transmit_speed is None:
        return "Unknown"
    if receive_speed == transmit_speed:
        return _format_bits_per_second(receive_speed)
    receive_text = _format_bits_per_second(receive_speed)
    transmit_text = _format_bits_per_second(transmit_speed)
    return f"Rx {receive_text} / Tx {transmit_text}"


def _format_bits_per_second(value: int | None) -> str:
    if value is None:
        return "Unknown"
    units = ((1_000_000_000, "Gbps"), (1_000_000, "Mbps"), (1_000, "Kbps"))
    for divisor, suffix in units:
        if value >= divisor:
            amount = value / divisor
            precision = 0 if amount.is_integer() else 1
            return f"{amount:.{precision}f} {suffix}"
    return f"{value} bps"


def _inspect_wifi(use_case: InspectCurrentWifi, console: Console) -> int:
    try:
        snapshot = use_case.execute()
    except WifiCollectionError as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        return 1

    console.print(f"[bold]{PROJECT_NAME}[/bold]")
    console.print("Current Wi-Fi", style="dim")
    if not snapshot.interfaces:
        console.print("No Wi-Fi interfaces were reported by Windows.")
    else:
        _render_wifi_interfaces(snapshot, console)

    for issue in snapshot.issues:
        console.print(f"[yellow]Warning:[/yellow] {issue.message}")
    return 3 if snapshot.is_partial else 0


def _render_wifi_interfaces(snapshot: CurrentWifiSnapshot, console: Console) -> None:
    multiple = len(snapshot.interfaces) > 1
    for position, interface in enumerate(snapshot.interfaces, start=1):
        if multiple:
            console.print(f"\n[bold]Interface {position}[/bold]")
        console.print(_create_wifi_table(interface))


def _create_wifi_table(interface: WifiInterfaceSnapshot) -> Table:
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value", overflow="fold")
    name = (
        interface.network_interface.friendly_name
        if interface.network_interface is not None
        else interface.description
    )
    table.add_row("Interface", Text(name))
    table.add_row("State", interface.state.display_name)
    if interface.connection is not None:
        _add_connection_rows(table, interface.connection)
    return table


def _add_connection_rows(table: Table, connection: WifiConnection) -> None:
    table.add_row("Connection state", connection.state.display_name)
    table.add_row("SSID", Text(connection.ssid.display_text or "<Hidden or empty>"))
    table.add_row("BSSID", str(connection.bssid))
    table.add_row("Connection mode", connection.mode.display_name)
    table.add_row("Profile", Text(connection.profile_name or "Unavailable"))
    table.add_row("PHY", connection.phy_type.display_name)
    table.add_row("Signal", f"{connection.signal_quality}%")
    table.add_row("Receive rate", _format_kilobits_per_second(connection.receive_rate_kbps))
    table.add_row("Transmit rate", _format_kilobits_per_second(connection.transmit_rate_kbps))
    table.add_row("Security enabled", "Yes" if connection.security.enabled else "No")
    table.add_row("Authentication", connection.security.authentication.display_name)
    table.add_row("Cipher", connection.security.cipher.display_name)


def _format_kilobits_per_second(value: int | None) -> str:
    if value is None:
        return "Unavailable"
    megabits = value / 1_000
    precision = 0 if megabits.is_integer() else 1
    return f"{megabits:.{precision}f} Mbps"


def _scan_nearby_wifi(use_case: ScanNearbyWifi, console: Console) -> int:
    try:
        snapshot = use_case.execute()
    except WifiCollectionError as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        return 1

    console.print(f"[bold]{PROJECT_NAME}[/bold]")
    console.print("Nearby Wi-Fi Networks", style="dim")
    if not snapshot.interfaces:
        console.print("No Wi-Fi interfaces were reported by Windows.")
    elif not snapshot.networks:
        console.print("No nearby Wi-Fi networks were reported by Windows.")
    else:
        console.print(_create_nearby_wifi_table(snapshot.networks))
    for issue in snapshot.issues:
        console.print(f"[yellow]Warning:[/yellow] {issue.message}")
    if snapshot.failed:
        return 1
    return 3 if snapshot.is_partial else 0


def _create_nearby_wifi_table(networks: tuple[WifiNetwork, ...]) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("SSID", overflow="fold")
    table.add_column("BSS", justify="right", no_wrap=True)
    table.add_column("Signal", justify="right", no_wrap=True)
    table.add_column("Band", no_wrap=True)
    table.add_column("Security", overflow="fold")
    table.add_column("Interface", overflow="fold")
    for network in networks:
        observed_count = len(network.access_points)
        bss_count = observed_count or network.reported_bss_count
        bands = "/".join(band.value for band in network.bands) or "Unknown"
        if network.security_enabled is None:
            security = "Unknown"
        elif network.security_enabled:
            security = f"{network.authentication.display_name} / {network.cipher.display_name}"
        else:
            security = "Open"
        table.add_row(
            Text(network.ssid.display_text or "<Hidden>"),
            str(bss_count),
            f"{network.best_signal_quality}%",
            bands,
            security,
            Text(network.interface_description),
        )
    return table


def _inspect_current_network(use_case: InspectCurrentNetwork, console: Console) -> int:
    try:
        snapshot = use_case.execute()
    except NetworkCollectionError as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        return 1

    console.print(f"[bold]{PROJECT_NAME}[/bold]")
    console.print("Current Network", style="dim")
    relevant = _relevant_network_contexts(snapshot)
    if not relevant:
        console.print("No usable IP configuration or default route was reported by Windows.")
    for position, context in enumerate(relevant, start=1):
        if len(relevant) > 1:
            console.print(f"\n[bold]Interface {position}[/bold]")
        console.print(_create_network_context_table(context, snapshot.default_routes))
    console.print(f"Routes observed: {len(snapshot.routes)}", style="dim")
    for issue in snapshot.issues:
        console.print(f"[yellow]Warning ({issue.source.value}):[/yellow] {issue.message}")
    return 3 if snapshot.is_partial else 0


def _relevant_network_contexts(
    snapshot: CurrentNetworkSnapshot,
) -> tuple[InterfaceNetworkContext, ...]:
    default_indices = {route.interface_index for route in snapshot.default_routes}
    return tuple(
        context
        for context in snapshot.interfaces
        if context.addresses or context.interface_index in default_indices
    )


def _create_network_context_table(
    context: InterfaceNetworkContext,
    default_routes: tuple[Route, ...],
) -> Table:
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value", overflow="fold")
    name = (
        context.network_interface.friendly_name
        if context.network_interface is not None
        else f"Interface {context.interface_index}"
    )
    table.add_row("Interface", Text(name))
    table.add_row("Index", str(context.interface_index))
    _add_ip_rows(table, context)
    _add_dns_rows(table, context)
    _add_dhcp_rows(table, context)
    _add_default_route_rows(table, context.interface_index, default_routes)
    if context.wifi_interface is not None:
        table.add_row("Wi-Fi association", "Yes")
    return table


def _add_ip_rows(table: Table, context: InterfaceNetworkContext) -> None:
    for version in (4, 6):
        assignments = tuple(item for item in context.addresses if item.address.version == version)
        for position, assignment in enumerate(assignments, start=1):
            label = f"IPv{version}" if len(assignments) == 1 else f"IPv{version} #{position}"
            scope = f"%{assignment.scope_id}" if assignment.scope_id else ""
            table.add_row(
                label,
                f"{assignment.address}{scope}/{assignment.prefix_length} ({assignment.network})",
            )


def _add_dns_rows(table: Table, context: InterfaceNetworkContext) -> None:
    if context.dns is None:
        table.add_row("DNS", "Unavailable")
        return
    if not context.dns.servers:
        table.add_row("DNS", "None configured")
    for position, server in enumerate(context.dns.servers, start=1):
        table.add_row(f"DNS #{position}", str(server))
    if context.dns.suffix:
        table.add_row("DNS suffix", Text(context.dns.suffix))


def _add_dhcp_rows(table: Table, context: InterfaceNetworkContext) -> None:
    table.add_row("DHCP IPv4", context.dhcp.ipv4_state.value)
    table.add_row("DHCP IPv6", context.dhcp.ipv6_state.value)
    if context.dhcp.server is not None:
        table.add_row("DHCP server", str(context.dhcp.server))


def _add_default_route_rows(
    table: Table,
    interface_index: int,
    default_routes: tuple[Route, ...],
) -> None:
    routes = tuple(route for route in default_routes if route.interface_index == interface_index)
    family_counts = {
        version: sum(route.destination.version == version for route in routes) for version in (4, 6)
    }
    family_positions = {4: 0, 6: 0}
    for route in routes:
        version = route.destination.version
        family_positions[version] += 1
        family = f"IPv{route.destination.version}"
        label = (
            f"Default {family}"
            if family_counts[version] == 1
            else f"Default {family} #{family_positions[version]}"
        )
        scope = f"%{route.next_hop_scope_id}" if route.next_hop_scope_id else ""
        table.add_row(label, f"{route.next_hop}{scope}")
        route_metric = (
            "Unavailable" if route.route_metric == UNUSED_ROUTE_METRIC else str(route.route_metric)
        )
        table.add_row("Route metric", route_metric)
        table.add_row(
            "Interface metric",
            str(route.interface_metric) if route.interface_metric is not None else "Unavailable",
        )
        table.add_row(
            "Effective metric",
            str(route.effective_metric) if route.effective_metric is not None else "Unavailable",
        )
