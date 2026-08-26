import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from threading import Event

from rich.console import Console
from rich.table import Table
from rich.text import Text

from wlanscope.application.discover_local_devices import DiscoverLocalDevices
from wlanscope.application.enrich_device_inventory import EnrichDeviceInventory
from wlanscope.application.export_full_network_report import (
    ExportFullNetworkReport,
    ReportPathError,
    paths_conflict,
)
from wlanscope.application.inspect_current_network import InspectCurrentNetwork
from wlanscope.application.inspect_current_wifi import InspectCurrentWifi
from wlanscope.application.inspect_nearby_wifi import (
    InspectNearbyWifiNetwork,
    NearbyWifiNetworkDetails,
    WifiAccessPointSelection,
    WifiNetworkSelection,
    WifiSelectionError,
)
from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.application.run_full_network_scan import RunFullNetworkScan
from wlanscope.application.scan_nearby_wifi import ScanNearbyWifi
from wlanscope.domain.discovery import (
    DiscoveryError,
    DiscoverySource,
    RangeAuthorizationRequiredError,
    ReachabilityState,
)
from wlanscope.domain.enrichment import (
    EnrichedDeviceInventory,
    HostnameResolutionState,
    VendorResolutionState,
)
from wlanscope.domain.full_scan import FullNetworkSnapshot, FullScanStatus
from wlanscope.domain.interfaces import (
    InterfaceCollectionError,
    NetworkInterface,
    OperationalState,
)
from wlanscope.domain.nearby_wifi import WifiAccessPoint, WifiNetwork
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
from wlanscope.reporting.writer import ReportWriteError
from wlanscope.version import __version__

PROJECT_NAME = "WLANScope"
PROJECT_TAGLINE = "Windows Wireless & Network Reconnaissance"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wlanscope",
        description=(
            f"{PROJECT_NAME}: {PROJECT_TAGLINE}. Read-only network observation for Windows."
        ),
        epilog=(
            "Use 'wlanscope COMMAND --help' for command details. Wi-Fi scanning observes "
            "the radio environment; device discovery sends bounded ICMP Echo probes only "
            "within the selected local subnet."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROJECT_NAME} {__version__}",
    )
    subcommands = parser.add_subparsers(dest="command", title="commands", metavar="COMMAND")
    subcommands.add_parser(
        "adapters",
        help="List Windows network interfaces",
        description="List network interfaces reported by Windows.",
    )
    wifi_parser = subcommands.add_parser(
        "wifi",
        help="Inspect the current Wi-Fi connection",
        description=(
            "Inspect current Wi-Fi connection details. Use the scan subcommand to observe "
            "nearby Wi-Fi networks."
        ),
    )
    wifi_subcommands = wifi_parser.add_subparsers(
        dest="wifi_command", title="Wi-Fi commands", metavar="COMMAND"
    )
    wifi_scan_parser = wifi_subcommands.add_parser(
        "scan",
        help="Discover nearby Wi-Fi networks",
        description=(
            "Observe nearby Wi-Fi networks and access points reported by Windows. Windows "
            "location access may be required."
        ),
    )
    wifi_scan_parser.add_argument(
        "--details",
        type=int,
        metavar="NETWORK",
        help="Show details for a one-based network index from this scan",
    )
    wifi_scan_parser.add_argument(
        "--access-point",
        type=int,
        metavar="AP",
        help="Show details for a one-based access point index within the selected network",
    )
    subcommands.add_parser(
        "current",
        help="Inspect the current IP and routing context",
        description="Inspect current IP, routing, DNS, and DHCP context reported by Windows.",
    )
    devices_parser = subcommands.add_parser(
        "devices",
        help="Discover hosts observable on the local subnet",
        description=(
            "Observe hosts on the routed local IPv4 subnet using the neighbor cache and "
            "bounded ICMP Echo probes."
        ),
    )
    devices_parser.add_argument(
        "--allow-large-range",
        action="store_true",
        help=(
            "Authorize the selected local subnet when it contains 257 to 4096 usable "
            "addresses; discovery remains limited to that subnet"
        ),
    )
    scan_parser = subcommands.add_parser(
        "scan",
        help="Run a complete network and Wi-Fi snapshot",
        description="Run a summarized full network and Wi-Fi scan using existing collectors.",
    )
    scan_parser.add_argument(
        "--allow-large-range",
        action="store_true",
        help=(
            "Authorize the selected local subnet when it contains 257 to 4096 usable "
            "addresses; discovery remains limited to that subnet"
        ),
    )
    scan_parser.add_argument(
        "--json",
        type=Path,
        metavar="PATH",
        help="Write a versioned JSON report to PATH",
    )
    scan_parser.add_argument(
        "--markdown",
        type=Path,
        metavar="PATH",
        help="Write a Markdown report to PATH",
    )
    scan_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite only explicitly requested JSON or Markdown report files",
    )
    return parser


def main(
    arguments: Sequence[str] | None = None,
    interface_use_case: ListNetworkInterfaces | None = None,
    wifi_use_case: InspectCurrentWifi | None = None,
    nearby_wifi_use_case: ScanNearbyWifi | None = None,
    nearby_wifi_detail_use_case: InspectNearbyWifiNetwork | None = None,
    current_use_case: InspectCurrentNetwork | None = None,
    devices_use_case: DiscoverLocalDevices | None = None,
    device_enrichment_use_case: EnrichDeviceInventory | None = None,
    full_scan_use_case: RunFullNetworkScan | None = None,
    report_export_use_case: ExportFullNetworkReport | None = None,
    console: Console | None = None,
    error_console: Console | None = None,
    input_reader: Callable[[str], str] | None = None,
    stdin_is_tty: bool | None = None,
    stdout_is_tty: bool | None = None,
) -> int:
    parser = build_parser()
    parsed_arguments = parser.parse_args(arguments)
    output = console or Console()
    diagnostics = error_console or (console if console is not None else Console(stderr=True))
    if (
        parsed_arguments.command == "wifi"
        and parsed_arguments.wifi_command == "scan"
        and parsed_arguments.access_point is not None
        and parsed_arguments.details is None
    ):
        parser.error("--access-point requires --details")
    if parsed_arguments.command == "scan":
        if (
            parsed_arguments.force
            and parsed_arguments.json is None
            and parsed_arguments.markdown is None
        ):
            parser.error("--force requires --json or --markdown")
        if paths_conflict(parsed_arguments.json, parsed_arguments.markdown):
            parser.error("--json and --markdown must use different paths")
    if parsed_arguments.command is None:
        interactive = (stdin_is_tty if stdin_is_tty is not None else sys.stdin.isatty()) and (
            stdout_is_tty if stdout_is_tty is not None else output.is_terminal
        )
        if not interactive:
            output.print(Text(parser.format_help()), end="")
            return 0
        return _run_interactive(
            interface_use_case or _create_interface_use_case(),
            wifi_use_case or _create_wifi_use_case(),
            current_use_case or _create_current_use_case(),
            nearby_wifi_use_case or _create_nearby_wifi_use_case(),
            nearby_wifi_detail_use_case or InspectNearbyWifiNetwork(),
            devices_use_case or _create_devices_use_case(),
            device_enrichment_use_case or _create_device_enrichment_use_case(),
            full_scan_use_case or _create_full_scan_use_case(),
            report_export_use_case or _create_report_export_use_case(),
            output,
            diagnostics,
            input_reader or input,
        )
    if parsed_arguments.command == "adapters":
        return _list_adapters(
            interface_use_case or _create_interface_use_case(),
            output,
            diagnostics,
        )
    if parsed_arguments.command == "wifi":
        if parsed_arguments.wifi_command == "scan":
            return _scan_nearby_wifi(
                nearby_wifi_use_case or _create_nearby_wifi_use_case(),
                nearby_wifi_detail_use_case or InspectNearbyWifiNetwork(),
                parsed_arguments.details,
                parsed_arguments.access_point,
                output,
                diagnostics,
            )
        return _inspect_wifi(
            wifi_use_case or _create_wifi_use_case(),
            output,
            diagnostics,
        )
    if parsed_arguments.command == "current":
        return _inspect_current_network(
            current_use_case or _create_current_use_case(),
            output,
            diagnostics,
        )
    if parsed_arguments.command == "devices":
        return _discover_devices(
            devices_use_case or _create_devices_use_case(),
            device_enrichment_use_case or _create_device_enrichment_use_case(),
            parsed_arguments.allow_large_range,
            output,
            diagnostics,
        )
    if parsed_arguments.command == "scan":
        return _run_full_scan(
            full_scan_use_case or _create_full_scan_use_case(),
            report_export_use_case or _create_report_export_use_case(),
            parsed_arguments.allow_large_range,
            parsed_arguments.json,
            parsed_arguments.markdown,
            parsed_arguments.force,
            output,
            diagnostics,
        )
    return 0


def _run_interactive(
    interfaces: ListNetworkInterfaces,
    current_wifi: InspectCurrentWifi,
    current_network: InspectCurrentNetwork,
    nearby_wifi: ScanNearbyWifi,
    nearby_details: InspectNearbyWifiNetwork,
    devices: DiscoverLocalDevices,
    enrichment: EnrichDeviceInventory,
    full_scan: RunFullNetworkScan,
    reports: ExportFullNetworkReport,
    console: Console,
    error_console: Console,
    input_reader: Callable[[str], str],
) -> int:
    from wlanscope.interactive import (
        InteractiveRenderers,
        InteractiveSession,
        InteractiveUseCases,
    )

    return InteractiveSession(
        InteractiveUseCases(
            interfaces,
            current_wifi,
            current_network,
            nearby_wifi,
            nearby_details,
            devices,
            enrichment,
            full_scan,
            reports,
        ),
        InteractiveRenderers(
            _create_interface_table,
            _create_wifi_table,
            _relevant_network_contexts,
            _create_network_context_table,
            _create_nearby_wifi_table,
            _render_nearby_wifi_details,
            _create_access_point_detail_table,
            _create_device_table,
            _render_device_summary,
            _create_full_scan_overview,
            _create_full_scan_section_table,
            _create_full_scan_summary,
        ),
        console,
        error_console,
        input_reader,
    ).run()


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


def _create_devices_use_case() -> DiscoverLocalDevices:
    from wlanscope.composition import create_discover_local_devices

    return create_discover_local_devices()


def _create_device_enrichment_use_case() -> EnrichDeviceInventory:
    from wlanscope.composition import create_enrich_device_inventory

    return create_enrich_device_inventory()


def _create_full_scan_use_case() -> RunFullNetworkScan:
    from wlanscope.composition import create_run_full_network_scan

    return create_run_full_network_scan()


def _create_report_export_use_case() -> ExportFullNetworkReport:
    from wlanscope.composition import create_export_full_network_report

    return create_export_full_network_report()


def _run_full_scan(
    use_case: RunFullNetworkScan,
    report_exporter: ExportFullNetworkReport,
    allow_large_range: bool,
    json_path: Path | None,
    markdown_path: Path | None,
    force: bool,
    console: Console,
    error_console: Console,
) -> int:
    cancellation = Event()
    try:
        snapshot = use_case.execute(allow_large_range, cancellation)
    except KeyboardInterrupt:
        cancellation.set()
        error_console.print("[yellow]Full network scan canceled.[/yellow]")
        return 130

    console.print(f"[bold]{PROJECT_NAME}[/bold]")
    console.print("Full Network Scan", style="dim")
    console.print(_create_full_scan_overview(snapshot))
    console.print("Section Status", style="bold")
    console.print(_create_full_scan_section_table(snapshot))
    console.print("Network Summary", style="bold")
    console.print(_create_full_scan_summary(snapshot))
    if snapshot.issues:
        error_console.print("Issues", style="bold")
        for issue in snapshot.issues:
            error_console.print(
                Text.assemble(
                    ("[", "yellow"),
                    Text(issue.section.value, style="yellow"),
                    ("] ", "yellow"),
                    Text(issue.message),
                )
            )
    try:
        exports = report_exporter.execute(snapshot, json_path, markdown_path, force)
    except (ReportPathError, ReportWriteError) as error:
        error_console.print("[bold red]Report error:[/bold red]", Text(f" {error}"))
        return 1
    if exports:
        console.print("Reports written", style="bold")
        for exported in exports:
            console.print(
                Text.assemble(
                    (f"  {exported.format.value:<8} ", "green"),
                    Text(str(exported.path)),
                )
            )
    return {
        FullScanStatus.SUCCESS: 0,
        FullScanStatus.PARTIAL: 3,
        FullScanStatus.FAILED: 1,
    }[snapshot.status]


def _create_full_scan_overview(snapshot: FullNetworkSnapshot) -> Table:
    table = _create_detail_table()
    table.add_row("Status", snapshot.status.value)
    table.add_row("Duration", f"{snapshot.duration_seconds:.1f} seconds")
    table.add_row("Warnings", str(len(snapshot.issues)))
    return table


def _create_full_scan_section_table(snapshot: FullNetworkSnapshot) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Section", overflow="fold")
    table.add_column("Status", no_wrap=True)
    for result in snapshot.sections:
        table.add_row(result.section.value, result.status.value)
    return table


def _create_full_scan_summary(snapshot: FullNetworkSnapshot) -> Table:
    table = _create_detail_table()
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
    bss_count = sum(len(network.access_points) for network in nearby_networks)
    devices = snapshot.devices
    table.add_row("Interfaces", str(len(interfaces)))
    table.add_row(
        "Interfaces up",
        str(sum(interface.operational_state is OperationalState.UP for interface in interfaces)),
    )
    table.add_row("Current Wi-Fi connected", _yes_no(connected_wifi))
    table.add_row("IPv4 present", _yes_no(any(item.address.version == 4 for item in addresses)))
    table.add_row("IPv6 present", _yes_no(any(item.address.version == 6 for item in addresses)))
    table.add_row(
        "IPv4 default route",
        _yes_no(any(route.destination.version == 4 for route in routes)),
    )
    table.add_row(
        "IPv6 default route",
        _yes_no(any(route.destination.version == 6 for route in routes)),
    )
    table.add_row("Nearby Wi-Fi networks", str(len(nearby_networks)))
    table.add_row("Nearby BSS observations", str(bss_count))
    table.add_row(
        "Observed hosts",
        str(len(devices.hosts)) if devices is not None else "Unavailable",
    )
    table.add_row(
        "PTR resolved",
        str(devices.ptr_resolved_count) if devices is not None else "Unavailable",
    )
    table.add_row(
        "Vendors resolved",
        str(devices.vendor_resolved_count) if devices is not None else "Unavailable",
    )
    return table


def _yes_no(value: bool) -> str:
    return "Yes" if value else "No"


def _discover_devices(
    use_case: DiscoverLocalDevices,
    enrichment_use_case: EnrichDeviceInventory,
    allow_large_range: bool,
    console: Console,
    error_console: Console,
) -> int:
    cancellation = Event()
    try:
        inventory = use_case.execute(allow_large_range, cancellation)
        if inventory.canceled:
            error_console.print("[yellow]Local subnet discovery canceled.[/yellow]")
            return 130
        enriched = enrichment_use_case.execute(inventory, cancellation)
    except KeyboardInterrupt:
        cancellation.set()
        error_console.print("[yellow]Local subnet discovery canceled.[/yellow]")
        return 130
    except RangeAuthorizationRequiredError as error:
        error_console.print("[bold red]Error:[/bold red]", Text(f" {error}"))
        error_console.print("Re-run with --allow-large-range.")
        return 2
    except (DiscoveryError, NetworkCollectionError) as error:
        error_console.print("[bold red]Discovery unavailable:[/bold red]", Text(f" {error}"))
        return 1

    console.print(f"[bold]{PROJECT_NAME}[/bold]")
    console.print("Local Network Discovery", style="dim")
    if inventory.plan.usable_host_count > 1_024:
        error_console.print(
            "[yellow]Warning:[/yellow] Explicitly authorized discovery of a large local range."
        )
    console.print(_create_device_table(enriched, console.width))
    _render_device_summary(enriched, console)
    for issue in inventory.issues:
        error_console.print(
            Text.assemble(
                ("Warning (", "yellow"),
                Text(issue.stage, style="yellow"),
                ("): ", "yellow"),
                Text(issue.message),
            )
        )
    for enrichment_issue in enriched.issues:
        error_console.print(
            Text.assemble(
                ("Warning (", "yellow"),
                Text(enrichment_issue.source, style="yellow"),
                ("): ", "yellow"),
                Text(enrichment_issue.message),
            )
        )
    return 3 if enriched.is_partial else 0


def _create_device_table(inventory: EnrichedDeviceInventory, terminal_width: int) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("IP", no_wrap=True)
    table.add_column("Hostname", overflow="fold")
    table.add_column("Vendor", overflow="fold")
    table.add_column("State", no_wrap=True)
    compact = terminal_width < 100
    if not compact:
        table.add_column("MAC", no_wrap=True)
        table.add_column("Sources", overflow="fold")
    for host in inventory.hosts:
        sources = ", ".join(
            _format_discovery_source(source)
            for source in sorted(host.discovered.sources, key=lambda item: item.value)
        )
        state = host.discovered.reachability.value
        if (
            host.discovered.reachability is ReachabilityState.NOT_PROBED
            and host.discovered.neighbor_state is not None
        ):
            state = host.discovered.neighbor_state.display_name
        row: list[str | Text] = [
            str(host.discovered.address),
            Text(_hostname_display(host.hostname.state, host.hostname.hostname)),
            Text(_vendor_display(host.vendor.state, host.vendor.vendor)),
            state,
        ]
        if not compact:
            row.extend(
                (
                    str(host.discovered.mac_address)
                    if host.discovered.mac_address is not None
                    else "Unknown",
                    sources,
                )
            )
        table.add_row(*row)
    return table


def _hostname_display(state: HostnameResolutionState, hostname: str | None) -> str:
    return hostname if state is HostnameResolutionState.RESOLVED and hostname else state.value


def _vendor_display(state: VendorResolutionState, vendor: str | None) -> str:
    return vendor if state is VendorResolutionState.RESOLVED and vendor else state.value


def _format_discovery_source(source: DiscoverySource) -> str:
    labels = {
        DiscoverySource.SELF: "Self",
        DiscoverySource.GATEWAY: "Gateway",
        DiscoverySource.NEIGHBOR_CACHE: "Neighbor",
        DiscoverySource.ICMP_RESPONSE: "ICMP",
    }
    return labels[source]


def _render_device_summary(inventory: EnrichedDeviceInventory, console: Console) -> None:
    discovered = inventory.discovered
    responded = sum(host.reachability is ReachabilityState.RESPONDED for host in discovered.hosts)
    neighbor_only = sum(
        host.sources == frozenset({DiscoverySource.NEIGHBOR_CACHE}) for host in discovered.hosts
    )
    console.print(f"Subnet: {discovered.plan.subnet}")
    console.print(f"Targets considered: {len(discovered.plan.targets)}")
    console.print(f"Probes executed: {discovered.probes_executed}")
    console.print(f"Observed hosts: {len(discovered.hosts)}")
    console.print(f"ICMP responses: {responded}")
    console.print(f"Neighbor-only observations: {neighbor_only}")
    console.print(f"PTR resolved: {inventory.ptr_resolved_count}/{inventory.ptr_attempted_count}")
    console.print(
        f"Vendors resolved: {inventory.vendor_resolved_count}/{inventory.vendor_attempted_count}"
    )
    console.print(f"Locally administered MACs: {inventory.locally_administered_count}")


def _list_adapters(
    use_case: ListNetworkInterfaces,
    console: Console,
    error_console: Console,
) -> int:
    try:
        inventory = use_case.execute()
    except InterfaceCollectionError as error:
        error_console.print(
            "[bold red]Network interfaces unavailable:[/bold red]", Text(f" {error}")
        )
        return 1

    console.print(f"[bold]{PROJECT_NAME}[/bold]")
    console.print("Network Interfaces", style="dim")

    if not inventory.interfaces:
        console.print("No network interfaces were returned by Windows.")
    else:
        console.print(_create_interface_table(inventory.interfaces, console.width))

    for warning in inventory.warnings:
        error_console.print("[yellow]Warning:[/yellow]", Text(f" {warning}"))

    return 3 if inventory.is_partial else 0


def _create_interface_table(interfaces: tuple[NetworkInterface, ...], terminal_width: int) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Index", justify="right", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Name", overflow="fold")
    compact = terminal_width < 100
    if not compact:
        table.add_column("MAC", no_wrap=True)
        table.add_column("Link", justify="right", no_wrap=True)

    for interface in interfaces:
        row: list[str | Text] = [
            str(interface.interface_index),
            interface.kind.value,
            interface.operational_state.value,
            Text(interface.friendly_name),
        ]
        if not compact:
            row.extend(
                (
                    str(interface.mac_address) if interface.mac_address else "Unknown",
                    _format_link_speed(interface),
                )
            )
        table.add_row(*row)
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


def _inspect_wifi(
    use_case: InspectCurrentWifi,
    console: Console,
    error_console: Console,
) -> int:
    try:
        snapshot = use_case.execute()
    except WifiCollectionError as error:
        error_console.print("[bold red]Current Wi-Fi unavailable:[/bold red]", Text(f" {error}"))
        return 1

    console.print(f"[bold]{PROJECT_NAME}[/bold]")
    console.print("Current Wi-Fi", style="dim")
    if not snapshot.interfaces:
        console.print("No Wi-Fi interfaces were reported by Windows.")
    else:
        _render_wifi_interfaces(snapshot, console)

    for issue in snapshot.issues:
        error_console.print("[yellow]Warning:[/yellow]", Text(f" {issue.message}"))
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


def _scan_nearby_wifi(
    use_case: ScanNearbyWifi,
    detail_use_case: InspectNearbyWifiNetwork,
    network_index: int | None,
    access_point_index: int | None,
    console: Console,
    error_console: Console,
) -> int:
    try:
        snapshot = use_case.execute()
    except KeyboardInterrupt:
        error_console.print("[yellow]Nearby Wi-Fi scan canceled.[/yellow]")
        return 130
    except WifiCollectionError as error:
        error_console.print("[bold red]Nearby Wi-Fi unavailable:[/bold red]", Text(f" {error}"))
        return 1

    console.print(f"[bold]{PROJECT_NAME}[/bold]")
    console.print("Nearby Wi-Fi Networks", style="dim")
    if not snapshot.interfaces:
        console.print("No Wi-Fi interfaces were reported by Windows.")
    elif not snapshot.networks:
        console.print("No nearby Wi-Fi networks were reported by Windows.")
    elif network_index is not None:
        try:
            details = detail_use_case.execute(snapshot, WifiNetworkSelection(network_index))
            access_point = (
                detail_use_case.select_access_point(
                    details,
                    WifiAccessPointSelection(access_point_index),
                )
                if access_point_index is not None
                else None
            )
        except WifiSelectionError as error:
            error_console.print("[bold red]Selection error:[/bold red]", Text(f" {error}"))
            return 2
        _render_nearby_wifi_details(details, access_point, console)
    else:
        console.print(_create_nearby_wifi_table(snapshot.networks, console.width))
    if network_index is not None and not snapshot.networks and not snapshot.failed:
        error_console.print("[bold red]Selection error:[/bold red] No networks are available")
        return 2
    for issue in snapshot.issues:
        error_console.print("[yellow]Warning:[/yellow]", Text(f" {issue.message}"))
    if snapshot.failed:
        return 1
    return 3 if snapshot.is_partial else 0


def _render_nearby_wifi_details(
    details: NearbyWifiNetworkDetails,
    selected_access_point: WifiAccessPoint | None,
    console: Console,
) -> None:
    console.print("Network Details", style="bold")
    console.print(_create_nearby_network_detail_table(details))
    if details.network.access_points:
        console.print("Access Points", style="bold")
        console.print(_create_access_point_summary_table(details.network.access_points))
    else:
        console.print("No BSS entries were observed for this network.")
    if selected_access_point is not None:
        console.print("Access Point Details", style="bold")
        console.print(_create_access_point_detail_table(selected_access_point))
    console.print(
        "Details use the current scan snapshot; no additional scan was performed.", style="dim"
    )


def _create_nearby_network_detail_table(details: NearbyWifiNetworkDetails) -> Table:
    network = details.network
    table = _create_detail_table()
    table.add_row("SSID", Text(network.ssid.display_text or "<Hidden>"))
    table.add_row("Hidden", "Yes" if network.ssid.is_empty else "No")
    table.add_row("Interface", Text(network.interface_description))
    table.add_row("Connectable", "Yes" if network.connectable else "No")
    table.add_row("Profile", Text(network.profile_name or "Unavailable"))
    table.add_row("Security enabled", _format_optional_boolean(network.security_enabled))
    table.add_row("Authentication", network.authentication.display_name)
    table.add_row("Cipher", network.cipher.display_name)
    table.add_row("Aggregate signal", f"{network.signal_quality}%")
    observed_signal = details.best_observed_signal_quality
    table.add_row(
        "Best observed BSS signal",
        f"{observed_signal}%" if observed_signal is not None else "Unavailable",
    )
    table.add_row("Reported BSS count", str(details.reported_bss_count))
    table.add_row("Observed BSS count", str(details.observed_bss_count))
    table.add_row("BSS count discrepancy", "Yes" if details.has_bss_count_discrepancy else "No")
    table.add_row("Bands", ", ".join(band.value for band in details.bands) or "Unknown")
    table.add_row(
        "PHY types",
        ", ".join(phy_type.display_name for phy_type in details.phy_types) or "Unknown",
    )
    table.add_row(
        "Center frequencies",
        ", ".join(_format_center_frequency(value) for value in details.center_frequencies_khz)
        or "Unknown",
    )
    table.add_row("Channels", ", ".join(map(str, details.channels)) or "Unknown")
    return table


def _create_access_point_summary_table(
    access_points: tuple[WifiAccessPoint, ...],
) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("BSSID", no_wrap=True)
    table.add_column("Signal", justify="right", no_wrap=True)
    table.add_column("RSSI", justify="right", no_wrap=True)
    table.add_column("PHY", no_wrap=True)
    table.add_column("Band", no_wrap=True)
    table.add_column("Channel", justify="right", no_wrap=True)
    for index, access_point in enumerate(access_points, start=1):
        table.add_row(
            str(index),
            str(access_point.bssid),
            f"{access_point.signal_quality}%",
            f"{access_point.rssi_dbm} dBm",
            access_point.phy_type.display_name,
            access_point.band.value,
            str(access_point.channel) if access_point.channel is not None else "Unknown",
        )
    return table


def _create_access_point_detail_table(access_point: WifiAccessPoint) -> Table:
    table = _create_detail_table()
    table.add_row("BSSID", str(access_point.bssid))
    table.add_row("SSID", Text(access_point.ssid.display_text or "<Hidden>"))
    table.add_row("Interface identifier", Text(access_point.interface_id))
    table.add_row("PHY", access_point.phy_type.display_name)
    table.add_row("Signal quality", f"{access_point.signal_quality}%")
    table.add_row("RSSI", f"{access_point.rssi_dbm} dBm")
    table.add_row("Center frequency", _format_center_frequency(access_point.center_frequency_khz))
    table.add_row("Band", access_point.band.value)
    table.add_row(
        "Channel",
        str(access_point.channel) if access_point.channel is not None else "Unknown",
    )
    table.add_row(
        "Beacon period",
        f"{access_point.beacon_period_tu} TU"
        if access_point.beacon_period_tu is not None
        else "Unavailable",
    )
    table.add_row(
        "Capability information",
        f"0x{access_point.capability_information:04X}"
        if access_point.capability_information is not None
        else "Unavailable",
    )
    table.add_row(
        "BSS timestamp",
        f"{access_point.timestamp_us} microseconds"
        if access_point.timestamp_us is not None
        else "Unavailable",
    )
    table.add_row(
        "Host timestamp",
        str(access_point.host_timestamp)
        if access_point.host_timestamp is not None
        else "Unavailable",
    )
    return table


def _create_detail_table() -> Table:
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value", overflow="fold")
    return table


def _format_center_frequency(center_frequency_khz: int) -> str:
    frequency_mhz = center_frequency_khz / 1_000
    if frequency_mhz >= 1_000:
        return f"{frequency_mhz:,.3f} MHz ({frequency_mhz / 1_000:.3f} GHz)"
    return f"{frequency_mhz:,.3f} MHz"


def _format_optional_boolean(value: bool | None) -> str:
    if value is None:
        return "Unknown"
    return "Yes" if value else "No"


def _create_nearby_wifi_table(networks: tuple[WifiNetwork, ...], terminal_width: int) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("SSID", overflow="fold")
    table.add_column("BSS", justify="right", no_wrap=True)
    table.add_column("Signal", justify="right", no_wrap=True)
    table.add_column("Band", no_wrap=True)
    compact = terminal_width < 100
    if not compact:
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
        row: list[str | Text] = [
            Text(network.ssid.display_text or "<Hidden>"),
            str(bss_count),
            f"{network.best_signal_quality}%",
            bands,
        ]
        if not compact:
            row.extend((security, Text(network.interface_description)))
        table.add_row(*row)
    return table


def _inspect_current_network(
    use_case: InspectCurrentNetwork,
    console: Console,
    error_console: Console,
) -> int:
    try:
        snapshot = use_case.execute()
    except NetworkCollectionError as error:
        error_console.print("[bold red]Current network unavailable:[/bold red]", Text(f" {error}"))
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
        error_console.print(
            Text.assemble(
                (f"Warning ({issue.source.value}): ", "yellow"),
                Text(issue.message),
            )
        )
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
