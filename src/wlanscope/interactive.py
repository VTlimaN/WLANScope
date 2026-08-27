from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Event

from rich.console import Console, RenderableType
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
)
from wlanscope.domain.enrichment import EnrichedDeviceInventory, EnrichedHost
from wlanscope.domain.full_scan import FullNetworkSnapshot
from wlanscope.domain.interfaces import InterfaceCollectionError, NetworkInterface
from wlanscope.domain.nearby_wifi import NearbyWifiSnapshot, WifiAccessPoint, WifiNetwork
from wlanscope.domain.network import (
    CurrentNetworkSnapshot,
    NetworkCollectionError,
)
from wlanscope.domain.wifi import CurrentWifiSnapshot, WifiCollectionError, WifiInterfaceSnapshot
from wlanscope.presentation import (
    create_about_identity,
    create_branding,
    create_data_table,
    create_empty_state,
    create_key_value_table,
    create_main_menu,
    create_notice,
    create_screen_header,
    create_technical_note,
    format_bool,
    format_bytes,
    format_rate,
    format_timestamp,
    navigation_text,
)
from wlanscope.reporting.writer import ReportWriteError
from wlanscope.version import __version__

InputReader = Callable[[str], str]


@dataclass(frozen=True, slots=True)
class InteractiveUseCases:
    interfaces: ListNetworkInterfaces
    current_wifi: InspectCurrentWifi
    current_network: InspectCurrentNetwork
    nearby_wifi: ScanNearbyWifi
    nearby_details: InspectNearbyWifiNetwork
    devices: DiscoverLocalDevices
    enrichment: EnrichDeviceInventory
    full_scan: RunFullNetworkScan
    reports: ExportFullNetworkReport


@dataclass(frozen=True, slots=True)
class InteractiveRenderers:
    interface_table: Callable[[tuple[NetworkInterface, ...], int], Table]
    wifi_table: Callable[[WifiInterfaceSnapshot], Table]
    nearby_table: Callable[[tuple[WifiNetwork, ...], int], Table]
    nearby_details: Callable[[NearbyWifiNetworkDetails, WifiAccessPoint | None, Console], None]
    access_point_detail: Callable[[WifiAccessPoint], Table]
    device_table: Callable[[EnrichedDeviceInventory, int], Table]
    device_summary: Callable[[EnrichedDeviceInventory, Console], None]
    current_overview: Callable[
        [CurrentWifiSnapshot | None, CurrentNetworkSnapshot | None, int], RenderableType
    ]
    full_overview: Callable[[FullNetworkSnapshot], RenderableType]
    full_sections: Callable[[FullNetworkSnapshot], RenderableType]
    full_summary: Callable[[FullNetworkSnapshot, int], RenderableType]


class InteractiveSession:
    def __init__(
        self,
        use_cases: InteractiveUseCases,
        renderers: InteractiveRenderers,
        console: Console,
        error_console: Console,
        input_reader: InputReader,
        clear_enabled: bool | None = None,
    ) -> None:
        self._use_cases = use_cases
        self._renderers = renderers
        self._console = console
        self._error_console = error_console
        self._input = input_reader
        self._clear_enabled = console.is_terminal and (
            True if clear_enabled is None else clear_enabled
        )

    def run(self) -> int:
        try:
            while True:
                self._render_main_menu()
                choice = self._read("Select an option: ")
                if choice.casefold() in {"0", "q"}:
                    return 0
                action = {
                    "1": self._current_network,
                    "2": self._interfaces,
                    "3": self._nearby_wifi,
                    "4": self._devices,
                    "5": self._full_scan,
                    "6": self._reports,
                    "7": self._about,
                }.get(choice)
                if action is None:
                    self._invalid_selection()
                    continue
                action()
        except EOFError:
            return 0
        except KeyboardInterrupt:
            self._error_console.print("[yellow]Interactive session canceled.[/yellow]")
            return 130

    def _render_main_menu(self) -> None:
        self._clear()
        branding = create_branding(self._console.width, __version__)
        self._console.print(branding.header)
        self._console.print()
        self._console.print(create_main_menu(self._console.width))
        self._console.print(create_technical_note(self._console.width))
        self._console.print(navigation_text(("0", "Exit"), ("Q", "Exit")))
        self._console.print(branding.metadata)

    def _clear(self) -> None:
        if self._clear_enabled:
            self._console.clear()

    def _begin_screen(self, title: str, subtitle: str | None = None) -> None:
        self._clear()
        self._console.print(create_screen_header(title, subtitle))

    def _current_network(self) -> None:
        while True:
            self._begin_screen("Current Network", "Connection and local IP context")
            wifi = None
            network = None
            network_interfaces: tuple[NetworkInterface, ...] = ()
            try:
                network_interfaces = self._use_cases.interfaces.execute().interfaces
            except InterfaceCollectionError as error:
                network_interfaces = ()
                self._operation_unavailable("Interface association", error)
            try:
                wifi = self._use_cases.current_wifi.execute(network_interfaces)
            except WifiCollectionError as error:
                self._operation_unavailable("Current Wi-Fi", error)
            try:
                network = self._use_cases.current_network.execute_with_associations(
                    network_interfaces, wifi
                )
            except NetworkCollectionError as error:
                self._operation_unavailable("Current network", error)
            self._render_current_overview(wifi, network)
            while True:
                self._console.print("1. Overview")
                self._console.print("2. Wi-Fi Connection")
                self._console.print("3. IP Addresses")
                self._console.print("4. Routes")
                self._console.print("5. DNS / DHCP")
                self._console.print("6. Adapter")
                self._console.print("7. Wi-Fi Technical")
                self._console.print(navigation_text(("R", "Refresh"), ("0", "Back"), ("B", "Back")))
                choice = self._read("Select option: ").casefold()
                if choice in {"0", "b"}:
                    return
                if choice == "r":
                    break
                if choice == "1":
                    self._begin_screen("Current Network", "Overview")
                    self._render_current_overview(wifi, network)
                elif choice == "2":
                    self._render_current_wifi_details(wifi, include_connection=True)
                elif choice == "3":
                    self._render_current_ip_addresses(network)
                elif choice == "4":
                    self._render_current_routes(network)
                elif choice == "5":
                    self._render_current_dns_dhcp(network)
                elif choice == "6":
                    self._render_current_adapters(network_interfaces)
                elif choice == "7":
                    self._render_current_wifi_details(wifi, include_connection=False)
                else:
                    self._invalid_selection()
                    continue
                self._wait_for_back()
                self._begin_screen("Current Network", "Connection and local IP context")
                self._render_current_overview(wifi, network)

    def _render_current_overview(
        self,
        wifi: CurrentWifiSnapshot | None,
        network: CurrentNetworkSnapshot | None,
    ) -> None:
        self._console.print(self._renderers.current_overview(wifi, network, self._console.width))
        if wifi is not None:
            self._render_messages(tuple(issue.message for issue in wifi.issues))
        if network is not None:
            self._render_messages(tuple(issue.message for issue in network.issues))

    def _render_current_wifi_details(
        self, wifi: CurrentWifiSnapshot | None, include_connection: bool
    ) -> None:
        title = "Wi-Fi Connection" if include_connection else "Wi-Fi Technical"
        self._begin_screen(title)
        if wifi is None or not wifi.interfaces:
            self._console.print("Unavailable")
            return
        for interface in wifi.interfaces:
            self._console.print(self._renderers.wifi_table(interface))

    def _render_current_ip_addresses(self, network: CurrentNetworkSnapshot | None) -> None:
        self._begin_screen("IP Addresses")
        wide = self._console.width >= 140
        columns: list[tuple[str, dict[str, object]]] = [
            ("Address", {"no_wrap": True}),
            ("Family", {"no_wrap": True}),
            ("Network", {"overflow": "fold"}),
            ("Class", {"overflow": "fold"}),
            ("Origin", {"overflow": "fold"}),
            ("State", {"no_wrap": True}),
        ]
        if wide:
            columns.extend(
                (
                    ("Preferred", {"no_wrap": True}),
                    ("Valid", {"no_wrap": True}),
                    ("Skip source", {"no_wrap": True}),
                )
            )
        table = create_data_table(tuple(columns))
        assignments = (
            tuple(item for context in network.interfaces for item in context.addresses)
            if network is not None
            else ()
        )
        for item in assignments:
            row = [
                f"{item.address}/{item.prefix_length}",
                f"IPv{item.address.version}",
                str(item.network),
                ", ".join(item.classifications) or "Unknown",
                f"{item.prefix_origin.display_name} / {item.address_origin.display_name}",
                item.dad_state.display_name,
            ]
            if wide:
                row.extend(
                    (
                        _optional_counter(item.preferred_lifetime_seconds),
                        _optional_counter(item.valid_lifetime_seconds),
                        format_bool(item.skip_as_source),
                    )
                )
            table.add_row(*row)
        self._console.print(
            table if assignments else create_empty_state("No IP addresses available.")
        )

    def _render_current_routes(self, network: CurrentNetworkSnapshot | None) -> None:
        self._begin_screen("Routes")
        wide = self._console.width >= 140
        columns: list[tuple[str, dict[str, object]]] = [
            ("Destination", {"no_wrap": True}),
            ("Next hop", {"no_wrap": True}),
            ("Interface", {"no_wrap": True}),
            ("Metric", {"no_wrap": True}),
            ("Type", {"no_wrap": True}),
        ]
        if wide:
            columns.extend(
                (
                    ("Protocol", {"no_wrap": True}),
                    ("Origin", {"no_wrap": True}),
                    ("Effective", {"no_wrap": True}),
                )
            )
        table = create_data_table(tuple(columns))
        routes = network.routes if network is not None else ()
        for route in routes:
            row = [
                str(route.destination),
                str(route.next_hop),
                str(route.interface_index),
                str(route.route_metric),
                "Default" if route.is_default else "On-link" if route.is_on_link else "Route",
            ]
            if wide:
                row.extend(
                    (
                        route.protocol.display_name,
                        route.origin.display_name,
                        _optional_counter(route.effective_metric),
                    )
                )
            table.add_row(*row)
        self._console.print(table if routes else create_empty_state("No routes available."))

    def _render_current_dns_dhcp(self, network: CurrentNetworkSnapshot | None) -> None:
        self._begin_screen("DNS / DHCP")
        if network is None:
            self._console.print(create_empty_state("DNS and DHCP configuration unavailable."))
            return
        for context in network.interfaces:
            table = create_key_value_table(())
            table.add_row("Interface", str(context.interface_index))
            if context.dns is None:
                table.add_row("DNS", "Unavailable")
            else:
                table.add_row(
                    "DNS servers",
                    ", ".join(str(server) for server in context.dns.servers) or "None configured",
                )
                table.add_row("DNS suffix", Text(context.dns.suffix or "Unavailable"))
                table.add_row(
                    "DNS address registration",
                    _optional_boolean(context.dns.registration_enabled),
                )
                table.add_row(
                    "DNS suffix registration",
                    _optional_boolean(context.dns.suffix_registration_enabled),
                )
            table.add_row("DHCP IPv4", context.dhcp.ipv4_state.value)
            table.add_row("DHCP IPv6", context.dhcp.ipv6_state.value)
            table.add_row(
                "DHCP server", str(context.dhcp.server) if context.dhcp.server else "Unavailable"
            )
            table.add_row(
                "Lease obtained",
                format_timestamp(context.dhcp.lease_obtained),
            )
            table.add_row(
                "Lease expires",
                format_timestamp(context.dhcp.lease_expires),
            )
            self._console.print(table)

    def _render_current_adapters(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        self._begin_screen("Adapter")
        if not interfaces:
            self._console.print(create_empty_state("Adapter details unavailable."))
            return
        self._console.print(self._renderers.interface_table(interfaces, self._console.width))

    def _interfaces(self) -> None:
        inventory = None
        while True:
            self._begin_screen("Network Interfaces", "Windows adapter inventory")
            if inventory is None:
                try:
                    inventory = self._use_cases.interfaces.execute()
                except InterfaceCollectionError as error:
                    self._operation_unavailable("Network interfaces", error)
                    if self._refresh_or_back() == "0":
                        return
                    continue
            if inventory.interfaces:
                self._console.print(
                    self._renderers.interface_table(inventory.interfaces, self._console.width)
                )
            else:
                self._console.print("No network interfaces were reported by Windows.")
            self._render_messages(inventory.warnings)
            self._console.print(navigation_text(("R", "Refresh"), ("0", "Back"), ("B", "Back")))
            choice = self._read("Select interface: ").casefold()
            if choice in {"0", "b"}:
                return
            if choice == "r":
                inventory = None
                continue
            index = self._one_based_index(choice, len(inventory.interfaces))
            if index is not None:
                self._interface_detail(inventory.interfaces[index])

    def _interface_detail(self, interface: NetworkInterface) -> None:
        self._begin_screen("Interface Details", interface.friendly_name)
        self._console.print("Identity / State / Link", style="bold")
        self._console.print(
            create_key_value_table(
                (
                    ("Name", Text(interface.friendly_name)),
                    ("Alias", Text(interface.alias)),
                    ("Description", Text(interface.description or "Unavailable")),
                    ("Kind", interface.kind.value),
                    ("Operational state", interface.operational_state.value),
                    ("Administrative state", interface.administrative_state.value),
                    ("Media state", interface.media_state.value),
                    ("Interface index", str(interface.interface_index)),
                    ("Identifier", Text(interface.stable_id)),
                    ("Windows type", str(interface.windows_interface_type)),
                    ("MAC", str(interface.mac_address) if interface.mac_address else "Unavailable"),
                    ("MTU", str(interface.mtu) if interface.mtu is not None else "Unavailable"),
                    ("Receive link", format_rate(interface.receive_link_speed_bps)),
                    ("Transmit link", format_rate(interface.transmit_link_speed_bps)),
                )
            )
        )
        if interface.statistics is not None:
            statistics = interface.statistics
            self._console.print("Statistics", style="bold")
            self._console.print(
                create_key_value_table(
                    (
                        ("Source", statistics.provenance),
                        (
                            "Received bytes",
                            format_bytes(
                                statistics.received_bytes,
                                include_exact=self._console.width >= 140,
                            ),
                        ),
                        (
                            "Sent bytes",
                            format_bytes(
                                statistics.sent_bytes,
                                include_exact=self._console.width >= 140,
                            ),
                        ),
                        ("Received errors", _optional_counter(statistics.received_errors)),
                        ("Outbound errors", _optional_counter(statistics.outbound_errors)),
                        ("Received discards", _optional_counter(statistics.received_discards)),
                        ("Outbound discards", _optional_counter(statistics.outbound_discards)),
                    )
                )
            )
        else:
            self._console.print(create_empty_state("Adapter statistics unavailable."))
        hardware = interface.hardware
        self._console.print("Driver / Hardware", style="bold")
        self._console.print(
            create_key_value_table(
                (
                    ("Manufacturer", Text(interface.manufacturer or "Unavailable")),
                    ("Driver", Text(interface.driver_description or "Unavailable")),
                    ("Driver version", Text(interface.driver_version or "Unavailable")),
                    ("Hardware", _optional_boolean(interface.is_hardware)),
                    ("Virtual", _optional_boolean(interface.is_virtual)),
                    ("Hidden", _optional_boolean(interface.is_hidden)),
                    (
                        "Connector present",
                        _optional_boolean(hardware.connector_present)
                        if hardware
                        else "Unavailable",
                    ),
                    (
                        "Driver date",
                        Text(hardware.driver_date or "Unavailable") if hardware else "Unavailable",
                    ),
                    (
                        "Device identifier",
                        Text(hardware.device_id or "Unavailable") if hardware else "Unavailable",
                    ),
                )
            )
        )
        self._wait_for_back()

    def _nearby_wifi(self) -> None:
        snapshot: NearbyWifiSnapshot | None = None
        while True:
            self._begin_screen("Nearby Wi-Fi Networks", "Observational wireless environment")
            if snapshot is None:
                try:
                    snapshot = self._use_cases.nearby_wifi.execute()
                except WifiCollectionError as error:
                    self._operation_unavailable("Nearby Wi-Fi", error)
                    if self._refresh_or_back() == "0":
                        return
                    continue
            if snapshot.networks:
                self._console.print(
                    self._renderers.nearby_table(snapshot.networks, self._console.width)
                )
            else:
                self._console.print(create_empty_state("No nearby networks observed."))
            self._render_messages(tuple(issue.message for issue in snapshot.issues))
            self._console.print(navigation_text(("R", "Refresh"), ("0", "Back"), ("B", "Back")))
            choice = self._read("Select network: ").casefold()
            if choice in {"0", "b"}:
                return
            if choice == "r":
                snapshot = None
                continue
            index = self._one_based_index(choice, len(snapshot.networks))
            if index is not None:
                self._nearby_network(snapshot, index + 1)

    def _nearby_network(self, snapshot: NearbyWifiSnapshot, selection: int) -> None:
        try:
            details = self._use_cases.nearby_details.execute(
                snapshot, WifiNetworkSelection(selection)
            )
        except WifiSelectionError as error:
            self._operation_unavailable("Network details", error)
            return
        while True:
            self._begin_screen("Nearby Network Detail")
            self._renderers.nearby_details(details, None, self._console)
            self._console.print(navigation_text(("0", "Back"), ("B", "Back")))
            choice = self._read("Select access point: ").casefold()
            if choice in {"0", "b"}:
                return
            index = self._one_based_index(choice, len(details.network.access_points))
            if index is None:
                continue
            try:
                access_point = self._use_cases.nearby_details.select_access_point(
                    details, WifiAccessPointSelection(index + 1)
                )
            except WifiSelectionError as error:
                self._operation_unavailable("Access point details", error)
                continue
            self._begin_screen("Access Point Details")
            self._console.print(self._renderers.access_point_detail(access_point))
            self._wait_for_back()

    def _devices(self) -> None:
        allow_large_range = False
        refresh = True
        enriched = None
        while True:
            if refresh:
                try:
                    cancellation = Event()
                    discovered = self._use_cases.devices.execute(allow_large_range, cancellation)
                    if discovered.canceled:
                        self._error_console.print(
                            "[yellow]Local subnet discovery canceled.[/yellow]"
                        )
                        return
                    enriched = self._use_cases.enrichment.execute(discovered, cancellation)
                except RangeAuthorizationRequiredError as error:
                    self._error_console.print(Text(str(error)))
                    self._console.print("1. Run with large-range authorization")
                    self._console.print("0. Back")
                    while True:
                        choice = self._read("Select an option: ")
                        if choice == "0":
                            return
                        if choice == "1":
                            allow_large_range = True
                            break
                        self._invalid_selection()
                    continue
                except (DiscoveryError, NetworkCollectionError) as error:
                    self._operation_unavailable("Observed devices", error)
                    if self._refresh_or_back() == "0":
                        return
                    continue
                refresh = False
            if enriched is None:
                return
            self._begin_screen("Observed Devices", "Local snapshot and role evidence")
            if enriched.hosts:
                self._console.print(self._renderers.device_table(enriched, self._console.width))
            else:
                self._console.print(create_empty_state("No devices observed."))
            self._renderers.device_summary(enriched, self._console)
            self._render_messages(
                tuple(issue.message for issue in enriched.discovered.issues)
                + tuple(issue.message for issue in enriched.issues)
            )
            self._console.print(navigation_text(("R", "Refresh"), ("0", "Back"), ("B", "Back")))
            choice = self._read("Select device: ").casefold()
            if choice in {"0", "b"}:
                return
            if choice == "r":
                refresh = True
                continue
            index = self._one_based_index(choice, len(enriched.hosts))
            if index is not None:
                self._device_detail(enriched.hosts[index])

    def _device_detail(self, host: EnrichedHost) -> None:
        self._begin_screen("Device Details")
        discovered = host.discovered
        sources = ", ".join(
            source.value for source in sorted(discovered.sources, key=lambda item: item.value)
        )
        table = create_key_value_table(())
        table.add_row("Identity / Address", "")
        table.add_row("IP", str(discovered.address))
        table.add_row("Address family", discovered.address_family)
        table.add_row(
            "Address classification",
            ", ".join(discovered.address_classifications) or "Unknown",
        )
        table.add_row("Interface index", str(discovered.interface_index))
        table.add_row(
            "MAC", str(discovered.mac_address) if discovered.mac_address else "Unavailable"
        )
        table.add_row(
            "Locally administered MAC",
            _optional_boolean(
                discovered.mac_address.is_locally_administered
                if discovered.mac_address is not None
                else None
            ),
        )
        table.add_section()
        table.add_row("Name Resolution / Vendor", "")
        table.add_row("Hostname", Text(_hostname_display(host)))
        table.add_row("Hostname state", host.hostname.state.value)
        table.add_row(
            "Hostname source", host.hostname.source.value if host.hostname.source else "Unavailable"
        )
        table.add_row("Vendor", Text(_vendor_display(host)))
        table.add_row("Vendor state", host.vendor.state.value)
        table.add_row(
            "Vendor source", host.vendor.source.value if host.vendor.source else "Unavailable"
        )
        table.add_section()
        table.add_row("Observation / Neighbor", "")
        table.add_row("Reachability", discovered.reachability.value)
        table.add_row(
            "Neighbor state",
            discovered.neighbor_state.display_name
            if discovered.neighbor_state is not None
            else "Unavailable",
        )
        table.add_row("Discovery sources", sources)
        table.add_row(
            "Observation provenance",
            ", ".join(
                source.value for source in sorted(discovered.sources, key=lambda item: item.value)
            ),
        )
        table.add_section()
        table.add_row("Role Evidence / Provenance", "")
        table.add_row("Self evidence", _yes_no(DiscoverySource.SELF in discovered.sources))
        table.add_row("Gateway evidence", _yes_no(DiscoverySource.GATEWAY in discovered.sources))
        table.add_row("Neighbor router indication", _yes_no(discovered.is_router))
        table.add_row(
            "Role evidence",
            ", ".join(
                label
                for present, label in (
                    (DiscoverySource.SELF in discovered.sources, "Self"),
                    (DiscoverySource.GATEWAY in discovered.sources, "Gateway"),
                    (discovered.is_router, "Neighbor router indication"),
                )
                if present
            )
            or "None reported",
        )
        self._console.print(table)
        self._wait_for_back()

    def _full_scan(self) -> None:
        allow_large_range = False
        while True:
            snapshot = self._use_cases.full_scan.execute(allow_large_range, Event())
            self._render_full_scan(snapshot)
            while True:
                self._console.print("1. Refresh")
                self._console.print("2. Run with large-range authorization")
                self._console.print(navigation_text(("0", "Back"), ("B", "Back")))
                choice = self._read("Select option: ").casefold()
                if choice in {"0", "b"}:
                    return
                if choice == "1":
                    break
                if choice == "2":
                    allow_large_range = True
                    break
                self._invalid_selection()

    def _render_full_scan(self, snapshot: FullNetworkSnapshot) -> None:
        self._begin_screen("Full Network Scan", "Point-in-time multi-source summary")
        self._console.print(self._renderers.full_overview(snapshot))
        self._console.print(self._renderers.full_sections(snapshot))
        self._console.print(self._renderers.full_summary(snapshot, self._console.width))
        self._render_messages(tuple(issue.message for issue in snapshot.issues))

    def _reports(self) -> None:
        while True:
            self._begin_screen("Reports", "Export the current full-scan model")
            self._console.print("1. JSON")
            self._console.print("2. Markdown")
            self._console.print("3. JSON + Markdown")
            self._console.print(navigation_text(("0", "Back"), ("B", "Back")))
            choice = self._read("Select option: ").casefold()
            if choice in {"0", "b"}:
                return
            if choice not in {"1", "2", "3"}:
                self._invalid_selection()
                continue
            json_path = self._path_input("JSON report path: ") if choice in {"1", "3"} else None
            if choice in {"1", "3"} and json_path is None:
                continue
            markdown_path = (
                self._path_input("Markdown report path: ") if choice in {"2", "3"} else None
            )
            if choice in {"2", "3"} and markdown_path is None:
                continue
            if paths_conflict(json_path, markdown_path):
                self._operation_unavailable(
                    "Report export",
                    ReportPathError("JSON and Markdown reports must use different paths"),
                )
                continue
            snapshot = self._use_cases.full_scan.execute(False, Event())
            self._export_reports(snapshot, json_path, markdown_path)

    def _export_reports(
        self,
        snapshot: FullNetworkSnapshot,
        json_path: Path | None,
        markdown_path: Path | None,
    ) -> None:
        try:
            exports = self._use_cases.reports.execute(snapshot, json_path, markdown_path, False)
        except ReportWriteError as error:
            if "already exists" not in str(error):
                self._operation_unavailable("Report export", error)
                return
            self._error_console.print(Text(str(error)))
            self._console.print("1. Overwrite")
            self._console.print("0. Cancel")
            while True:
                overwrite_choice = self._read("Select option: ")
                if overwrite_choice == "0":
                    return
                if overwrite_choice == "1":
                    break
                self._invalid_selection()
            try:
                exports = self._use_cases.reports.execute(snapshot, json_path, markdown_path, True)
            except (ReportPathError, ReportWriteError) as retry_error:
                self._operation_unavailable("Report export", retry_error)
                return
        except ReportPathError as error:
            self._operation_unavailable("Report export", error)
            return
        self._console.print(create_notice("Success", "Report written"))
        self._console.print(
            create_key_value_table(
                (
                    ("Format", ", ".join(exported.format.value for exported in exports)),
                    ("Snapshot status", snapshot.status.value),
                )
            )
        )
        for exported in exports:
            self._console.print(
                Text.assemble(f"Path ({exported.format.value}): ", Text(str(exported.path)))
            )

    def _about(self) -> None:
        self._begin_screen("About")
        self._console.print(create_about_identity(__version__))
        self._console.print()
        self._console.print("Capabilities", style="bold")
        self._console.print("Current network inspection")
        self._console.print("Nearby Wi-Fi observation")
        self._console.print("Local device discovery")
        self._console.print("Deep network reporting")
        self._console.print("Security model", style="bold")
        self._console.print("Read-only; no credential extraction; no network mutation")
        self._wait_for_back()

    def _refresh_or_back(self) -> str:
        self._console.print("1. Refresh")
        self._console.print(navigation_text(("0", "Back"), ("B", "Back")))
        while True:
            choice = self._read("Select option: ").casefold()
            if choice in {"0", "b"}:
                return "0"
            if choice == "1":
                return "1"
            self._invalid_selection()

    def _wait_for_back(self) -> None:
        self._console.print(navigation_text(("0", "Back"), ("B", "Back")))
        while self._read("Select option: ").casefold() not in {"0", "b"}:
            self._invalid_selection()

    def _path_input(self, prompt: str) -> Path | None:
        value = self._read(prompt).strip()
        if not value:
            self._error_console.print("[yellow]Report export canceled: no path supplied.[/yellow]")
            return None
        return Path(value)

    def _one_based_index(self, value: str, length: int) -> int | None:
        try:
            index = int(value)
        except ValueError:
            self._invalid_selection()
            return None
        if index < 1 or index > length:
            self._invalid_selection()
            return None
        return index - 1

    def _read(self, prompt: str) -> str:
        return self._input(prompt).strip()

    def _invalid_selection(self) -> None:
        self._error_console.print("[yellow]Invalid selection.[/yellow]")

    def _operation_unavailable(self, label: str, error: Exception) -> None:
        self._error_console.print(create_notice("Unavailable", error, label))

    def _render_messages(self, messages: tuple[str, ...]) -> None:
        unique = tuple(dict.fromkeys(messages))
        if unique:
            self._error_console.print(create_notice("Partial", "\n".join(unique)))


def _optional_boolean(value: bool | None) -> str:
    if value is None:
        return "Unknown"
    return _yes_no(value)


def _yes_no(value: bool) -> str:
    return "Yes" if value else "No"


def _format_bits_per_second(value: int | None) -> str:
    if value is None:
        return "Unavailable"
    units = ((1_000_000_000, "Gbps"), (1_000_000, "Mbps"), (1_000, "Kbps"))
    for divisor, suffix in units:
        if value >= divisor:
            amount = value / divisor
            precision = 0 if amount.is_integer() else 1
            return f"{amount:.{precision}f} {suffix}"
    return f"{value} bps"


def _hostname_display(host: EnrichedHost) -> str:
    return host.hostname.hostname or host.hostname.state.value


def _vendor_display(host: EnrichedHost) -> str:
    return host.vendor.vendor or host.vendor.state.value


def _optional_counter(value: int | None) -> str:
    return str(value) if value is not None else "Unavailable"
