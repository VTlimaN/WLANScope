from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
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
)
from wlanscope.domain.enrichment import EnrichedDeviceInventory, EnrichedHost
from wlanscope.domain.full_scan import FullNetworkSnapshot
from wlanscope.domain.interfaces import InterfaceCollectionError, NetworkInterface
from wlanscope.domain.nearby_wifi import NearbyWifiSnapshot, WifiAccessPoint, WifiNetwork
from wlanscope.domain.network import (
    CurrentNetworkSnapshot,
    InterfaceNetworkContext,
    NetworkCollectionError,
    Route,
)
from wlanscope.domain.wifi import WifiCollectionError, WifiInterfaceSnapshot
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
    relevant_network_contexts: Callable[
        [CurrentNetworkSnapshot], tuple[InterfaceNetworkContext, ...]
    ]
    network_context_table: Callable[[InterfaceNetworkContext, tuple[Route, ...]], Table]
    nearby_table: Callable[[tuple[WifiNetwork, ...], int], Table]
    nearby_details: Callable[[NearbyWifiNetworkDetails, WifiAccessPoint | None, Console], None]
    access_point_detail: Callable[[WifiAccessPoint], Table]
    device_table: Callable[[EnrichedDeviceInventory, int], Table]
    device_summary: Callable[[EnrichedDeviceInventory, Console], None]
    full_overview: Callable[[FullNetworkSnapshot], Table]
    full_sections: Callable[[FullNetworkSnapshot], Table]
    full_summary: Callable[[FullNetworkSnapshot], Table]


class InteractiveSession:
    def __init__(
        self,
        use_cases: InteractiveUseCases,
        renderers: InteractiveRenderers,
        console: Console,
        error_console: Console,
        input_reader: InputReader,
    ) -> None:
        self._use_cases = use_cases
        self._renderers = renderers
        self._console = console
        self._error_console = error_console
        self._input = input_reader

    def run(self) -> int:
        try:
            while True:
                self._render_main_menu()
                choice = self._read("Select an option: ")
                if choice == "0":
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
        self._console.print("[bold]WLANScope[/bold]")
        self._console.print("Windows Wireless & Network Reconnaissance", style="dim")
        self._console.print("1. Current Network")
        self._console.print("2. Network Interfaces")
        self._console.print("3. Nearby Wi-Fi Networks")
        self._console.print("4. Observed Devices")
        self._console.print("5. Full Network Scan")
        self._console.print("6. Reports")
        self._console.print("7. About")
        self._console.print("0. Exit")

    def _current_network(self) -> None:
        while True:
            self._console.print("Current Network", style="bold")
            wifi = None
            network = None
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
            if wifi is not None:
                for interface in wifi.interfaces:
                    self._console.print(self._renderers.wifi_table(interface))
                if not wifi.interfaces:
                    self._console.print("Current Wi-Fi: Unavailable")
                self._render_messages(tuple(issue.message for issue in wifi.issues))
            if network is not None:
                relevant = self._renderers.relevant_network_contexts(network)
                for context in relevant:
                    self._console.print(
                        self._renderers.network_context_table(context, network.default_routes)
                    )
                if not relevant:
                    self._console.print("IP and routing context: Unavailable")
                self._render_messages(tuple(issue.message for issue in network.issues))
            while True:
                self._console.print("1. Refresh")
                self._console.print("0. Back")
                choice = self._read("Select an option: ")
                if choice == "0":
                    return
                if choice == "1":
                    break
                self._invalid_selection()

    def _interfaces(self) -> None:
        inventory = None
        while True:
            self._console.print("Network Interfaces", style="bold")
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
            self._console.print("R. Refresh")
            self._console.print("0. Back")
            choice = self._read("Select an interface or action: ").casefold()
            if choice == "0":
                return
            if choice == "r":
                inventory = None
                continue
            index = self._one_based_index(choice, len(inventory.interfaces))
            if index is not None:
                self._interface_detail(inventory.interfaces[index])

    def _interface_detail(self, interface: NetworkInterface) -> None:
        self._console.print("Interface Details", style="bold")
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column("Field", style="bold", no_wrap=True)
        table.add_column("Value", overflow="fold")
        rows: tuple[tuple[str, str | Text], ...] = (
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
            ("Receive link", _format_bits_per_second(interface.receive_link_speed_bps)),
            ("Transmit link", _format_bits_per_second(interface.transmit_link_speed_bps)),
            ("Manufacturer", Text(interface.manufacturer or "Unavailable")),
            ("Driver", Text(interface.driver_description or "Unavailable")),
            ("Driver version", Text(interface.driver_version or "Unavailable")),
            ("Hardware", _optional_boolean(interface.is_hardware)),
            ("Virtual", _optional_boolean(interface.is_virtual)),
            ("Hidden", _optional_boolean(interface.is_hidden)),
        )
        for label, value in rows:
            table.add_row(label, value)
        self._console.print(table)
        self._wait_for_back()

    def _nearby_wifi(self) -> None:
        snapshot: NearbyWifiSnapshot | None = None
        while True:
            if snapshot is None:
                try:
                    snapshot = self._use_cases.nearby_wifi.execute()
                except WifiCollectionError as error:
                    self._operation_unavailable("Nearby Wi-Fi", error)
                    if self._refresh_or_back() == "0":
                        return
                    continue
            self._console.print("Nearby Wi-Fi Networks", style="bold")
            if snapshot.networks:
                self._console.print(
                    self._renderers.nearby_table(snapshot.networks, self._console.width)
                )
            else:
                self._console.print("No nearby Wi-Fi networks were reported by Windows.")
            self._render_messages(tuple(issue.message for issue in snapshot.issues))
            self._console.print("R. Refresh")
            self._console.print("0. Back")
            choice = self._read("Select a network or action: ").casefold()
            if choice == "0":
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
            self._renderers.nearby_details(details, None, self._console)
            self._console.print("0. Back")
            choice = self._read("Select an access point or action: ")
            if choice == "0":
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
            self._console.print("Access Point Details", style="bold")
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
            self._console.print("Observed Devices", style="bold")
            self._console.print(self._renderers.device_table(enriched, self._console.width))
            self._renderers.device_summary(enriched, self._console)
            self._render_messages(
                tuple(issue.message for issue in enriched.discovered.issues)
                + tuple(issue.message for issue in enriched.issues)
            )
            self._console.print("R. Refresh")
            self._console.print("0. Back")
            choice = self._read("Select a device or action: ").casefold()
            if choice == "0":
                return
            if choice == "r":
                refresh = True
                continue
            index = self._one_based_index(choice, len(enriched.hosts))
            if index is not None:
                self._device_detail(enriched.hosts[index])

    def _device_detail(self, host: EnrichedHost) -> None:
        discovered = host.discovered
        sources = ", ".join(
            source.value for source in sorted(discovered.sources, key=lambda item: item.value)
        )
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column("Field", style="bold", no_wrap=True)
        table.add_column("Value", overflow="fold")
        table.add_row("IP", str(discovered.address))
        table.add_row("Interface index", str(discovered.interface_index))
        table.add_row(
            "MAC", str(discovered.mac_address) if discovered.mac_address else "Unavailable"
        )
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
        table.add_row("Reachability", discovered.reachability.value)
        table.add_row(
            "Neighbor state",
            discovered.neighbor_state.display_name
            if discovered.neighbor_state is not None
            else "Unavailable",
        )
        table.add_row("Discovery sources", sources)
        table.add_row("Self evidence", _yes_no(DiscoverySource.SELF in discovered.sources))
        table.add_row("Gateway evidence", _yes_no(DiscoverySource.GATEWAY in discovered.sources))
        self._console.print("Device Details", style="bold")
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
                self._console.print("0. Back")
                choice = self._read("Select an option: ")
                if choice == "0":
                    return
                if choice == "1":
                    break
                if choice == "2":
                    allow_large_range = True
                    break
                self._invalid_selection()

    def _render_full_scan(self, snapshot: FullNetworkSnapshot) -> None:
        self._console.print("Full Network Scan", style="bold")
        self._console.print(self._renderers.full_overview(snapshot))
        self._console.print(self._renderers.full_sections(snapshot))
        self._console.print(self._renderers.full_summary(snapshot))
        self._render_messages(tuple(issue.message for issue in snapshot.issues))

    def _reports(self) -> None:
        while True:
            self._console.print("Reports", style="bold")
            self._console.print("1. Run Full Scan and Export JSON")
            self._console.print("2. Run Full Scan and Export Markdown")
            self._console.print("3. Run Full Scan and Export JSON + Markdown")
            self._console.print("0. Back")
            choice = self._read("Select an option: ")
            if choice == "0":
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
                overwrite_choice = self._read("Select an option: ")
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
        self._console.print("Reports written", style="bold")
        for exported in exports:
            self._console.print(
                Text.assemble(f"{exported.format.value}: ", Text(str(exported.path)))
            )

    def _about(self) -> None:
        self._console.print("WLANScope", style="bold")
        self._console.print("Windows Wireless & Network Reconnaissance")
        self._console.print("Author: sasser")
        self._console.print(f"Version: {__version__}")
        self._console.print("Purpose: Read-only Windows wireless and local network visibility.")
        self._wait_for_back()

    def _refresh_or_back(self) -> str:
        self._console.print("1. Refresh")
        self._console.print("0. Back")
        while True:
            choice = self._read("Select an option: ")
            if choice in {"0", "1"}:
                return choice
            self._invalid_selection()

    def _wait_for_back(self) -> None:
        self._console.print("0. Back")
        while self._read("Select an option: ") != "0":
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
        self._error_console.print(Text(f"{label} unavailable: {error}"))

    def _render_messages(self, messages: tuple[str, ...]) -> None:
        for message in messages:
            self._error_console.print(Text.assemble(("Warning: ", "yellow"), Text(message)))


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
