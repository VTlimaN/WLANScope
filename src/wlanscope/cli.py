import argparse
from collections.abc import Sequence

from rich.console import Console
from rich.table import Table

from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.domain.interfaces import InterfaceCollectionError, NetworkInterface
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
    return parser


def main(
    arguments: Sequence[str] | None = None,
    interface_use_case: ListNetworkInterfaces | None = None,
    console: Console | None = None,
) -> int:
    parser = build_parser()
    parsed_arguments = parser.parse_args(arguments)
    if parsed_arguments.command == "adapters":
        return _list_adapters(
            interface_use_case or _create_interface_use_case(),
            console or Console(),
        )
    return 0


def _create_interface_use_case() -> ListNetworkInterfaces:
    from wlanscope.composition import create_list_network_interfaces

    return create_list_network_interfaces()


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
