from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.style import StyleType
from rich.table import Table
from rich.text import Text

from wlanscope.presentation.formatting import literal_text
from wlanscope.presentation.theme import (
    BORDER,
    HEADER,
    LABEL,
    MUTED,
    PRIMARY,
    STATUS_STYLES,
    TABLE_HEADER,
)


class LiteralTable(Table):
    def add_row(
        self,
        *renderables: RenderableType | None,
        style: StyleType | None = None,
        end_section: bool = False,
    ) -> None:
        safe_renderables = tuple(
            literal_text(renderable) if isinstance(renderable, str) else renderable
            for renderable in renderables
        )
        super().add_row(*safe_renderables, style=style, end_section=end_section)


def create_screen_header(title: str, subtitle: str | None = None) -> Panel:
    product = Text("WLANScope", style=PRIMARY)
    product.append("  ")
    product.append(title, style=HEADER)
    content: list[RenderableType] = [product]
    if subtitle:
        content.append(Text(subtitle, style=MUTED))
    return Panel(Group(*content), border_style=BORDER, padding=(0, 1))


def create_main_menu(width: int) -> Panel:
    table = LiteralTable(box=None, show_header=False, pad_edge=False, expand=True)
    table.add_column("Key", justify="right", style=PRIMARY, width=3, no_wrap=True)
    table.add_column("Option", overflow="fold")
    for key, label in (
        ("1", "Current Network"),
        ("2", "Network Interfaces"),
        ("3", "Nearby Wi-Fi Networks"),
        ("4", "Observed Devices"),
        ("5", "Full Network Scan"),
        ("6", "Reports"),
        ("7", "About"),
        ("0", "Exit"),
    ):
        table.add_row(key, label)
    panel_width = min(max(width - 4, 44), 76)
    return Panel(
        table,
        title="Main Menu",
        title_align="left",
        border_style=BORDER,
        width=panel_width,
        padding=(0, 1),
    )


def create_key_value_table(rows: Iterable[tuple[str, RenderableType]]) -> Table:
    table = LiteralTable(show_header=False, box=None, pad_edge=False, expand=False)
    table.add_column("Field", style=LABEL, no_wrap=True)
    table.add_column("Value", overflow="fold")
    for label, value in rows:
        table.add_row(label, value)
    return table


def create_data_table(columns: Sequence[tuple[str, Mapping[str, Any]]]) -> Table:
    table = LiteralTable(
        show_header=True,
        header_style=TABLE_HEADER,
        box=box.SIMPLE_HEAD,
        border_style=BORDER,
        pad_edge=False,
        expand=False,
    )
    for heading, options in columns:
        table.add_column(heading, **options)
    return table


def create_status_badge(status: str) -> Text:
    normalized = status.casefold()
    return Text(f"[ {status} ]", style=STATUS_STYLES.get(normalized, MUTED))


def create_notice(status: str, message: object, context: object | None = None) -> Panel:
    content: list[RenderableType] = [create_status_badge(status), literal_text(message)]
    if context is not None:
        content.append(literal_text(context))
    return Panel(Group(*content), border_style=BORDER, padding=(0, 1), expand=False)


def create_empty_state(message: object) -> Text:
    return literal_text(message, style=MUTED)


def navigation_text(*actions: tuple[str, str]) -> Text:
    text = Text()
    for index, (key, label) in enumerate(actions):
        if index:
            text.append("    ")
        text.append(key, style=PRIMARY)
        text.append(f" {label}", style=MUTED)
    return text
