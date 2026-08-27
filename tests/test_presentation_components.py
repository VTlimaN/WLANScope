from io import StringIO

import pytest
from rich.console import Console

from wlanscope.presentation import (
    create_data_table,
    create_empty_state,
    create_key_value_table,
    create_main_menu,
    create_notice,
    create_status_badge,
)


def render(renderable: object, width: int = 160) -> str:
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=width)
    console.print(renderable)
    return output.getvalue()


@pytest.mark.parametrize("width", (80, 120, 160))
def test_main_menu_is_readable_at_supported_widths(width: int) -> None:
    output = render(create_main_menu(width), width)

    assert "Main Menu" in output
    assert "Current Network" in output
    assert "Nearby Wi-Fi Networks" in output
    assert "Exit" in output
    assert max(map(len, output.splitlines())) <= width


def test_tables_treat_string_cells_as_literal_by_default() -> None:
    values = (
        "[bold]ssid[/bold]",
        "[red]danger[/red]",
        "<adapter>",
        "vendor|name",
        "`hostname`",
        "[path]",
    )
    key_values = create_key_value_table(
        tuple((f"Value {index}", value) for index, value in enumerate(values))
    )
    data = create_data_table((("External", {"overflow": "fold"}),))
    for value in values:
        data.add_row(value)

    key_output = render(key_values)
    data_output = render(data)
    assert all(value in key_output for value in values)
    assert all(value in data_output for value in values)


def test_status_notice_and_empty_state_remain_textual_without_color() -> None:
    status = render(create_status_badge("Unsupported"))
    notice = render(create_notice("Unavailable", "[red]danger[/red]", "Adapter"))
    empty = render(create_empty_state("No routes available."))

    assert "[ Unsupported ]" in status
    assert "[ Unavailable ]" in notice
    assert "[red]danger[/red]" in notice
    assert "No routes available." in empty
    assert "\x1b" not in status + notice + empty
