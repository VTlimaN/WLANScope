from io import StringIO

import pytest
from rich.console import Console

from wlanscope.presentation import (
    LayoutMode,
    create_about_identity,
    create_branding,
    create_main_menu,
    create_technical_note,
)


def render(renderable: object, width: int, no_color: bool = False) -> str:
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=width, no_color=no_color)
    console.print(renderable)
    return output.getvalue()


@pytest.mark.parametrize(
    ("width", "expected_mode"),
    ((80, LayoutMode.COMPACT), (120, LayoutMode.STANDARD), (160, LayoutMode.WIDE)),
)
def test_branding_adapts_to_supported_widths(width: int, expected_mode: LayoutMode) -> None:
    branding = create_branding(width, "9.8.7")
    header = render(branding.header, width)
    metadata = render(branding.metadata, width)
    menu = render(create_main_menu(width), width)
    note = render(create_technical_note(width), width)

    assert branding.mode is expected_mode
    assert "Windows Wireless & Network Reconnaissance" in header
    assert "Read-only wireless and local network visibility for Windows." in header
    assert "WLANScope v9.8.7" in metadata
    assert "Created by sasser" in metadata
    assert "Current Network" in menu
    assert "WLANScope Note" in note
    assert "Sanitize them before public sharing." in note
    assert max(map(len, (header + menu + note + metadata).splitlines())) <= width


def test_compact_and_standard_use_text_wordmark_while_wide_uses_large_wordmark() -> None:
    compact = render(create_branding(80, "1.0").header, 80)
    standard = render(create_branding(120, "1.0").header, 120)
    wide = render(create_branding(160, "1.0").header, 160)

    assert compact.splitlines()[0].strip() == "WLANScope"
    assert standard.splitlines()[0].strip() == "WLANScope"
    assert "W   W L" not in compact + standard
    assert "W   W L" in wide
    assert len(wide.splitlines()) == 7


def test_about_identity_uses_consistent_creator_and_version_once() -> None:
    output = render(create_about_identity("9.8.7"), 80)

    assert "WLANScope" in output
    assert "Windows Wireless & Network Reconnaissance" in output
    assert output.count("Version") == 1
    assert output.count("9.8.7") == 1
    assert output.count("Created by") == 1
    assert output.count("sasser") == 1


def test_branding_remains_readable_without_color() -> None:
    branding = create_branding(160, "9.8.7")
    output = render(branding.header, 160, no_color=True) + render(
        branding.metadata, 160, no_color=True
    )

    assert "Windows Wireless & Network Reconnaissance" in output
    assert "Created by sasser" in output
    assert "\x1b" not in output


def test_technical_note_is_static_and_contains_no_host_data() -> None:
    output = render(create_technical_note(80), 80)

    assert "local network identifiers" in output
    assert "SSID" not in output
    assert "BSSID" not in output
    assert "192.168." not in output
    assert "C:\\Users" not in output
