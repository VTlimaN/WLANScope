from datetime import UTC, datetime

import pytest
from rich.text import Text

from wlanscope.presentation import (
    LayoutMode,
    format_bool,
    format_bytes,
    format_duration,
    format_frequency,
    format_list,
    format_optional,
    format_rate,
    format_timestamp,
    layout_mode,
    literal_text,
    sanitize_terminal_text,
)


@pytest.mark.parametrize(
    ("width", "expected"),
    ((80, LayoutMode.COMPACT), (120, LayoutMode.STANDARD), (160, LayoutMode.WIDE)),
)
def test_layout_breakpoints(width: int, expected: LayoutMode) -> None:
    assert layout_mode(width) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (None, "Unavailable"),
        (0, "0 bytes"),
        (1023, "1023 bytes"),
        (1024, "1.00 KiB"),
        (1024**2, "1.00 MiB"),
        (1024**3, "1.00 GiB"),
        (-1024, "-1.00 KiB"),
    ),
)
def test_format_bytes_uses_iec_units(value: int | None, expected: str) -> None:
    assert format_bytes(value) == expected


def test_format_bytes_can_include_exact_value() -> None:
    assert format_bytes(1024**3 + 1, include_exact=True).endswith("(1,073,741,825 bytes)")


@pytest.mark.parametrize(
    ("value", "expected"),
    ((None, "Unavailable"), (0, "0 bps"), (1_000_000, "1 Mbps"), (-1_500, "-1.5 kbps")),
)
def test_format_rate(value: int | None, expected: str) -> None:
    assert format_rate(value) == expected


def test_optional_boolean_frequency_duration_and_timestamp() -> None:
    timestamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

    assert format_optional(None) == "Unavailable"
    assert format_optional(0) == "0"
    assert format_bool(None) == "Unknown"
    assert format_bool(True) == "Yes"
    assert format_bool(False) == "No"
    assert format_frequency(None) == "Unavailable"
    assert format_frequency(5_180_000) == "5,180.000 MHz (5.180 GHz)"
    assert format_duration(None) == "Unavailable"
    assert format_duration(0) == "0 ms"
    assert format_duration(-1.5) == "-1.5 s"
    assert format_duration(3661) == "1 h 1 min 1 s"
    assert format_timestamp(None) == "Unavailable"
    assert format_timestamp(timestamp) == "2026-01-02 03:04:05+00:00"


def test_format_list_accepts_finite_iterables_and_unicode() -> None:
    assert format_list(iter(("Wi-Fi", "6 GHz"))) == "Wi-Fi, 6 GHz"
    assert format_list(()) == "Unavailable"


def test_literal_text_preserves_markup_like_content() -> None:
    value = "[red]danger[/red] <adapter> `hostname` [path]"
    rendered = literal_text(value)

    assert isinstance(rendered, Text)
    assert rendered.plain == value
    assert rendered.spans == []


def test_terminal_text_neutralizes_controls_and_bidi_without_stripping_unicode() -> None:
    value = "Wi-Fi São Paulo \x1b[2J\nspoofed\u202e"

    assert sanitize_terminal_text(value) == ("Wi-Fi São Paulo \\x1b[2J\\x0aspoofed\\u202e")
    assert literal_text(value).plain == "Wi-Fi São Paulo \\x1b[2J\\x0aspoofed\\u202e"
