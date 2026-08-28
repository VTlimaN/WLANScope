from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from enum import Enum
from typing import Any

from rich.style import StyleType
from rich.text import Text

_BIDI_CONTROLS = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


class LayoutMode(Enum):
    COMPACT = "compact"
    STANDARD = "standard"
    WIDE = "wide"


def layout_mode(width: int) -> LayoutMode:
    if width < 100:
        return LayoutMode.COMPACT
    if width < 140:
        return LayoutMode.STANDARD
    return LayoutMode.WIDE


class SafeText(Text):
    def __init__(self, text: str = "", *args: Any, **kwargs: Any) -> None:
        super().__init__(sanitize_terminal_text(text), *args, **kwargs)


def literal_text(value: object, style: StyleType | None = None) -> Text:
    safe_value = sanitize_terminal_text(str(value))
    return SafeText(safe_value) if style is None else SafeText(safe_value, style=style)


def sanitize_terminal_text(value: str) -> str:
    return "".join(
        _visible_escape(character)
        if ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F or character in _BIDI_CONTROLS
        else character
        for character in value
    )


def _visible_escape(character: str) -> str:
    value = ord(character)
    if value <= 0xFF:
        return f"\\x{value:02x}"
    return f"\\u{value:04x}"


def format_optional(value: object | None, unavailable: str = "Unavailable") -> str:
    return unavailable if value is None else str(value)


def format_bool(value: bool | None, unavailable: str = "Unknown") -> str:
    if value is None:
        return unavailable
    return "Yes" if value else "No"


def format_bytes(value: int | None, include_exact: bool = False) -> str:
    if value is None:
        return "Unavailable"
    sign = "-" if value < 0 else ""
    magnitude = abs(value)
    units = ("bytes", "KiB", "MiB", "GiB", "TiB")
    amount = float(magnitude)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == units[-1]:
            break
        amount /= 1024
    rendered = f"{sign}{magnitude} bytes" if unit == "bytes" else f"{sign}{amount:.2f} {unit}"
    if include_exact and unit != "bytes":
        return f"{rendered} ({value:,} bytes)"
    return rendered


def format_rate(value_bps: int | None) -> str:
    if value_bps is None:
        return "Unavailable"
    sign = "-" if value_bps < 0 else ""
    magnitude = abs(value_bps)
    for divisor, suffix in (
        (1_000_000_000, "Gbps"),
        (1_000_000, "Mbps"),
        (1_000, "kbps"),
    ):
        if magnitude >= divisor:
            amount = magnitude / divisor
            precision = 0 if amount.is_integer() else 1
            return f"{sign}{amount:.{precision}f} {suffix}"
    return f"{value_bps} bps"


def format_frequency(value_khz: int | None) -> str:
    if value_khz is None:
        return "Unavailable"
    frequency_mhz = value_khz / 1_000
    if frequency_mhz >= 1_000:
        return f"{frequency_mhz:,.3f} MHz ({frequency_mhz / 1_000:.3f} GHz)"
    return f"{frequency_mhz:,.3f} MHz"


def format_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "Unavailable"
    sign = "-" if seconds < 0 else ""
    remaining = abs(float(seconds))
    if remaining < 1:
        return f"{sign}{remaining * 1_000:.0f} ms"
    if remaining < 60:
        return f"{sign}{remaining:.1f} s"
    minutes, rest = divmod(int(remaining), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{sign}{hours} h {minutes} min {rest} s"
    return f"{sign}{minutes} min {rest} s"


def format_timestamp(value: datetime | None) -> str:
    if value is None:
        return "Unavailable"
    return value.isoformat(sep=" ", timespec="seconds")


def format_list(values: Iterable[object], empty: str = "Unavailable") -> str:
    materialized = tuple(values)
    return ", ".join(str(value) for value in materialized) if materialized else empty
