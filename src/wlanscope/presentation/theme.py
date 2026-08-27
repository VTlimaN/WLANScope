from rich.style import Style
from rich.theme import Theme

PRIMARY = Style(color="cyan", bold=True)
SECONDARY = Style(color="bright_cyan")
SUCCESS = Style(color="green", bold=True)
WARNING = Style(color="yellow", bold=True)
ERROR = Style(color="red", bold=True)
MUTED = Style(color="bright_black")
BORDER = Style(color="bright_black")
LABEL = Style(color="cyan", bold=True)
VALUE = Style()
HEADER = Style(color="cyan", bold=True)
TABLE_HEADER = Style(color="bright_cyan", bold=True)

WLANSCOPE_THEME = Theme(
    {
        "primary": PRIMARY,
        "secondary": SECONDARY,
        "success": SUCCESS,
        "warning": WARNING,
        "error": ERROR,
        "muted": MUTED,
        "border": BORDER,
        "label": LABEL,
        "value": VALUE,
        "screen.header": HEADER,
        "table.header": TABLE_HEADER,
    }
)

STATUS_STYLES: dict[str, Style] = {
    "success": SUCCESS,
    "partial": WARNING,
    "failed": ERROR,
    "unavailable": Style(color="yellow"),
    "unsupported": MUTED,
    "unknown": MUTED,
    "not applicable": MUTED,
    "not attempted": MUTED,
    "canceled": WARNING,
    "skipped": MUTED,
    "available": SUCCESS,
}
