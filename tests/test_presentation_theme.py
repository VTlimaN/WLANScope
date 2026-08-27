from rich.console import Console
from rich.style import Style

from wlanscope.presentation import STATUS_STYLES, WLANSCOPE_THEME


def test_theme_loads_all_semantic_styles() -> None:
    console = Console(theme=WLANSCOPE_THEME)
    roles = (
        "primary",
        "secondary",
        "success",
        "warning",
        "error",
        "muted",
        "border",
        "label",
        "value",
    )

    assert all(isinstance(console.get_style(role), Style) for role in roles)


def test_status_mapping_covers_public_status_vocabulary() -> None:
    expected = {
        "success",
        "partial",
        "failed",
        "unavailable",
        "unsupported",
        "unknown",
        "not applicable",
        "canceled",
    }

    assert expected <= STATUS_STYLES.keys()
    assert all(isinstance(style, Style) for style in STATUS_STYLES.values())
