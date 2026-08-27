from __future__ import annotations

from dataclasses import dataclass

from rich.align import Align
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.text import Text

from wlanscope.presentation.formatting import LayoutMode, layout_mode
from wlanscope.presentation.theme import BORDER, MUTED, PRIMARY, SECONDARY

PRODUCT_NAME = "WLANScope"
TAGLINE = "Windows Wireless & Network Reconnaissance"
PURPOSE = "Read-only wireless and local network visibility for Windows."
CREATOR = "sasser"
TECHNICAL_NOTE = (
    "Reports may contain local network identifiers.\nSanitize them before public sharing."
)

_LARGE_WORDMARK = (
    ("W   W L      A    N   N  ", " SSS   CCCC  OOO  PPPP  EEEEE"),
    ("W   W L     A A   NN  N  ", "S     C     O   O P   P E"),
    ("W W W L    AAAAA  N N N  ", " SSS  C     O   O PPPP  EEEE"),
    ("WW WW L    A   A  N  NN  ", "    S C     O   O P     E"),
    ("W   W LLLL A   A  N   N  ", "SSSS   CCCC  OOO  P     EEEEE"),
)


@dataclass(frozen=True, slots=True)
class Branding:
    mode: LayoutMode
    header: RenderableType
    metadata: Text


def create_branding(width: int, version: str) -> Branding:
    mode = layout_mode(width)
    if mode is LayoutMode.WIDE:
        wordmark = _large_wordmark_text()
    else:
        wordmark = Text()
        wordmark.append("WLAN", style=PRIMARY)
        wordmark.append("Scope", style=SECONDARY)
    tagline = Text(TAGLINE, style=SECONDARY)
    purpose = Text(PURPOSE, style=MUTED)
    if mode is LayoutMode.COMPACT:
        header: RenderableType = Group(wordmark, tagline, purpose)
    else:
        header = Align.center(
            Group(Align.center(wordmark), Align.center(tagline), Align.center(purpose))
        )
    metadata = Text()
    metadata.append(f"{PRODUCT_NAME} v{version}", style=MUTED)
    metadata.append("  |  Created by ", style=MUTED)
    metadata.append(CREATOR, style=SECONDARY)
    return Branding(mode, header, metadata)


def create_technical_note(width: int) -> Panel:
    return Panel(
        Text(TECHNICAL_NOTE, style=MUTED, overflow="fold"),
        title="WLANScope Note",
        title_align="left",
        border_style=BORDER,
        padding=(0, 1),
        width=min(max(width - 4, 44), 76),
    )


def create_about_identity(version: str) -> Group:
    product = Text()
    product.append("WLAN", style=PRIMARY)
    product.append("Scope", style=SECONDARY)
    metadata = Text()
    metadata.append("Version      ", style=MUTED)
    metadata.append(version)
    creator = Text()
    creator.append("Created by   ", style=MUTED)
    creator.append(CREATOR, style=SECONDARY)
    return Group(product, Text(TAGLINE, style=SECONDARY), Text(), metadata, creator)


def _large_wordmark_text() -> Text:
    wordmark = Text()
    for index, (product, scope) in enumerate(_LARGE_WORDMARK):
        wordmark.append(product, style=PRIMARY)
        wordmark.append(scope, style=SECONDARY)
        if index < len(_LARGE_WORDMARK) - 1:
            wordmark.append("\n")
    return wordmark
