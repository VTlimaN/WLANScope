import argparse
from collections.abc import Sequence

from wlanscope.version import __version__

PROJECT_NAME = "WLANScope"
PROJECT_TAGLINE = "Windows Wireless & Network Reconnaissance"


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="wlanscope",
        description=f"{PROJECT_NAME} — {PROJECT_TAGLINE}",
        epilog="Created by sasser",
    )


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROJECT_NAME} {__version__}",
    )
    parser.parse_args(arguments)
    return 0
