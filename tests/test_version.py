from importlib import import_module
from importlib.metadata import metadata, version

import wlanscope


def test_package_import() -> None:
    assert import_module("wlanscope") is wlanscope


def test_version_matches_distribution_metadata() -> None:
    assert wlanscope.__version__ == version("wlanscope")


def test_project_metadata() -> None:
    project_metadata = metadata("wlanscope")

    assert project_metadata["Name"] == "wlanscope"
    assert project_metadata["Author"] == "sasser"
    assert project_metadata["Requires-Python"] == ">=3.12"
    assert project_metadata["License-Expression"] == "Apache-2.0"
