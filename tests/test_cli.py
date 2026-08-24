import subprocess
import sys
from io import StringIO

import pytest
from pytest import CaptureFixture
from rich.console import Console

from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.cli import PROJECT_NAME, PROJECT_TAGLINE, main
from wlanscope.domain.interfaces import (
    AdapterEnrichment,
    AdministrativeState,
    InterfaceCollectionError,
    InterfaceEnrichmentError,
    InterfaceKind,
    MacAddress,
    MediaState,
    NetworkInterface,
    OperationalState,
)
from wlanscope.version import __version__


def test_help_describes_available_cli(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_result:
        main(["--help"])

    output = capsys.readouterr().out

    assert exit_result.value.code == 0
    assert PROJECT_NAME in output
    assert PROJECT_TAGLINE in output
    assert "--version" in output


def test_version_uses_package_metadata(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_result:
        main(["--version"])

    assert exit_result.value.code == 0
    assert capsys.readouterr().out.strip() == f"{PROJECT_NAME} {__version__}"


@pytest.mark.parametrize("option", ["--help", "--version"])
def test_module_entry_point(option: str) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wlanscope", option],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert PROJECT_NAME in result.stdout
    assert result.stderr == ""


def test_module_entry_point_without_arguments() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wlanscope"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_cli_without_arguments_succeeds(capsys: CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert capsys.readouterr().out == ""


def test_adapters_command_renders_fake_interfaces() -> None:
    output = StringIO()
    use_case = ListNetworkInterfaces(StaticInterfaceCollector((_interface(),)))

    exit_code = main(
        ["adapters"],
        interface_use_case=use_case,
        console=Console(file=output, color_system=None, width=100),
    )

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Network Interfaces" in rendered
    assert "Ethernet" in rendered
    assert "02:00:00:00:00:01" in rendered


def test_adapters_command_handles_empty_inventory() -> None:
    output = StringIO()
    use_case = ListNetworkInterfaces(StaticInterfaceCollector(()))

    exit_code = main(
        ["adapters"],
        interface_use_case=use_case,
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 0
    assert "No network interfaces" in output.getvalue()


def test_adapters_command_reports_primary_failure() -> None:
    output = StringIO()
    use_case = ListNetworkInterfaces(FailingInterfaceCollector())

    exit_code = main(
        ["adapters"],
        interface_use_case=use_case,
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 1
    assert "Interface collection unavailable" in output.getvalue()


def test_adapters_command_reports_partial_enrichment() -> None:
    output = StringIO()
    use_case = ListNetworkInterfaces(
        StaticInterfaceCollector((_interface(),)),
        FailingAdapterEnrichmentCollector(),
    )

    exit_code = main(
        ["adapters"],
        interface_use_case=use_case,
        console=Console(file=output, color_system=None),
    )

    assert exit_code == 3
    assert "Warning" in output.getvalue()


class StaticInterfaceCollector:
    def __init__(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        self._interfaces = interfaces

    def collect(self) -> tuple[NetworkInterface, ...]:
        return self._interfaces


class FailingInterfaceCollector:
    def collect(self) -> tuple[NetworkInterface, ...]:
        raise InterfaceCollectionError("Interface collection unavailable")


class FailingAdapterEnrichmentCollector:
    def collect(self) -> tuple[AdapterEnrichment, ...]:
        raise InterfaceEnrichmentError("Adapter enrichment unavailable")


def _interface() -> NetworkInterface:
    return NetworkInterface(
        interface_index=7,
        stable_id="aaaaaaaa-0000-0000-0000-000000000001",
        alias="Adapter A",
        friendly_name="Adapter A",
        description="Sanitized adapter",
        windows_interface_type=6,
        kind=InterfaceKind.ETHERNET,
        operational_state=OperationalState.UP,
        administrative_state=AdministrativeState.UP,
        media_state=MediaState.CONNECTED,
        mac_address=MacAddress.from_text("02:00:00:00:00:01"),
        mtu=1500,
        receive_link_speed_bps=1_000_000_000,
        transmit_link_speed_bps=1_000_000_000,
        is_hardware=True,
    )
