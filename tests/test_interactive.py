from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from io import StringIO
from pathlib import Path
from threading import Event
from typing import cast

import pytest
from rich.console import Console

from tests.reporting_samples import sample_snapshot
from tests.test_cli import _interface
from tests.test_devices_cli import (
    FakeDevices,
    MissingHostnames,
    UnavailableVendors,
    make_inventory,
)
from tests.test_nearby_wifi_cli import StaticCollector, _data
from wlanscope.application.discover_local_devices import DiscoverLocalDevices
from wlanscope.application.enrich_device_inventory import EnrichDeviceInventory
from wlanscope.application.export_full_network_report import ExportFullNetworkReport
from wlanscope.application.inspect_current_network import InspectCurrentNetwork
from wlanscope.application.inspect_current_wifi import InspectCurrentWifi
from wlanscope.application.inspect_nearby_wifi import InspectNearbyWifiNetwork
from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.application.run_full_network_scan import RunFullNetworkScan
from wlanscope.application.scan_nearby_wifi import ScanNearbyWifi
from wlanscope.cli import (
    _create_access_point_detail_table,
    _create_device_table,
    _create_full_scan_overview,
    _create_full_scan_section_table,
    _create_full_scan_summary,
    _create_interface_table,
    _create_nearby_wifi_table,
    _create_wifi_table,
    _render_device_summary,
    _render_nearby_wifi_details,
    main,
)
from wlanscope.domain.discovery import RangeAuthorizationRequiredError
from wlanscope.domain.full_scan import ScanSectionStatus
from wlanscope.domain.interfaces import InterfaceInventory
from wlanscope.domain.nearby_wifi import NearbyWifiSnapshot
from wlanscope.domain.network import CurrentNetworkSnapshot
from wlanscope.domain.wifi import CurrentWifiSnapshot, WifiCollectionError, WifiSsid
from wlanscope.interactive import (
    InteractiveRenderers,
    InteractiveSession,
    InteractiveUseCases,
)
from wlanscope.presentation.rendering import render_current_network_overview
from wlanscope.version import __version__


class ScriptedInput:
    def __init__(self, values: Sequence[str | BaseException]) -> None:
        self._values = iter(values)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        value = next(self._values)
        if isinstance(value, BaseException):
            raise value
        return value


class TrackingConsole(Console):
    def __init__(self, output: StringIO, force_terminal: bool) -> None:
        super().__init__(file=output, force_terminal=force_terminal, width=120)
        self.clear_calls = 0

    def clear(self, home: bool = True) -> None:
        self.clear_calls += 1


class ReturningUseCase:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls = 0
        self.arguments: list[tuple[object, ...]] = []

    def execute(self, *arguments: object) -> object:
        self.calls += 1
        self.arguments.append(arguments)
        return self.result

    def execute_with_associations(self, *arguments: object) -> object:
        return self.execute(*arguments)


class FailingUseCase:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    def execute(self, *arguments: object) -> object:
        self.calls += 1
        raise self.error

    def execute_with_associations(self, *arguments: object) -> object:
        return self.execute(*arguments)


class RangeProtectedDevices:
    def __init__(self) -> None:
        self.authorizations: list[bool] = []

    def execute(self, allow_large_range: bool, cancellation: Event) -> object:
        self.authorizations.append(allow_large_range)
        if not allow_large_range:
            raise RangeAuthorizationRequiredError(510)
        return make_inventory(usable_host_count=510)


def nearby_snapshot() -> NearbyWifiSnapshot:
    return ScanNearbyWifi(StaticCollector(_data())).execute()


def use_cases(
    *,
    interfaces: object | None = None,
    current_wifi: object | None = None,
    current_network: object | None = None,
    nearby: object | None = None,
    devices: object | None = None,
    enrichment: object | None = None,
    full_scan: object | None = None,
    reports: object | None = None,
) -> InteractiveUseCases:
    return InteractiveUseCases(
        cast(
            ListNetworkInterfaces,
            interfaces or ReturningUseCase(InterfaceInventory((_interface(),))),
        ),
        cast(
            InspectCurrentWifi,
            current_wifi or ReturningUseCase(CurrentWifiSnapshot(())),
        ),
        cast(
            InspectCurrentNetwork,
            current_network or ReturningUseCase(CurrentNetworkSnapshot((), ())),
        ),
        cast(ScanNearbyWifi, nearby or ReturningUseCase(nearby_snapshot())),
        InspectNearbyWifiNetwork(),
        cast(DiscoverLocalDevices, devices or FakeDevices(make_inventory())),
        cast(
            EnrichDeviceInventory,
            enrichment or EnrichDeviceInventory(MissingHostnames(), UnavailableVendors()),
        ),
        cast(RunFullNetworkScan, full_scan or ReturningUseCase(sample_snapshot())),
        cast(ExportFullNetworkReport, reports or ExportFullNetworkReport()),
    )


def run_session(
    values: Sequence[str | BaseException],
    selected_use_cases: InteractiveUseCases | None = None,
    width: int = 120,
) -> tuple[int, str, str, ScriptedInput]:
    output = StringIO()
    errors = StringIO()
    reader = ScriptedInput(values)
    session = InteractiveSession(
        selected_use_cases or use_cases(),
        interactive_renderers(),
        Console(file=output, force_terminal=False, width=width),
        Console(file=errors, force_terminal=False, width=width),
        reader,
    )
    return session.run(), output.getvalue(), errors.getvalue(), reader


def interactive_renderers() -> InteractiveRenderers:
    return InteractiveRenderers(
        _create_interface_table,
        _create_wifi_table,
        _create_nearby_wifi_table,
        _render_nearby_wifi_details,
        _create_access_point_detail_table,
        _create_device_table,
        _render_device_summary,
        render_current_network_overview,
        _create_full_scan_overview,
        _create_full_scan_section_table,
        _create_full_scan_summary,
    )


def test_root_tty_opens_menu_and_exits() -> None:
    output = StringIO()

    exit_code = main(
        [],
        input_reader=ScriptedInput(["0"]),
        stdin_is_tty=True,
        stdout_is_tty=True,
        console=Console(file=output, force_terminal=False),
        interface_use_case=use_cases().interfaces,
        wifi_use_case=use_cases().current_wifi,
        current_use_case=use_cases().current_network,
        nearby_wifi_use_case=use_cases().nearby_wifi,
        nearby_wifi_detail_use_case=use_cases().nearby_details,
        devices_use_case=use_cases().devices,
        device_enrichment_use_case=use_cases().enrichment,
        full_scan_use_case=use_cases().full_scan,
        report_export_use_case=use_cases().reports,
    )

    assert exit_code == 0
    assert "Current Network" in output.getvalue()
    assert "Observed Devices" in output.getvalue()
    assert "About" in output.getvalue()
    assert "Windows Wireless & Network Reconnaissance" in output.getvalue()
    assert "WLANScope Note" in output.getvalue()
    assert "Created by sasser" in output.getvalue()
    assert __version__ in output.getvalue()


def test_root_non_tty_prints_help_without_reading_input() -> None:
    output = StringIO()
    reader = ScriptedInput([AssertionError("Input must not be read")])

    exit_code = main(
        [],
        input_reader=reader,
        stdin_is_tty=False,
        stdout_is_tty=False,
        console=Console(file=output, force_terminal=False),
    )

    assert exit_code == 0
    assert "usage: wlanscope" in output.getvalue()
    assert "\x1b" not in output.getvalue()
    assert reader.prompts == []


@pytest.mark.parametrize("width", (80, 120, 160))
def test_root_landing_remains_complete_at_supported_widths(width: int) -> None:
    exit_code, output, _, reader = run_session(["0"], width=width)

    assert exit_code == 0
    assert "Windows Wireless & Network Reconnaissance" in output
    assert "Main Menu" in output
    assert "WLANScope Note" in output
    assert "Created by sasser" in output
    assert __version__ in output
    assert reader.prompts == ["Select an option: "]
    assert max(map(len, output.splitlines())) <= width


def test_clear_requires_tty_and_enabled() -> None:
    tty_output = StringIO()
    tty_console = TrackingConsole(tty_output, True)
    tty_session = InteractiveSession(
        use_cases(),
        interactive_renderers(),
        tty_console,
        Console(file=StringIO(), force_terminal=False),
        ScriptedInput(["0"]),
        clear_enabled=True,
    )
    non_tty_console = TrackingConsole(StringIO(), False)
    non_tty_session = InteractiveSession(
        use_cases(),
        interactive_renderers(),
        non_tty_console,
        Console(file=StringIO(), force_terminal=False),
        ScriptedInput(["0"]),
        clear_enabled=True,
    )
    disabled_console = TrackingConsole(StringIO(), True)
    disabled_session = InteractiveSession(
        use_cases(),
        interactive_renderers(),
        disabled_console,
        Console(file=StringIO(), force_terminal=False),
        ScriptedInput(["0"]),
        clear_enabled=False,
    )

    assert tty_session.run() == 0
    assert non_tty_session.run() == 0
    assert disabled_session.run() == 0
    assert tty_console.clear_calls == 1
    assert non_tty_console.clear_calls == 0
    assert disabled_console.clear_calls == 0


def test_navigation_accepts_exit_and_back_aliases_case_insensitively() -> None:
    lower_code, _, _, _ = run_session(["q"])
    upper_code, output, _, _ = run_session(["1", "B", "Q"])

    assert lower_code == 0
    assert upper_code == 0
    assert "Current Network" in output


def test_current_network_back_redraws_overview_before_continuing() -> None:
    snapshot = sample_snapshot()
    assert snapshot.interfaces is not None
    assert snapshot.current_wifi is not None
    assert snapshot.current_network is not None

    exit_code, output, _, _ = run_session(
        ["1", "3", "b", "0", "q"],
        use_cases(
            interfaces=ReturningUseCase(snapshot.interfaces),
            current_wifi=ReturningUseCase(snapshot.current_wifi),
            current_network=ReturningUseCase(snapshot.current_network),
        ),
    )

    assert exit_code == 0
    assert "IP Addresses" in output
    assert output.count("Connection and local IP context") == 2
    assert output.count("Addressing") == 2


def test_invalid_and_empty_main_menu_input_recovers() -> None:
    exit_code, output, errors, _ = run_session(["", "invalid", "-1", "999999", "0"])

    assert exit_code == 0
    assert output.count("Current Network") >= 5
    assert errors.count("Invalid selection") == 4


def test_ctrl_c_returns_130_without_traceback() -> None:
    exit_code, _, errors, _ = run_session([KeyboardInterrupt()])

    assert exit_code == 130
    assert "canceled" in errors
    assert "Traceback" not in errors


def test_eof_exits_cleanly() -> None:
    exit_code, _, errors, _ = run_session([EOFError()])

    assert exit_code == 0
    assert errors == ""


def test_current_network_refresh_is_explicit() -> None:
    interface = _interface()
    interfaces = ReturningUseCase(InterfaceInventory((interface,)))
    wifi = ReturningUseCase(CurrentWifiSnapshot(()))
    network = ReturningUseCase(CurrentNetworkSnapshot((), ()))

    exit_code, output, _, _ = run_session(
        ["1", "invalid", "r", "0", "0"],
        use_cases(
            interfaces=interfaces,
            current_wifi=wifi,
            current_network=network,
        ),
    )

    assert exit_code == 0
    assert interfaces.calls == 2
    assert wifi.calls == 2
    assert network.calls == 2
    assert wifi.arguments == [((interface,),), ((interface,),)]
    assert all(arguments[0] == (interface,) for arguments in network.arguments)
    assert "Addressing" in output
    assert "Unavailable" in output


def test_current_network_unavailable_returns_to_session() -> None:
    wifi = FailingUseCase(WifiCollectionError("Current source unavailable"))
    network = ReturningUseCase(CurrentNetworkSnapshot((), ()))

    exit_code, output, errors, _ = run_session(
        ["1", "0", "7", "0", "0"],
        use_cases(current_wifi=wifi, current_network=network),
    )

    assert exit_code == 0
    assert "Current Wi-Fi" in errors
    assert "Current source unavailable" in errors
    assert network.calls == 1
    assert "sasser" in output


def test_current_network_renders_wifi_and_profile_deep_data() -> None:
    snapshot = sample_snapshot()
    assert snapshot.interfaces is not None
    assert snapshot.current_wifi is not None
    assert snapshot.current_network is not None

    exit_code, output, _, _ = run_session(
        ["1", "0", "0"],
        use_cases(
            interfaces=ReturningUseCase(snapshot.interfaces),
            current_wifi=ReturningUseCase(snapshot.current_wifi),
            current_network=ReturningUseCase(snapshot.current_network),
        ),
    )

    assert exit_code == 0
    assert "Connection" in output
    assert "Addressing" in output
    assert "Wireless" in output
    assert "Example Wi-Fi" in output
    assert "IPv4 connectivity" in output


def test_current_network_deep_navigation_reuses_one_collection() -> None:
    snapshot = sample_snapshot()
    assert snapshot.interfaces is not None
    assert snapshot.current_wifi is not None
    assert snapshot.current_network is not None
    interfaces = ReturningUseCase(snapshot.interfaces)
    wifi = ReturningUseCase(snapshot.current_wifi)
    network = ReturningUseCase(snapshot.current_network)

    exit_code, output, _, _ = run_session(
        ["1", "3", "0", "4", "0", "5", "0", "6", "0", "7", "0", "0", "0"],
        use_cases(interfaces=interfaces, current_wifi=wifi, current_network=network),
    )

    assert exit_code == 0
    assert interfaces.calls == 1
    assert wifi.calls == 1
    assert network.calls == 1
    assert "IP Addresses" in output
    assert "Routes" in output
    assert "DNS / DHCP" in output
    assert "Wi-Fi Technical" in output
    assert output.count("Connection and local IP context") >= 6


def test_interface_detail_and_refresh_reuse_snapshot_until_requested() -> None:
    snapshot = sample_snapshot()
    assert snapshot.interfaces is not None
    interfaces = ReturningUseCase(snapshot.interfaces)

    exit_code, output, _, _ = run_session(
        ["2", "1", "0", "r", "0", "0"], use_cases(interfaces=interfaces)
    )

    assert exit_code == 0
    assert interfaces.calls == 2
    assert "Interface Details" in output
    assert "Driver version" in output
    assert "Received bytes" in output
    assert "Connector present" in output


def test_interface_invalid_selection_does_not_refresh_or_interpret_markup() -> None:
    interface = replace(
        _interface(),
        friendly_name="[bold]<adapter>[/bold]",
        description="vendor|name",
    )
    interfaces = ReturningUseCase(InterfaceInventory((interface,)))

    exit_code, output, errors, _ = run_session(
        ["2", "invalid", "1", "0", "0", "0"], use_cases(interfaces=interfaces)
    )

    assert exit_code == 0
    assert interfaces.calls == 1
    assert "Invalid selection" in errors
    assert "[bold]<adapter>[/bold]" in output
    assert "vendor|name" in output


def test_nearby_details_and_ap_reuse_snapshot_then_refresh_once() -> None:
    snapshot = sample_snapshot()
    assert snapshot.nearby_wifi is not None
    nearby = ReturningUseCase(snapshot.nearby_wifi)

    exit_code, output, _, _ = run_session(
        ["3", "1", "1", "0", "0", "r", "0", "0"],
        use_cases(nearby=nearby),
    )

    assert exit_code == 0
    assert nearby.calls == 2
    assert "Network Details" in output
    assert "Access Point Details" in output
    assert "Supported rates" in output
    assert "RSN group cipher" in output


def test_device_detail_renders_classification_and_provenance() -> None:
    snapshot = sample_snapshot()
    assert snapshot.devices is not None

    exit_code, output, _, _ = run_session(
        ["4", "1", "0", "0", "0"],
        use_cases(
            devices=ReturningUseCase(snapshot.devices.discovered),
            enrichment=ReturningUseCase(snapshot.devices),
        ),
    )

    assert exit_code == 0
    assert "Address classification" in output
    assert "Locally administered MAC" in output
    assert "Observation provenance" in output


def test_hidden_and_duplicate_ssids_are_selected_by_snapshot_index() -> None:
    original = nearby_snapshot()
    visible = original.networks[0]
    hidden = replace(visible, ssid=WifiSsid(b""), access_points=())
    snapshot = NearbyWifiSnapshot(
        original.interfaces,
        (hidden, visible, visible),
        original.issues,
    )
    nearby = ReturningUseCase(snapshot)

    exit_code, output, _, _ = run_session(
        ["3", "1", "0", "3", "0", "0", "0"], use_cases(nearby=nearby)
    )

    assert exit_code == 0
    assert nearby.calls == 1
    assert "<Hidden>" in output
    assert output.count("Network Details") == 2


def test_nearby_failure_does_not_end_session() -> None:
    nearby = FailingUseCase(WifiCollectionError("Location access is restricted"))
    current = ReturningUseCase(CurrentNetworkSnapshot((), ()))

    exit_code, output, errors, _ = run_session(
        ["3", "0", "1", "0", "0"],
        use_cases(nearby=nearby, current_network=current),
    )

    assert exit_code == 0
    assert "Nearby Wi-Fi" in errors
    assert "Location access is restricted" in errors
    assert "Current Network" in output
    assert current.calls == 1


def test_interactive_empty_states_are_explicit() -> None:
    nearby = ReturningUseCase(NearbyWifiSnapshot((), ()))
    empty_inventory = replace(make_inventory(), hosts=(), probes_executed=0)
    devices = ReturningUseCase(empty_inventory)
    enrichment = ReturningUseCase(
        EnrichDeviceInventory(MissingHostnames(), UnavailableVendors()).execute(
            empty_inventory, Event()
        )
    )
    interface = replace(_interface(), statistics=None)

    nearby_code, nearby_output, _, _ = run_session(["3", "0", "0"], use_cases(nearby=nearby))
    devices_code, devices_output, _, _ = run_session(
        ["4", "0", "0"], use_cases(devices=devices, enrichment=enrichment)
    )
    interface_code, interface_output, _, _ = run_session(
        ["2", "1", "0", "0", "0"],
        use_cases(interfaces=ReturningUseCase(InterfaceInventory((interface,)))),
    )

    assert nearby_code == 0
    assert devices_code == 0
    assert interface_code == 0
    assert "No nearby networks observed." in nearby_output
    assert "No devices observed." in devices_output
    assert "Adapter statistics unavailable." in interface_output


def test_devices_detail_and_refresh_run_complete_pipeline() -> None:
    devices = ReturningUseCase(make_inventory())
    enrichment = ReturningUseCase(
        EnrichDeviceInventory(MissingHostnames(), UnavailableVendors()).execute(
            make_inventory(), Event()
        )
    )

    exit_code, output, _, _ = run_session(
        ["4", "1", "0", "r", "0", "0"],
        use_cases(devices=devices, enrichment=enrichment),
    )

    assert exit_code == 0
    assert devices.calls == 2
    assert enrichment.calls == 2
    assert "Device Details" in output
    assert "Gateway evidence" in output


def test_devices_large_range_requires_explicit_menu_action() -> None:
    devices = RangeProtectedDevices()

    exit_code, _, errors, _ = run_session(
        ["4", "invalid", "1", "0", "0"], use_cases(devices=devices)
    )

    assert exit_code == 0
    assert devices.authorizations == [False, True]
    assert "explicit large-range authorization" in errors
    assert "Invalid selection" in errors


def test_full_scan_refresh_and_large_range_authorization_are_explicit() -> None:
    full_scan = ReturningUseCase(sample_snapshot())

    exit_code, output, errors, _ = run_session(
        ["5", "invalid", "1", "2", "0", "0"], use_cases(full_scan=full_scan)
    )

    assert exit_code == 0
    assert [arguments[0] for arguments in full_scan.arguments] == [False, False, True]
    assert "Full Network Scan" in output
    assert "Invalid selection" in errors


def test_full_scan_partial_and_failed_snapshots_remain_navigable() -> None:
    partial = ReturningUseCase(sample_snapshot(ScanSectionStatus.PARTIAL))
    failed = ReturningUseCase(sample_snapshot(ScanSectionStatus.FAILED))

    partial_code, partial_output, _, _ = run_session(["5", "0", "0"], use_cases(full_scan=partial))
    failed_code, failed_output, _, _ = run_session(["5", "0", "0"], use_cases(full_scan=failed))

    assert partial_code == 0
    assert failed_code == 0
    assert "Partial" in partial_output
    assert "Failed" in failed_output


def test_reports_dual_format_use_one_snapshot(tmp_path: Path) -> None:
    full_scan = ReturningUseCase(sample_snapshot())
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"

    exit_code, output, _, _ = run_session(
        ["6", "3", str(json_path), str(markdown_path), "0", "0"],
        use_cases(full_scan=full_scan),
    )

    assert exit_code == 0
    assert full_scan.calls == 1
    assert json_path.exists()
    assert markdown_path.exists()
    assert "Report written" in output


def test_reports_conflicting_paths_are_rejected_before_scan(tmp_path: Path) -> None:
    full_scan = ReturningUseCase(sample_snapshot())
    target = tmp_path / "same.out"

    exit_code, _, errors, _ = run_session(
        ["6", "3", str(target), str(target), "0", "0"],
        use_cases(full_scan=full_scan),
    )

    assert exit_code == 0
    assert full_scan.calls == 0
    assert "different paths" in errors


def test_report_overwrite_requires_confirmation(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("original", encoding="utf-8")

    exit_code, _, errors, _ = run_session(
        ["6", "1", str(target), "invalid", "0", "0", "0"], use_cases()
    )

    assert exit_code == 0
    assert target.read_text(encoding="utf-8") == "original"
    assert "already exists" in errors
    assert "Invalid selection" in errors


def test_report_overwrite_confirmation_reuses_snapshot(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("original", encoding="utf-8")
    full_scan = ReturningUseCase(sample_snapshot())

    exit_code, _, _, _ = run_session(
        ["6", "1", str(target), "1", "0", "0"], use_cases(full_scan=full_scan)
    )

    assert exit_code == 0
    assert full_scan.calls == 1
    assert '"schema_version": "1.0"' in target.read_text(encoding="utf-8")


def test_report_missing_parent_does_not_end_session(tmp_path: Path) -> None:
    target = tmp_path / "missing" / "report.md"

    exit_code, output, errors, _ = run_session(["6", "2", str(target), "0", "7", "0", "0"])

    assert exit_code == 0
    assert "parent directory does not exist" in errors
    assert "sasser" in output


def test_about_uses_package_metadata_without_machine_data() -> None:
    exit_code, output, _, _ = run_session(["7", "0", "0"])

    assert exit_code == 0
    about = output[output.index("WLANScope  About") : output.rindex("Main Menu")]
    assert about.count("Created by") == 1
    assert about.count("sasser") == 1
    assert about.count("Version") == 1
    assert about.count(__version__) == 1
    assert "C:\\Users" not in output


def test_existing_subcommand_does_not_open_interactive_menu() -> None:
    output = StringIO()
    interfaces = ReturningUseCase(InterfaceInventory((_interface(),)))

    exit_code = main(
        ["adapters"],
        interface_use_case=cast(ListNetworkInterfaces, interfaces),
        input_reader=ScriptedInput([AssertionError("Input must not be read")]),
        stdin_is_tty=True,
        stdout_is_tty=True,
        console=Console(file=output, force_terminal=False),
    )

    assert exit_code == 0
    assert interfaces.calls == 1
    assert "0. Exit" not in output.getvalue()
