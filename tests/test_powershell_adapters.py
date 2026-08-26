import subprocess
from collections.abc import Sequence

import pytest

from wlanscope.domain.interfaces import AdministrativeState, MediaState
from wlanscope.platform.windows.powershell import (
    ADAPTER_SCRIPT,
    PowerShellAdapterCollector,
    PowerShellCommandError,
    PowerShellDataError,
    PowerShellRunner,
    PowerShellTimeoutError,
    PowerShellUnavailableError,
    ProcessResult,
    parse_adapter_enrichments,
)

SINGLE_ADAPTER_JSON = """{
    "InterfaceGuid": "aaaaaaaa-0000-0000-0000-000000000001",
    "InterfaceIndex": 7,
    "Manufacturer": "Example Networks",
    "DriverDescription": "Example Adapter Driver",
    "DriverVersion": "1.2.3",
    "Virtual": false,
    "Hidden": false,
    "AdminStatus": "Up",
    "MediaConnectionState": "Connected",
    "ReceiveLinkSpeed": 1000000000,
    "TransmitLinkSpeed": 1000000000
}"""


def test_adapter_statistics_collection_is_one_batch_command() -> None:
    assert ADAPTER_SCRIPT.count("Get-NetAdapterStatistics") == 1
    assert "ForEach-Object" in ADAPTER_SCRIPT


def test_parse_single_adapter_object() -> None:
    enrichment = parse_adapter_enrichments(SINGLE_ADAPTER_JSON)[0]

    assert enrichment.interface_index == 7
    assert enrichment.manufacturer == "Example Networks"
    assert enrichment.administrative_state is AdministrativeState.UP
    assert enrichment.media_state is MediaState.CONNECTED


def test_parse_adapter_array() -> None:
    output = f"[{SINGLE_ADAPTER_JSON}, {SINGLE_ADAPTER_JSON}]"

    assert len(parse_adapter_enrichments(output)) == 2


def test_empty_output_produces_empty_enrichment() -> None:
    assert parse_adapter_enrichments("  \r\n") == ()


def test_missing_optional_properties_remain_unavailable() -> None:
    enrichment = parse_adapter_enrichments(
        '{"InterfaceGuid":"aaaaaaaa-0000-0000-0000-000000000001"}'
    )[0]

    assert enrichment.manufacturer is None
    assert enrichment.driver_version is None
    assert enrichment.is_hidden is None
    assert enrichment.administrative_state is AdministrativeState.UNKNOWN


def test_parses_adapter_statistics_and_hardware_details() -> None:
    output = """{
        "InterfaceGuid":"aaaaaaaa-0000-0000-0000-000000000001",
        "Statistics":{
            "ReceivedBytes":100,"SentBytes":200,
            "ReceivedUnicastPackets":10,"SentUnicastPackets":20,
            "ReceivedMulticastPackets":3,"SentMulticastPackets":4,
            "ReceivedBroadcastPackets":5,"SentBroadcastPackets":6,
            "ReceivedDiscards":1,"OutboundDiscards":2,
            "ReceivedErrors":7,"OutboundErrors":8
        },
        "Hardware":{
            "ConnectorPresent":true,
            "DriverDate":"2026-01-02",
            "DeviceId":"SANITIZED\\\\DEVICE"
        }
    }"""

    enrichment = parse_adapter_enrichments(output)[0]

    assert enrichment.statistics is not None
    assert enrichment.statistics.received_bytes == 100
    assert enrichment.statistics.outbound_errors == 8
    assert enrichment.hardware is not None
    assert enrichment.hardware.connector_present
    assert enrichment.hardware.device_id == "SANITIZED\\DEVICE"


def test_empty_hardware_and_absent_statistics_remain_unavailable() -> None:
    enrichment = parse_adapter_enrichments(
        '{"InterfaceGuid":"aaaaaaaa-0000-0000-0000-000000000001",'
        '"Hardware":{"ConnectorPresent":null,"DriverDate":null,"DeviceId":null}}'
    )[0]

    assert enrichment.statistics is None
    assert enrichment.hardware is None


def test_missing_statistic_property_is_not_converted_to_zero() -> None:
    enrichment = parse_adapter_enrichments(
        '{"InterfaceGuid":"aaaaaaaa-0000-0000-0000-000000000001",'
        '"Statistics":{"ReceivedBytes":0,"SentBytes":null}}'
    )[0]

    assert enrichment.statistics is not None
    assert enrichment.statistics.received_bytes == 0
    assert enrichment.statistics.sent_bytes is None
    assert enrichment.statistics.received_errors is None


def test_empty_statistics_object_remains_unavailable() -> None:
    enrichment = parse_adapter_enrichments(
        '{"InterfaceGuid":"aaaaaaaa-0000-0000-0000-000000000001","Statistics":{}}'
    )[0]

    assert enrichment.statistics is None


@pytest.mark.parametrize("output", ["not-json", "42", "[null]"])
def test_invalid_json_data_raises_data_error(output: str) -> None:
    with pytest.raises(PowerShellDataError):
        parse_adapter_enrichments(output)


def test_runner_uses_safe_powershell_arguments() -> None:
    captured_arguments: Sequence[str] = ()

    def executor(arguments: Sequence[str], timeout_seconds: float) -> ProcessResult:
        nonlocal captured_arguments
        captured_arguments = arguments
        assert timeout_seconds == 4.0
        return ProcessResult(0, "[]", "")

    output = PowerShellRunner("powershell.exe", 4.0, executor).run(ADAPTER_SCRIPT)

    assert output == "[]"
    assert "-NoProfile" in captured_arguments
    assert "-NonInteractive" in captured_arguments
    assert "-Command" in captured_arguments
    assert "ExecutionPolicy" not in captured_arguments
    assert captured_arguments[-1] == ADAPTER_SCRIPT


def test_runner_translates_timeout() -> None:
    def executor(arguments: Sequence[str], timeout_seconds: float) -> ProcessResult:
        raise subprocess.TimeoutExpired(arguments, timeout_seconds)

    with pytest.raises(PowerShellTimeoutError):
        PowerShellRunner("powershell.exe", executor=executor).run(ADAPTER_SCRIPT)


def test_runner_translates_nonzero_exit() -> None:
    def executor(arguments: Sequence[str], timeout_seconds: float) -> ProcessResult:
        return ProcessResult(5, "", "Access denied")

    with pytest.raises(PowerShellCommandError, match="exit code 5"):
        PowerShellRunner("powershell.exe", executor=executor).run(ADAPTER_SCRIPT)


def test_runner_reports_unavailable_command(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_executable(name: str) -> None:
        return None

    monkeypatch.setattr(
        "wlanscope.platform.windows.powershell.shutil.which",
        missing_executable,
    )

    with pytest.raises(PowerShellUnavailableError, match="unavailable"):
        PowerShellRunner().run(ADAPTER_SCRIPT)


def test_collector_parses_runner_output() -> None:
    def executor(arguments: Sequence[str], timeout_seconds: float) -> ProcessResult:
        return ProcessResult(0, SINGLE_ADAPTER_JSON, "")

    runner = PowerShellRunner("powershell.exe", executor=executor)

    assert len(PowerShellAdapterCollector(runner).collect()) == 1
