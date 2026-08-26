import json
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from wlanscope.domain.interfaces import (
    AdapterEnrichment,
    AdapterHardwareDetails,
    AdapterStatistics,
    AdministrativeState,
    InterfaceEnrichmentError,
    MediaState,
    normalize_stable_id,
)

DEFAULT_POWERSHELL_TIMEOUT_SECONDS = 15.0

ADAPTER_SCRIPT = "\n".join(
    (
        "$ErrorActionPreference = 'Stop'",
        "$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false",
        "$adapters = @(Get-NetAdapter -Name '*' -IncludeHidden -ErrorAction Stop)",
        (
            "$statistics = @(Get-NetAdapterStatistics -Name '*' -IncludeHidden "
            "-ErrorAction SilentlyContinue)"
        ),
        "$items = @($adapters | ForEach-Object {",
        "    $adapter = $_",
        "    $stats = @($statistics | Where-Object { $_.ifIndex -eq $adapter.ifIndex })[0]",
        "    [pscustomobject]@{",
        (
            "        InterfaceGuid = if ($null -eq $_.InterfaceGuid) "
            "{ $null } else { [string]$_.InterfaceGuid }"
        ),
        "        InterfaceIndex = if ($null -eq $_.ifIndex) { $null } else { [uint32]$_.ifIndex }",
        (
            "        Manufacturer = if ($null -eq $_.Manufacturer) "
            "{ $null } else { [string]$_.Manufacturer }"
        ),
        (
            "        DriverDescription = if ($null -eq $_.DriverDescription) "
            "{ $null } else { [string]$_.DriverDescription }"
        ),
        (
            "        DriverVersion = if ($null -eq $_.DriverVersion) "
            "{ $null } else { [string]$_.DriverVersion }"
        ),
        "        Virtual = if ($null -eq $_.Virtual) { $null } else { [bool]$_.Virtual }",
        "        Hidden = if ($null -eq $_.Hidden) { $null } else { [bool]$_.Hidden }",
        (
            "        AdminStatus = if ($null -eq $_.AdminStatus) "
            "{ $null } else { [string]$_.AdminStatus }"
        ),
        (
            "        MediaConnectionState = if ($null -eq $_.MediaConnectionState) "
            "{ $null } else { [string]$_.MediaConnectionState }"
        ),
        (
            "        ReceiveLinkSpeed = if ($null -eq $_.ReceiveLinkSpeed) "
            "{ $null } else { [uint64]$_.ReceiveLinkSpeed }"
        ),
        (
            "        TransmitLinkSpeed = if ($null -eq $_.TransmitLinkSpeed) "
            "{ $null } else { [uint64]$_.TransmitLinkSpeed }"
        ),
        "        Statistics = if ($null -eq $stats) { $null } else { [pscustomobject]@{",
        (
            "            ReceivedBytes = if ($null -eq $stats.ReceivedBytes) "
            "{ $null } else { [uint64]$stats.ReceivedBytes }"
        ),
        (
            "            SentBytes = if ($null -eq $stats.SentBytes) "
            "{ $null } else { [uint64]$stats.SentBytes }"
        ),
        (
            "            ReceivedUnicastPackets = if ($null -eq $stats.ReceivedUnicastPackets) "
            "{ $null } else { [uint64]$stats.ReceivedUnicastPackets }"
        ),
        (
            "            SentUnicastPackets = if ($null -eq $stats.SentUnicastPackets) "
            "{ $null } else { [uint64]$stats.SentUnicastPackets }"
        ),
        (
            "            ReceivedMulticastPackets = if ($null -eq $stats.ReceivedMulticastPackets) "
            "{ $null } else { [uint64]$stats.ReceivedMulticastPackets }"
        ),
        (
            "            SentMulticastPackets = if ($null -eq $stats.SentMulticastPackets) "
            "{ $null } else { [uint64]$stats.SentMulticastPackets }"
        ),
        (
            "            ReceivedBroadcastPackets = if ($null -eq $stats.ReceivedBroadcastPackets) "
            "{ $null } else { [uint64]$stats.ReceivedBroadcastPackets }"
        ),
        (
            "            SentBroadcastPackets = if ($null -eq $stats.SentBroadcastPackets) "
            "{ $null } else { [uint64]$stats.SentBroadcastPackets }"
        ),
        (
            "            ReceivedDiscards = if ($null -eq $stats.ReceivedDiscardedPackets) "
            "{ $null } else { [uint64]$stats.ReceivedDiscardedPackets }"
        ),
        (
            "            OutboundDiscards = if ($null -eq $stats.OutboundDiscardedPackets) "
            "{ $null } else { [uint64]$stats.OutboundDiscardedPackets }"
        ),
        (
            "            ReceivedErrors = if ($null -eq $stats.ReceivedPacketErrors) "
            "{ $null } else { [uint64]$stats.ReceivedPacketErrors }"
        ),
        (
            "            OutboundErrors = if ($null -eq $stats.OutboundPacketErrors) "
            "{ $null } else { [uint64]$stats.OutboundPacketErrors }"
        ),
        "        }}",
        "        Hardware = [pscustomobject]@{",
        (
            "            ConnectorPresent = if ($null -eq $_.ConnectorPresent) "
            "{ $null } else { [bool]$_.ConnectorPresent }"
        ),
        (
            "            DriverDate = if ($null -eq $_.DriverDate) "
            "{ $null } else { [string]$_.DriverDate }"
        ),
        (
            "            DeviceId = if ($null -eq $_.PnPDeviceID) "
            "{ $null } else { [string]$_.PnPDeviceID }"
        ),
        "        }",
        "    }",
        "})",
        "ConvertTo-Json -InputObject $items -Depth 3 -Compress",
    )
)


@dataclass(frozen=True, slots=True)
class ProcessResult:
    return_code: int
    stdout: str
    stderr: str


ProcessExecutor = Callable[[Sequence[str], float], ProcessResult]


class PowerShellUnavailableError(InterfaceEnrichmentError):
    pass


class PowerShellTimeoutError(InterfaceEnrichmentError):
    pass


class PowerShellCommandError(InterfaceEnrichmentError):
    def __init__(self, return_code: int) -> None:
        self.return_code = return_code
        super().__init__(f"PowerShell command failed with exit code {return_code}")


class PowerShellDataError(InterfaceEnrichmentError):
    pass


class PowerShellRunner:
    def __init__(
        self,
        executable: str | None = None,
        timeout_seconds: float = DEFAULT_POWERSHELL_TIMEOUT_SECONDS,
        executor: ProcessExecutor | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("PowerShell timeout must be positive")
        self._executable = executable
        self._timeout_seconds = timeout_seconds
        self._executor = executor or _execute_process

    def run(self, script: str) -> str:
        executable = self._executable or shutil.which("powershell.exe")
        if executable is None:
            raise PowerShellUnavailableError("powershell.exe is unavailable")
        arguments = (
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        )
        try:
            result = self._executor(arguments, self._timeout_seconds)
        except subprocess.TimeoutExpired as error:
            raise PowerShellTimeoutError("PowerShell command timed out") from error
        except UnicodeError as error:
            raise PowerShellDataError("PowerShell returned invalid UTF-8 data") from error
        if result.return_code != 0:
            raise PowerShellCommandError(result.return_code)
        return result.stdout


class PowerShellAdapterCollector:
    def __init__(self, runner: PowerShellRunner | None = None) -> None:
        self._runner = runner or PowerShellRunner()

    def collect(self) -> tuple[AdapterEnrichment, ...]:
        return parse_adapter_enrichments(self._runner.run(ADAPTER_SCRIPT))


def parse_adapter_enrichments(output: str) -> tuple[AdapterEnrichment, ...]:
    if not output.strip():
        return ()
    try:
        parsed: object = json.loads(output)
    except json.JSONDecodeError as error:
        raise PowerShellDataError("PowerShell returned malformed adapter JSON") from error

    if isinstance(parsed, dict):
        records: list[object] = [parsed]
    elif isinstance(parsed, list):
        records = parsed
    else:
        raise PowerShellDataError("PowerShell adapter JSON must be an object or array")

    return tuple(_parse_adapter_record(record) for record in records)


def _execute_process(arguments: Sequence[str], timeout_seconds: float) -> ProcessResult:
    completed = subprocess.run(
        list(arguments),
        capture_output=True,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
        encoding="utf-8",
        errors="strict",
        shell=False,
        text=True,
        timeout=timeout_seconds,
    )
    return ProcessResult(completed.returncode, completed.stdout, completed.stderr)


def _parse_adapter_record(value: object) -> AdapterEnrichment:
    record = _string_keyed_mapping(value)
    stable_id_value = _optional_string(record.get("InterfaceGuid"))
    stable_id = normalize_stable_id(stable_id_value) if stable_id_value else None
    interface_index = _optional_integer(record.get("InterfaceIndex"))
    if stable_id is None and interface_index is None:
        raise PowerShellDataError("PowerShell adapter record has no stable identifier")

    return AdapterEnrichment(
        stable_id=stable_id,
        interface_index=interface_index,
        manufacturer=_optional_string(record.get("Manufacturer")),
        driver_description=_optional_string(record.get("DriverDescription")),
        driver_version=_optional_string(record.get("DriverVersion")),
        is_virtual=_optional_boolean(record.get("Virtual")),
        is_hidden=_optional_boolean(record.get("Hidden")),
        administrative_state=_administrative_state(record.get("AdminStatus")),
        media_state=_media_state(record.get("MediaConnectionState")),
        receive_link_speed_bps=_positive_integer(record.get("ReceiveLinkSpeed")),
        transmit_link_speed_bps=_positive_integer(record.get("TransmitLinkSpeed")),
        statistics=_adapter_statistics(record.get("Statistics")),
        hardware=_adapter_hardware(record.get("Hardware")),
    )


def _adapter_statistics(value: object) -> AdapterStatistics | None:
    if value is None:
        return None
    record = _string_keyed_mapping(value)
    names = (
        "ReceivedBytes",
        "SentBytes",
        "ReceivedUnicastPackets",
        "SentUnicastPackets",
        "ReceivedMulticastPackets",
        "SentMulticastPackets",
        "ReceivedBroadcastPackets",
        "SentBroadcastPackets",
        "ReceivedDiscards",
        "OutboundDiscards",
        "ReceivedErrors",
        "OutboundErrors",
    )
    statistics = AdapterStatistics(*(_optional_integer(record.get(name)) for name in names))
    return statistics if statistics.has_values else None


def _adapter_hardware(value: object) -> AdapterHardwareDetails | None:
    if value is None:
        return None
    record = _string_keyed_mapping(value)
    details = AdapterHardwareDetails(
        connector_present=_optional_boolean(record.get("ConnectorPresent")),
        driver_date=_optional_string(record.get("DriverDate")),
        device_id=_optional_string(record.get("DeviceId")),
    )
    if all(
        item is None for item in (details.connector_present, details.driver_date, details.device_id)
    ):
        return None
    return details


def _string_keyed_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PowerShellDataError("PowerShell adapter entry must be an object")
    if not all(isinstance(key, str) for key in value):
        raise PowerShellDataError("PowerShell adapter object contains a non-string key")
    return {str(key): item for key, item in value.items()}


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PowerShellDataError("PowerShell adapter string property has an invalid type")
    normalized = value.strip()
    return normalized or None


def _optional_integer(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise PowerShellDataError("PowerShell adapter integer property has an invalid type")
    if value < 0:
        raise PowerShellDataError("PowerShell adapter integer property cannot be negative")
    return value


def _positive_integer(value: object) -> int | None:
    parsed = _optional_integer(value)
    return parsed if parsed is not None and parsed > 0 else None


def _optional_boolean(value: object) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise PowerShellDataError("PowerShell adapter boolean property has an invalid type")
    return value


def _administrative_state(value: object) -> AdministrativeState:
    state = _optional_string(value)
    if state is None:
        return AdministrativeState.UNKNOWN
    states = {
        "up": AdministrativeState.UP,
        "down": AdministrativeState.DOWN,
        "testing": AdministrativeState.TESTING,
    }
    return states.get(state.casefold(), AdministrativeState.UNKNOWN)


def _media_state(value: object) -> MediaState:
    state = _optional_string(value)
    if state is None:
        return MediaState.UNKNOWN
    states = {
        "connected": MediaState.CONNECTED,
        "disconnected": MediaState.DISCONNECTED,
    }
    return states.get(state.casefold(), MediaState.UNKNOWN)
