from __future__ import annotations

import json
from ipaddress import IPv4Address, ip_address

from wlanscope.domain.network import (
    DhcpEnrichment,
    DhcpState,
    InterfaceNetworkEnrichment,
    IpAddress,
    NetworkEnrichmentError,
)
from wlanscope.platform.windows.powershell import PowerShellDataError, PowerShellRunner

NETWORK_ENRICHMENT_SCRIPT = "\n".join(
    (
        "$ErrorActionPreference = 'Stop'",
        "$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false",
        "$dnsClients = @(Get-DnsClient -ErrorAction Stop)",
        "$dnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop)",
        "$items = @(Get-NetIPInterface -ErrorAction Stop | ForEach-Object {",
        "    $interface = $_",
        (
            "    $client = @($dnsClients | Where-Object { "
            "$_.InterfaceIndex -eq $interface.InterfaceIndex })[0]"
        ),
        "    $servers = @($dnsServers | Where-Object {",
        "        $_.InterfaceIndex -eq $interface.InterfaceIndex -and",
        "        [string]$_.AddressFamily -eq [string]$interface.AddressFamily",
        "    })",
        "    [pscustomobject]@{",
        "        InterfaceIndex = [uint32]$interface.InterfaceIndex",
        "        AddressFamily = [string]$interface.AddressFamily",
        (
            "        InterfaceMetric = if ($null -eq $interface.InterfaceMetric) "
            "{ $null } else { [uint32]$interface.InterfaceMetric }"
        ),
        "        Dhcp = if ($null -eq $interface.Dhcp) { $null } else { [string]$interface.Dhcp }",
        (
            "        DnsSuffix = if ($null -eq $client.ConnectionSpecificSuffix) "
            "{ $null } else { [string]$client.ConnectionSpecificSuffix }"
        ),
        "        DnsServers = @($servers | ForEach-Object { @($_.ServerAddresses) })",
        "    }",
        "})",
        "ConvertTo-Json -InputObject $items -Depth 4 -Compress",
    )
)

DHCP_ENRICHMENT_SCRIPT = "\n".join(
    (
        "$ErrorActionPreference = 'Stop'",
        "$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false",
        (
            "$items = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration "
            "-Filter 'IPEnabled=True' -ErrorAction Stop | ForEach-Object {"
        ),
        "    [pscustomobject]@{",
        "        InterfaceIndex = [uint32]$_.InterfaceIndex",
        "        DhcpEnabled = [bool]$_.DHCPEnabled",
        (
            "        DhcpServer = if ($null -eq $_.DHCPServer) "
            "{ $null } else { [string]$_.DHCPServer }"
        ),
        "    }",
        "})",
        "ConvertTo-Json -InputObject $items -Depth 3 -Compress",
    )
)


class PowerShellNetworkCollector:
    def __init__(self, runner: PowerShellRunner | None = None) -> None:
        self._runner = runner or PowerShellRunner()

    def collect(self) -> tuple[InterfaceNetworkEnrichment, ...]:
        try:
            return parse_network_enrichments(self._runner.run(NETWORK_ENRICHMENT_SCRIPT))
        except PowerShellDataError as error:
            raise NetworkEnrichmentError(str(error)) from error


class CimDhcpCollector:
    def __init__(self, runner: PowerShellRunner | None = None) -> None:
        self._runner = runner or PowerShellRunner()

    def collect(self) -> tuple[DhcpEnrichment, ...]:
        try:
            return parse_dhcp_enrichments(self._runner.run(DHCP_ENRICHMENT_SCRIPT))
        except PowerShellDataError as error:
            raise NetworkEnrichmentError(str(error)) from error


def parse_network_enrichments(output: str) -> tuple[InterfaceNetworkEnrichment, ...]:
    return tuple(_parse_network_record(record) for record in _parse_json_records(output))


def parse_dhcp_enrichments(output: str) -> tuple[DhcpEnrichment, ...]:
    return tuple(_parse_dhcp_record(record) for record in _parse_json_records(output))


def _parse_network_record(value: object) -> InterfaceNetworkEnrichment:
    record = _mapping(value)
    family = _address_family(record.get("AddressFamily"))
    return InterfaceNetworkEnrichment(
        interface_index=_required_integer(record.get("InterfaceIndex"), "InterfaceIndex"),
        address_family=family,
        interface_metric=_optional_integer(record.get("InterfaceMetric"), "InterfaceMetric"),
        dhcp_state=_dhcp_state(record.get("Dhcp")),
        dns_servers=_dns_servers(record.get("DnsServers"), family),
        dns_suffix=_optional_string(record.get("DnsSuffix"), "DnsSuffix"),
    )


def _parse_dhcp_record(value: object) -> DhcpEnrichment:
    record = _mapping(value)
    enabled = record.get("DhcpEnabled")
    if not isinstance(enabled, bool):
        raise NetworkEnrichmentError("DHCP enrichment contains an invalid enabled state")
    server_value = _optional_string(record.get("DhcpServer"), "DhcpServer")
    server = None
    if server_value:
        try:
            parsed = ip_address(server_value)
        except ValueError as error:
            raise NetworkEnrichmentError("DHCP enrichment contains an invalid server") from error
        if not isinstance(parsed, IPv4Address):
            raise NetworkEnrichmentError("DHCP server must be an IPv4 address")
        server = parsed
    return DhcpEnrichment(
        interface_index=_required_integer(record.get("InterfaceIndex"), "InterfaceIndex"),
        enabled=enabled,
        server=server,
    )


def _parse_json_records(output: str) -> tuple[object, ...]:
    if not output.strip():
        return ()
    try:
        parsed: object = json.loads(output)
    except json.JSONDecodeError as error:
        raise NetworkEnrichmentError("PowerShell returned malformed network JSON") from error
    if isinstance(parsed, dict):
        return (parsed,)
    if isinstance(parsed, list):
        return tuple(parsed)
    raise NetworkEnrichmentError("PowerShell network JSON must be an object or array")


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise NetworkEnrichmentError("PowerShell network entry must be an object")
    return {str(key): item for key, item in value.items()}


def _address_family(value: object) -> int:
    if not isinstance(value, str):
        raise NetworkEnrichmentError("PowerShell address family is unavailable")
    families = {"ipv4": 4, "ipv6": 6}
    try:
        return families[value.casefold()]
    except KeyError as error:
        raise NetworkEnrichmentError("PowerShell returned an unsupported address family") from error


def _dns_servers(value: object, family: int) -> tuple[IpAddress, ...]:
    if value is None:
        return ()
    values = value if isinstance(value, list) else [value]
    servers: list[IpAddress] = []
    for item in values:
        if not isinstance(item, str):
            raise NetworkEnrichmentError("PowerShell DNS server has an invalid type")
        try:
            server = ip_address(item)
        except ValueError as error:
            raise NetworkEnrichmentError("PowerShell returned an invalid DNS server") from error
        if server.version != family:
            raise NetworkEnrichmentError("DNS server address family does not match its record")
        servers.append(server)
    return tuple(servers)


def _dhcp_state(value: object) -> DhcpState:
    if value is None:
        return DhcpState.UNKNOWN
    if not isinstance(value, str):
        raise NetworkEnrichmentError("PowerShell DHCP state has an invalid type")
    states = {"enabled": DhcpState.ENABLED, "disabled": DhcpState.DISABLED}
    return states.get(value.casefold(), DhcpState.UNKNOWN)


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise NetworkEnrichmentError(f"PowerShell {name} has an invalid type")
    normalized = value.strip()
    return normalized or None


def _optional_integer(value: object, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NetworkEnrichmentError(f"PowerShell {name} has an invalid value")
    return value


def _required_integer(value: object, name: str) -> int:
    parsed = _optional_integer(value, name)
    if parsed is None:
        raise NetworkEnrichmentError(f"PowerShell {name} is unavailable")
    return parsed
