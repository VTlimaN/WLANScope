import subprocess
from collections.abc import Sequence

import pytest

from wlanscope.domain.network import DhcpState, NetworkEnrichmentError
from wlanscope.platform.windows.network_enrichment import (
    CimDhcpCollector,
    PowerShellNetworkCollector,
    parse_dhcp_enrichments,
    parse_network_enrichments,
)
from wlanscope.platform.windows.powershell import (
    PowerShellCommandError,
    PowerShellRunner,
    PowerShellTimeoutError,
    ProcessResult,
)


def test_parses_network_enrichment_array() -> None:
    output = (
        '[{"InterfaceIndex":7,"AddressFamily":"IPv4","InterfaceMetric":25,'
        '"Dhcp":"Enabled","DnsSuffix":"example.invalid",'
        '"DnsServers":["192.0.2.53","198.51.100.53"]},'
        '{"InterfaceIndex":7,"AddressFamily":"IPv6","InterfaceMetric":30,'
        '"Dhcp":"Disabled","DnsSuffix":"example.invalid",'
        '"DnsServers":["2001:db8::53"]}]'
    )

    records = parse_network_enrichments(output)

    assert len(records) == 2
    assert records[0].interface_index == 7
    assert records[0].interface_metric == 25
    assert records[0].dhcp_state is DhcpState.ENABLED
    assert [str(server) for server in records[0].dns_servers] == [
        "192.0.2.53",
        "198.51.100.53",
    ]
    assert records[1].address_family == 6


def test_parses_single_network_object_and_missing_properties() -> None:
    records = parse_network_enrichments(
        '{"InterfaceIndex":8,"AddressFamily":"IPv6","InterfaceMetric":null,'
        '"Dhcp":null,"DnsSuffix":null,"DnsServers":null}'
    )

    assert len(records) == 1
    assert records[0].interface_metric is None
    assert records[0].dhcp_state is DhcpState.UNKNOWN
    assert records[0].dns_servers == ()


def test_empty_network_output_returns_empty_collection() -> None:
    assert parse_network_enrichments("  ") == ()


@pytest.mark.parametrize(
    "output",
    [
        "not-json",
        "42",
        '[{"AddressFamily":"IPv4"}]',
        '[{"InterfaceIndex":7,"AddressFamily":"Other"}]',
        (
            '[{"InterfaceIndex":7,"AddressFamily":"IPv4","InterfaceMetric":1,'
            '"DnsServers":["2001:db8::53"]}]'
        ),
    ],
)
def test_invalid_network_json_is_rejected(output: str) -> None:
    with pytest.raises(NetworkEnrichmentError):
        parse_network_enrichments(output)


def test_parses_dhcp_enabled_server_and_disabled_state() -> None:
    records = parse_dhcp_enrichments(
        '[{"InterfaceIndex":7,"DhcpEnabled":true,"DhcpServer":"192.0.2.1"},'
        '{"InterfaceIndex":8,"DhcpEnabled":false,"DhcpServer":null}]'
    )

    assert records[0].enabled
    assert str(records[0].server) == "192.0.2.1"
    assert not records[1].enabled
    assert records[1].server is None


@pytest.mark.parametrize(
    "output",
    [
        '[{"InterfaceIndex":7,"DhcpEnabled":"yes","DhcpServer":null}]',
        '[{"InterfaceIndex":7,"DhcpEnabled":true,"DhcpServer":"invalid"}]',
        '[{"InterfaceIndex":7,"DhcpEnabled":true,"DhcpServer":"2001:db8::1"}]',
    ],
)
def test_invalid_dhcp_enrichment_is_rejected(output: str) -> None:
    with pytest.raises(NetworkEnrichmentError):
        parse_dhcp_enrichments(output)


def test_network_collector_propagates_timeout() -> None:
    def timeout(arguments: Sequence[str], timeout_seconds: float) -> ProcessResult:
        raise subprocess.TimeoutExpired("powershell.exe", timeout_seconds)

    runner = PowerShellRunner(executable="powershell.exe", executor=timeout)

    with pytest.raises(PowerShellTimeoutError):
        PowerShellNetworkCollector(runner).collect()


def test_dhcp_collector_propagates_access_denied_command_failure() -> None:
    def denied(arguments: Sequence[str], timeout_seconds: float) -> ProcessResult:
        return ProcessResult(5, "", "Access denied")

    runner = PowerShellRunner(executable="powershell.exe", executor=denied)

    with pytest.raises(PowerShellCommandError):
        CimDhcpCollector(runner).collect()
