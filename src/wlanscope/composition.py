from wlanscope.application.discover_local_devices import DiscoverLocalDevices
from wlanscope.application.inspect_current_network import InspectCurrentNetwork
from wlanscope.application.inspect_current_wifi import InspectCurrentWifi
from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.application.scan_nearby_wifi import ScanNearbyWifi
from wlanscope.platform.windows.icmp import NativeIcmpProbeService
from wlanscope.platform.windows.ip_configuration import WindowsIpConfigurationCollector
from wlanscope.platform.windows.ip_helper import WindowsInterfaceCollector
from wlanscope.platform.windows.native_wifi import NativeWifiCollector
from wlanscope.platform.windows.native_wifi_scan import NativeNearbyWifiCollector
from wlanscope.platform.windows.neighbors import WindowsNeighborCollector
from wlanscope.platform.windows.network_enrichment import (
    CimDhcpCollector,
    PowerShellNetworkCollector,
)
from wlanscope.platform.windows.powershell import PowerShellAdapterCollector


def create_list_network_interfaces() -> ListNetworkInterfaces:
    return ListNetworkInterfaces(
        primary_collector=WindowsInterfaceCollector(),
        enrichment_collector=PowerShellAdapterCollector(),
    )


def create_inspect_current_wifi() -> InspectCurrentWifi:
    return InspectCurrentWifi(
        wifi_collector=NativeWifiCollector(),
        interface_collector=WindowsInterfaceCollector(),
    )


def create_inspect_current_network() -> InspectCurrentNetwork:
    return InspectCurrentNetwork(
        primary_collector=WindowsIpConfigurationCollector(),
        enrichment_collector=PowerShellNetworkCollector(),
        dhcp_collector=CimDhcpCollector(),
        interface_collector=WindowsInterfaceCollector(),
        wifi_collector=NativeWifiCollector(),
    )


def create_scan_nearby_wifi() -> ScanNearbyWifi:
    return ScanNearbyWifi(NativeNearbyWifiCollector())


def create_discover_local_devices() -> DiscoverLocalDevices:
    return DiscoverLocalDevices(
        current_network=create_inspect_current_network(),
        neighbor_collector=WindowsNeighborCollector(),
        probe_service=NativeIcmpProbeService(),
    )
