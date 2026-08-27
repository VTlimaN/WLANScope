from wlanscope.application.discover_local_devices import DiscoverLocalDevices
from wlanscope.application.enrich_device_inventory import EnrichDeviceInventory
from wlanscope.application.export_full_network_report import ExportFullNetworkReport
from wlanscope.application.inspect_current_network import InspectCurrentNetwork
from wlanscope.application.inspect_current_wifi import InspectCurrentWifi
from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.application.run_full_network_scan import RunFullNetworkScan
from wlanscope.application.scan_nearby_wifi import ScanNearbyWifi
from wlanscope.platform.dns import DnsPtrResolver
from wlanscope.platform.vendor_registry import LocalOuiVendorResolver
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
    return ScanNearbyWifi(NativeNearbyWifiCollector(), LocalOuiVendorResolver())


def create_discover_local_devices(
    current_network: InspectCurrentNetwork | None = None,
) -> DiscoverLocalDevices:
    return DiscoverLocalDevices(
        current_network=current_network or create_inspect_current_network(),
        neighbor_collector=WindowsNeighborCollector(),
        probe_service=NativeIcmpProbeService(),
    )


def create_enrich_device_inventory() -> EnrichDeviceInventory:
    return EnrichDeviceInventory(
        hostname_resolver=DnsPtrResolver(),
        vendor_resolver=LocalOuiVendorResolver(),
    )


def create_export_full_network_report() -> ExportFullNetworkReport:
    return ExportFullNetworkReport()


def create_run_full_network_scan() -> RunFullNetworkScan:
    interfaces = create_list_network_interfaces()
    current_wifi = create_inspect_current_wifi()
    current_network = create_inspect_current_network()
    return RunFullNetworkScan(
        interfaces=interfaces,
        current_wifi=current_wifi,
        current_network=current_network,
        nearby_wifi=create_scan_nearby_wifi(),
        devices=create_discover_local_devices(current_network),
        enrichment=create_enrich_device_inventory(),
    )
