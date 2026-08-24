from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.platform.windows.ip_helper import WindowsInterfaceCollector
from wlanscope.platform.windows.powershell import PowerShellAdapterCollector


def create_list_network_interfaces() -> ListNetworkInterfaces:
    return ListNetworkInterfaces(
        primary_collector=WindowsInterfaceCollector(),
        enrichment_collector=PowerShellAdapterCollector(),
    )
