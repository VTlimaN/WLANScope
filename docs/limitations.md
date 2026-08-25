# Limitations

WLANScope currently inventories Windows network interfaces, inspects current Wi-Fi and IP/routing context, and discovers and details nearby Wi-Fi networks. It does not yet inspect local devices or provide a full-screen interactive terminal interface.

The following limitations define the planned v1 scope:

- Windows 10 and Windows 11 are the only target platforms.
- Future device discovery will report devices observable from the local host, not every client connected to a router or access point.
- Firewalls, wireless client isolation, VLAN boundaries, sleeping devices, routing policy, VPNs, and operating-system caches can reduce visibility.
- Wi-Fi SSID and BSSID data may depend on Windows location settings, user consent, adapter state, WLAN service state, hardware, and driver support.
- Nearby scans depend on radio and driver behavior. Windows may deny scan requests or withhold available-network and BSS data when location access is unavailable.
- Hidden networks can expose an empty SSID, and their identity cannot be inferred from an empty value.
- The radio environment can change between scan completion, available-network retrieval, and BSS-list retrieval, so nearby results are not atomic.
- Observations made by different WLAN interfaces remain distinct and may report different signal, BSS, or availability data for the same environment.
- Detail views reuse one scan snapshot. A network or access point can disappear or change immediately after that snapshot without altering the displayed data.
- Duplicate visible SSIDs and multiple hidden entries are selected by their position and interface-specific identity within a snapshot, not by display text alone.
- Multiple WLAN interfaces are preserved, but connection details can become stale independently while collection is in progress.
- The Native WLAN API may not expose every driver-specific radio or security detail.
- Collectors may return partial results when a source is unavailable, unsupported, denied, or malformed.
- PowerShell networking cmdlets and CIM can be denied by Windows policy. IP Helper results remain available while affected DNS, metric, or DHCP enrichment is reported as partial.
- DHCP lease timestamps are not collected because the optional CIM source is not sufficiently available to make them a dependable M3 contract.
- Multiple default routes and VPN routing are preserved. A single preferred route is not asserted when effective metrics are missing or tied.
- Adapter manufacturer, driver, hidden, and virtual metadata depends on `Get-NetAdapter` availability and may be reported as unavailable while the primary IP Helper inventory remains usable.
- Interface state is observed at collection time and can change immediately afterward.
- Physical and virtual classification uses structured Windows fields. M1 does not infer VPN status from adapter names.
- A full scan will combine observations made at different times and will not represent an atomic network snapshot.
- Current network data is assembled from sequential API calls and is not an atomic snapshot.
- Missing responses will not prove that a device is offline.
- WLANScope will not provide offensive wireless operations, credential access, exploitation, packet manipulation, or access-control bypass.

These constraints will be presented with scan results where they materially affect interpretation.
