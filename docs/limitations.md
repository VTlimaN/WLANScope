# Limitations

WLANScope currently inventories Windows network interfaces. It does not yet inspect the current Wi-Fi connection, IP configuration, nearby networks, or local devices.

The following limitations define the planned v1 scope:

- Windows 10 and Windows 11 are the only target platforms.
- Future device discovery will report devices observable from the local host, not every client connected to a router or access point.
- Firewalls, wireless client isolation, VLAN boundaries, sleeping devices, routing policy, VPNs, and operating-system caches can reduce visibility.
- Wi-Fi SSID and BSSID data may depend on Windows location settings, user consent, adapter state, WLAN service state, hardware, and driver support.
- Collectors may return partial results when a source is unavailable, unsupported, denied, or malformed.
- Adapter manufacturer, driver, hidden, and virtual metadata depends on `Get-NetAdapter` availability and may be reported as unavailable while the primary IP Helper inventory remains usable.
- Interface state is observed at collection time and can change immediately afterward.
- Physical and virtual classification uses structured Windows fields. M1 does not infer VPN status from adapter names.
- A full scan will combine observations made at different times and will not represent an atomic network snapshot.
- Missing responses will not prove that a device is offline.
- WLANScope will not provide offensive wireless operations, credential access, exploitation, packet manipulation, or access-control bypass.

These constraints will be presented with scan results where they materially affect interpretation.
