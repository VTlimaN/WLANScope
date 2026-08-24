# Limitations

WLANScope is at Milestone 0. The current package does not collect or analyze network data.

The following limitations define the planned v1 scope:

- Windows 10 and Windows 11 are the only target platforms.
- Future device discovery will report devices observable from the local host, not every client connected to a router or access point.
- Firewalls, wireless client isolation, VLAN boundaries, sleeping devices, routing policy, VPNs, and operating-system caches can reduce visibility.
- Wi-Fi SSID and BSSID data may depend on Windows location settings, user consent, adapter state, WLAN service state, hardware, and driver support.
- Collectors may return partial results when a source is unavailable, unsupported, denied, or malformed.
- A full scan will combine observations made at different times and will not represent an atomic network snapshot.
- Missing responses will not prove that a device is offline.
- WLANScope will not provide offensive wireless operations, credential access, exploitation, packet manipulation, or access-control bypass.

These constraints will be presented with scan results where they materially affect interpretation.

