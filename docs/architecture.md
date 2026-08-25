# Architecture

## Implemented architecture

The project foundation provides packaging, metadata, CLI entry points, tests, build configuration, and continuous integration. Milestones 1 through 6 provide vertical features through four concrete layers:

- domain models normalize network-interface, byte-safe current and nearby Wi-Fi, IP assignment, DNS, DHCP, route, neighbor, and discovered-host data;
- application use cases coordinate interface inventory, optional enrichment, stable association, bounded local discovery, partial failures, and deterministic ordering;
- Windows platform adapters isolate IP Helper, Native WLAN API, PowerShell JSON, and optional CIM boundaries;
- the CLI renders normalized interface, current Wi-Fi, nearby Wi-Fi, current network, and observed-host views without accessing native sources directly.

Device enrichment and reporting components do not exist yet.

## Target boundaries

The planned dependency flow is:

```text
CLI
  -> Application
    -> Domain
    -> Windows platform adapters
    -> Discovery
    -> Reporting
```

The domain will not depend on subprocesses, PowerShell, Windows APIs, terminal rendering, or report formats. Application services will coordinate use cases. Windows-specific adapters will collect external data and normalize it at the platform boundary. Discovery will implement bounded defensive observation. Reporting will serialize completed snapshots without initiating collection.

Directories are added only when a milestone has real code to place in them. The current protocols are narrow boundaries consumed by the interface use case and its tests, not a general dependency injection framework.

## Data source policy

M1 uses `GetIfTable2` and `GetAdaptersAddresses` from IP Helper as primary structured sources. Their native records are copied into Python values before leaving the platform adapter. `Get-NetAdapter -IncludeHidden` supplies optional manufacturer, driver, hidden, and virtual metadata through explicitly selected properties serialized with `ConvertTo-Json`.

M2 uses `WlanOpenHandle`, `WlanEnumInterfaces`, and `WlanQueryInterface` from the Native WLAN API. Handles are closed and API-allocated buffers are released on both successful and exceptional paths. SSIDs retain their explicit byte length and raw bytes; terminal-safe text is derived separately. Current WLAN interfaces are associated with M1 interfaces only by a matching stable GUID.

M3 uses `GetUnicastIpAddressTable` and `GetIpForwardTable2` for primary IPv4/IPv6 assignments and routes. `GetAdaptersAddresses` supplies structured DNS ordering, interface metrics, DNS suffixes, DHCP state, and DHCP server data. Every MIB table is released with `FreeMibTable`. PowerShell networking cmdlets provide structured JSON fallback data, while `Win32_NetworkAdapterConfiguration` is isolated as optional DHCP enrichment.

Default gateways are derived only from `0.0.0.0/0` and `::/0` routes. Route and interface metrics remain separate; their sum is exposed only when both components are known. Concurrent defaults, including VPN routes, are preserved and preference remains unknown when metrics are missing or tied.

M4 reuses the Native WLAN handle and interface enumeration boundaries, requests scans with `WlanScan`, and waits for interface-specific ACM completion or failure notifications registered through `WlanRegisterNotification`. Registration is removed on successful, failed, and timed-out paths, and every wait has a fixed upper bound. `WlanGetAvailableNetworkList` supplies aggregate network and security metadata while `WlanGetNetworkBssList` supplies distinct access-point observations. Both API-owned lists are released with `WlanFreeMemory`.

Available networks and BSS observations remain separate until application orchestration groups them by byte-safe SSID and stable WLAN interface identity. Exact duplicate observations use a deterministic identity that includes interface, SSID, BSSID, and center frequency. Frequency remains stored in kHz; pure domain functions derive band and a channel only for recognized 2.4, 5, and 6 GHz frequencies.

M5 adds a pure application selection service over `NearbyWifiSnapshot`. One-based network and access-point indices refer only to the deterministic ordering within that snapshot, so hidden or duplicate SSIDs and observations from multiple interfaces remain unambiguous. Detail presentation receives the existing snapshot and never invokes the scanner. Opening network or BSS details therefore cannot combine observations from different scans.

The CLI exposes explicit `--details` and `--access-point` selectors. It does not prompt automatically, which keeps redirected and non-TTY execution deterministic. Network summaries, BSS counts, aggregate signal, observed signal, radio metadata, and individual BSS properties remain presentation concerns rather than new collection paths.

M6 consumes the preferred IPv4 routing context from M3 and chooses a subnet only when the default route, interface, preferred address, and prefix provide an unambiguous result. Range cardinality is checked before targets are materialized. Up to 256 usable addresses are allowed by default, ranges through 4,096 require `--allow-large-range`, and larger ranges are refused.

`GetIpNetTable2` captures IPv4 ARP and IPv6 Neighbor Discovery state before and after active probing, with API-owned memory released through `FreeMibTable`. IPv4 Echo probes use `IcmpCreateFile`, synchronous `IcmpSendEcho2` calls with a 750 ms bound, and `IcmpCloseHandle`. A bounded `ThreadPoolExecutor` uses at most 32 workers. IPv6 is never enumerated for probing.

Host identity is the interface and IP pair. Merge policy preserves self, gateway, neighbor-cache, and ICMP-response provenance independently, enriches a known host with a later MAC observation, and never treats ICMP silence as proof that a host is offline. Failures in a neighbor snapshot or ICMP boundary retain other evidence as a partial inventory.

PowerShell runs without a user profile, without a shell, without automatic execution-policy changes, and with a fixed timeout. Formatted tables and localized text parsing are not used.

Future Windows APIs and structured operating-system sources will follow the same priority. Localized textual commands remain last-resort fallbacks with dedicated parsers and sanitized fixtures.

Collection, parsing, normalization, orchestration, and presentation remain separate responsibilities.

## Reliability policy

Collectors will use explicit timeouts and return source-aware outcomes. Independent collector failures will produce partial results rather than erase valid observations. Unknown, unsupported, unavailable, and failed data will not be replaced by plausible values.

## Engineering policy

Production and test code use clear names, cohesive functions, explicit types, and narrow dependencies. Source code and tests contain no comments and avoid redundant docstrings. Documentation carries architectural explanations that do not belong inside code.

The roadmap is finite. Architecture may grow through M12 only when required by implemented behavior, and v1.0.0 is the stopping point for the approved scope.
