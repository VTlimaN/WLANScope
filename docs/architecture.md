# Architecture

## Implemented architecture

The project foundation provides packaging, metadata, CLI entry points, tests, build configuration, and continuous integration. Milestones 1 through 8 provide vertical features through four concrete layers:

- domain models normalize network-interface, byte-safe current and nearby Wi-Fi, IP assignment, DNS, DHCP, route, neighbor, and discovered-host data;
- application use cases coordinate interface inventory, stable association, bounded local discovery, device enrichment, partial failures, and deterministic ordering;
- Windows platform adapters isolate IP Helper, Native WLAN API, PowerShell JSON, and optional CIM boundaries;
- the CLI renders normalized interface, current Wi-Fi, nearby Wi-Fi, current network, and observed-host views without accessing native sources directly.

M9 provides persistent JSON and Markdown reporting without adding collection behavior.

## Target boundaries

The planned dependency flow is:

```text
CLI / Interactive
  -> Presentation
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

M7 runs only after M6 has produced its observed-host inventory. `EnrichDeviceInventory` wraps each unchanged discovered host with independent hostname and vendor outcomes; it never selects targets or invokes discovery. PTR queries use dnspython with a 750 ms per-query timeout, a 1.5 second lifetime, and at most 16 concurrent workers. IPv4 and already-observed IPv6 addresses are eligible. No PTR, timeout, and resolver failure remain distinct, and only systemic resolver failure produces a global issue.

Vendor lookup is local and optional. One IEEE public MA-L CSV export is loaded once per execution from the user data directory, and only validated 24-bit assignments participate in lookup. The project does not bundle or update the registry because upstream redistribution rights were not sufficiently explicit for repository inclusion. Missing registries and unknown prefixes are normal per-host outcomes; malformed registries are systemic issues. Locally administered, multicast, absent, and invalid MAC addresses are never attributed to a global vendor. Discovery provenance and enrichment provenance use separate types.

M8 adds `RunFullNetworkScan`, a sequential application orchestrator over the existing M1 through M7 use cases. Execution order is adapters, current Wi-Fi, current network, nearby Wi-Fi, local devices, then device enrichment. M5 detail selection is not invoked because the nearby snapshot already contains the summary data required by the full scan.

Results flow forward within one execution. M1 interfaces are supplied to M2 association, M1 and M2 snapshots are supplied to M3 association, the M3 snapshot is supplied to M6 planning, and the single M6 inventory is supplied to M7. Nearby Wi-Fi, device discovery, and enrichment therefore each run once. The standalone commands retain their original collection defaults.

`FullNetworkSnapshot` preserves the existing domain snapshots, timezone-aware UTC start and completion times, ordered section results, section-scoped issues, and a derived global status. Independent operational failures do not abort later independent stages. A device stage is skipped when current network context or a usable authorized subnet is unavailable. Unknown PTR and vendor outcomes remain normal and do not degrade status.

M9 introduces a one-way reporting boundary from `FullNetworkSnapshot` to explicit schema mapping or Markdown rendering and then to local file writing. Reporting modules depend only on domain models and package metadata; they do not import collectors, Windows platform modules, or `RunFullNetworkScan`. The CLI runs one full scan and passes the same immutable snapshot to every requested serializer.

JSON schema version `1.0` is independent of the package version. Mapping is deliberate rather than reflective, timestamps are normalized to UTC, and SSIDs preserve both safe display text and raw hexadecimal bytes. Markdown uses fixed sections and escapes external values before table or inline rendering. Both serializers are deterministic for the same snapshot.

Report writing uses UTF-8 temporary files in the destination directory, flushes and synchronizes content, and atomically renames or replaces the destination. Existing files are refused by default, `--force` enables replacement, missing parent directories are not created, and temporary files are removed after failures.

M10 keeps argparse and the existing command hierarchy while making the presentation boundary explicit. Normal results render to standard output; expected operational failures, partial-result warnings, policy guidance, and cancellation notices render to standard error. An injected console remains supported for deterministic offline tests, while real non-TTY execution disables interactive behavior and does not rely on ANSI styling.

Long-running device, full-scan, and nearby Wi-Fi scan flows normalize user cancellation to exit code 130 without hiding unexpected programming errors. Compact tables retain essential columns below 100 terminal columns and omit only secondary presentation fields; domain snapshots and reports remain complete and unchanged.

M10.5 adds an interactive presentation layer behind the root command. `InteractiveSession` receives the existing M1 through M9 use cases as an explicit immutable bundle and never imports Windows platform adapters, ctypes boundaries, collectors, or reporting serializers. The argparse subcommands retain their direct automation paths.

Interactive navigation retains nearby Wi-Fi, device, interface, and full-scan snapshots while opening details or returning within a screen. Only an explicit Refresh action invokes a use case again. Nearby network and access-point selection continues through the M5 application service, device refresh runs M6 followed by M7, full scan uses M8, and report export passes one M8 snapshot to M9 for one or both formats.

Current Network collects M1 once per explicit refresh, supplies those interfaces to M2, and supplies both results to the association-aware M3 entry point. This avoids repeating interface and current Wi-Fi association collection within the same interactive refresh.

The root dispatch requires both stdin and stdout to be terminals. Non-TTY execution prints help without reading input. EOF exits normally, while `Ctrl+C` returns 130 through the interactive boundary without changing the operational exception policy of individual use cases.

M10.7 introduces `wlanscope.presentation` as a narrow terminal-rendering boundary. `theme.py` owns the single semantic Rich theme and textual status mapping, `formatting.py` owns pure unit and value formatting plus the compact/standard/wide breakpoints, `components.py` owns reusable literal-safe tables, headers, menus, notices, and empty states, and `rendering.py` owns the Current Network overview and adaptive Full Scan summaries. The presentation package receives immutable domain models and imports no collectors, use cases, PowerShell, ctypes, or Windows APIs.

M10.8 adds `branding.py` within the same presentation boundary. It selects compact, standard, or wide root identity renderables from the existing breakpoints and composes trusted product metadata, the package version supplied by the interactive boundary, and a static privacy note. The interactive session controls placement and navigation; branding performs no collection, use-case execution, persistence, or platform access.

String cells created by presentation tables are converted to literal `Text` values before Rich renders them. SSIDs, adapter and profile names, hostnames, vendors, issue messages, and paths therefore cannot inject Rich markup. Trusted labels and semantic status styles remain explicit UI content.

InteractiveSession retains navigation, selection, refresh, cancellation, and use-case invocation. Returning from a Current Network detail redraws the existing overview without collecting another snapshot. `Console.clear()` is gated by interactive execution, terminal detection, and the injectable clear flag. Subcommands retain argparse dispatch and exit-code handling; non-TTY root and subcommand paths remain deterministic and do not add prompts or clearing.

Presentation layouts use three stable modes: compact below 100 columns, standard from 100 through 139, and wide from 140 columns. Compact views retain IP, MAC, BSSID, interface identity, and other primary values while omitting secondary metadata. Wide views expose additional hardware, radio, neighbor, role-evidence, and full-scan summary fields without changing the underlying snapshots or reports.

M10.6 extends existing boundaries rather than adding a new pipeline. A current WLAN collection reuses one Native WLAN session to query optional interface capability, infrastructure and ad hoc authentication/cipher capability lists, channel, RSSI, operation mode, management-frame-protection capability, radio state, and cumulative WLAN statistics. General MAC counters and bounded high-value per-PHY counters follow the documented variable-length `WLAN_STATISTICS` layout. Every API-owned query buffer is length-checked, copied, and released with `WlanFreeMemory`; unsupported opcodes have explicit capability state and do not fail the base connection snapshot.

Interface statistics and hardware metadata are collected for all adapters in the existing constant PowerShell invocation. `Get-NetAdapterStatistics` is joined to `Get-NetAdapter -IncludeHidden` by interface identity before JSON crosses the platform boundary. Missing counter properties remain unavailable and are never converted to zero. Current-network enrichment likewise obtains `Get-NetConnectionProfile` for all profiles and optional CIM DHCP lease timestamps in one constant, non-interactive script. These sources enrich primary IP Helper data and cannot erase it when unavailable.

The BSS boundary now validates every fixed `WLAN_BSS_ENTRY` field, supported-rate length, entry-relative information-element offset, and information-element size before copying bytes. The pure information-element parser accepts at most the documented BSS payload bound, checks every element header and declared length, and treats truncation as data rather than an exception. It exports interpreted summaries for rates, country, RSN, documented HT/VHT/extended-capability presence, extension identifiers, and vendor OUIs; unknown elements remain counts and identifiers rather than speculative fingerprints. Raw native pointers and full raw IE blobs never enter domain snapshots or reports.

Deep data flows through the same immutable M1 through M9 results. Full scan does not repeat the batch adapter or profile sources, nearby detail continues to use the single M4 snapshot, and device details add only evidence already produced by M6/M7, including Windows neighbor router indication. Provenance remains source-specific: Native WLAN and beacon/probe observations for radio data, IP Helper and structured PowerShell/CIM for network data, neighbor cache and ICMP for observation, DNS PTR for names, and the local IEEE MA-L registry for vendors.

The prerelease realtime connection-quality and per-link MLO structures are not bound because their official contract does not establish a stable minimum supported Windows release. `Get-NetAdapterHardwareInfo` is not added because its PCI-focused and custom-property output lacks a small cross-adapter property contract beyond the hardware metadata already returned by `Get-NetAdapter`. Vendor-specific advanced adapter properties are deliberately excluded from the primary domain.

PowerShell runs without a user profile, without a shell, without automatic execution-policy changes, and with a fixed timeout. Formatted tables and localized text parsing are not used.

Future Windows APIs and structured operating-system sources will follow the same priority. Localized textual commands remain last-resort fallbacks with dedicated parsers and sanitized fixtures.

Collection, parsing, normalization, orchestration, and presentation remain separate responsibilities.

## Reliability policy

Collectors will use explicit timeouts and return source-aware outcomes. Independent collector failures will produce partial results rather than erase valid observations. Unknown, unsupported, unavailable, and failed data will not be replaced by plausible values.

## Engineering policy

Production and test code use clear names, cohesive functions, explicit types, and narrow dependencies. Source code and tests contain no comments and avoid redundant docstrings. Documentation carries architectural explanations that do not belong inside code.

The roadmap is finite. Architecture may grow through M12 only when required by implemented behavior, and v1.0.0 is the stopping point for the approved scope.
