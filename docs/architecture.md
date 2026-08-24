# Architecture

## Implemented architecture

The project foundation provides packaging, metadata, CLI entry points, tests, build configuration, and continuous integration. Milestones 1 through 3 provide vertical features through four concrete layers:

- domain models normalize network-interface, byte-safe current Wi-Fi, IP assignment, DNS, DHCP, and route data;
- application use cases coordinate interface inventory, optional enrichment, stable association, partial failures, and deterministic ordering;
- Windows platform adapters isolate IP Helper, Native WLAN API, PowerShell JSON, and optional CIM boundaries;
- the CLI renders normalized interface, current Wi-Fi, and current network views without accessing native sources directly.

Nearby Wi-Fi discovery, host discovery, and reporting components do not exist yet.

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

PowerShell runs without a user profile, without a shell, without automatic execution-policy changes, and with a fixed timeout. Formatted tables and localized text parsing are not used.

Future Windows APIs and structured operating-system sources will follow the same priority. Localized textual commands remain last-resort fallbacks with dedicated parsers and sanitized fixtures.

Collection, parsing, normalization, orchestration, and presentation remain separate responsibilities.

## Reliability policy

Collectors will use explicit timeouts and return source-aware outcomes. Independent collector failures will produce partial results rather than erase valid observations. Unknown, unsupported, unavailable, and failed data will not be replaced by plausible values.

## Engineering policy

Production and test code use clear names, cohesive functions, explicit types, and narrow dependencies. Source code and tests contain no comments and avoid redundant docstrings. Documentation carries architectural explanations that do not belong inside code.

The roadmap is finite. Architecture may grow through M12 only when required by implemented behavior, and v1.0.0 is the stopping point for the approved scope.
