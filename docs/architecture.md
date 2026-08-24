# Architecture

## Implemented architecture

The project foundation provides packaging, metadata, CLI entry points, tests, build configuration, and continuous integration. Milestone 1 adds the first vertical feature through four concrete layers:

- domain models normalize interface identity, type, state, MAC address, link properties, and optional driver metadata;
- the application use case coordinates primary collection, optional enrichment, deterministic merge, warnings, and ordering;
- Windows platform adapters isolate IP Helper ctypes structures and PowerShell JSON processing;
- the CLI renders the normalized inventory without accessing native sources directly.

No WLAN connection, Wi-Fi discovery, host discovery, or reporting components exist yet.

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

PowerShell runs without a user profile, without a shell, without automatic execution-policy changes, and with a fixed timeout. Formatted tables and localized text parsing are not used.

Future Windows APIs and structured operating-system sources will follow the same priority. Localized textual commands remain last-resort fallbacks with dedicated parsers and sanitized fixtures.

Collection, parsing, normalization, orchestration, and presentation remain separate responsibilities.

## Reliability policy

Collectors will use explicit timeouts and return source-aware outcomes. Independent collector failures will produce partial results rather than erase valid observations. Unknown, unsupported, unavailable, and failed data will not be replaced by plausible values.

## Engineering policy

Production and test code use clear names, cohesive functions, explicit types, and narrow dependencies. Source code and tests contain no comments and avoid redundant docstrings. Documentation carries architectural explanations that do not belong inside code.

The roadmap is finite. Architecture may grow through M12 only when required by implemented behavior, and v1.0.0 is the stopping point for the approved scope.
