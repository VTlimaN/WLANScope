# Architecture

## Current implementation

Milestone 0 contains only the installable package, project metadata, minimal CLI, version resolution, tests, build configuration, and continuous integration. No networking implementation exists yet.

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

Directories will be added only when a milestone has real code to place in them. M0 deliberately avoids empty architectural placeholders and speculative interfaces.

## Data source policy

Windows APIs and structured operating-system sources take priority. Structured PowerShell objects may be serialized for isolated adapters when native APIs do not expose the required information economically. Localized textual commands are last-resort fallbacks with dedicated parsers and sanitized fixtures.

Collection, parsing, normalization, orchestration, and presentation remain separate responsibilities.

## Reliability policy

Collectors will use explicit timeouts and return source-aware outcomes. Independent collector failures will produce partial results rather than erase valid observations. Unknown, unsupported, unavailable, and failed data will not be replaced by plausible values.

## Engineering policy

Production and test code use clear names, cohesive functions, explicit types, and narrow dependencies. Source code and tests contain no comments and avoid redundant docstrings. Documentation carries architectural explanations that do not belong inside code.

The roadmap is finite. Architecture may grow through M12 only when required by implemented behavior, and v1.0.0 is the stopping point for the approved scope.

