# WLANScope

Windows Wireless & Network Reconnaissance

WLANScope is a Windows wireless and local-network inspection tool for defensive visibility, Blue Team diagnostics, and technical troubleshooting. It combines an adaptive Rich terminal interface with deterministic non-interactive subcommands while keeping collection read-only except for bounded ICMP Echo probes on the selected routed local subnet.

Created by sasser.

## Overview

WLANScope inspects network interfaces, the current Wi-Fi association, IPv4 and IPv6 configuration, routes, DNS and DHCP context, nearby 802.11 observations, and hosts observable from the local endpoint. A full scan composes those sources into one point-in-time snapshot for interactive review or local JSON and Markdown reporting.

The project is Windows-focused and evidence-based. Missing, unsupported, privacy-restricted, malformed, or driver-dependent data remains explicit instead of being guessed. WLANScope does not extract credentials, mutate network configuration, scan ports, or contact public-IP, ISP, or online vendor services.

## Technical Highlights

- Native Windows WLAN and IP Helper integration through typed `ctypes` boundaries with explicit handle and buffer ownership.
- Structured PowerShell and CIM enrichment without localized table parsing.
- Bounds-safe parsing of untrusted 802.11 Information Elements, including RSN summaries and passive WPS metadata.
- Local IEEE MA-L/OUI enrichment for observed hosts and globally administered AP BSSIDs, with no online lookup.
- Immutable, platform-independent domain models and source-aware partial outcomes.
- Point-in-time snapshots reused across detail views, enrichment, and report formats.
- Deterministic JSON and Markdown reporting with atomic writes and opt-in identifier pseudonymization.
- Adaptive Rich presentation plus automation-friendly command mode.
- Offline automated tests for native boundaries, domain policies, CLI behavior, reporting, and presentation.

## Features

### Current Network

- Current Wi-Fi association, profile, signal, channel, PHY, security, capabilities, and cumulative statistics when exposed by Windows and the driver.
- IPv4 and IPv6 addresses, prefixes, origins, lifetimes, and address state.
- Routes, default gateways, interface and route metrics, DNS, DHCP, and Windows connectivity profile data.

### Network Interfaces

- Physical and virtual interface inventory, state, link speed, MAC address, and MTU.
- Manufacturer, driver, connector, PnP, hidden, and virtual metadata when available.
- Cumulative traffic, discard, and error counters when supported.

### Nearby Wi-Fi

- Visible and hidden SSIDs, aggregate networks, and individual BSS/access-point observations.
- Signal, RSSI, BSSID, channel, frequency, band, PHY, security, beacon metadata, and supported rates.
- Bounded summaries of RSN, country, HT, VHT, HE, EHT, vendor, and unknown Information Elements.
- AP-level vendor attribution through the optional local IEEE MA-L registry.
- Passive WPS metadata detection from observed WPS Vendor Specific Information Elements.

AP vendor lookup applies only to globally administered BSSIDs. Locally administered BSSIDs are not attributed to a global organization, and registry absence or an unknown assignment remains explicit. Vendor attribution belongs to the AP/BSSID observation, not to the SSID as a whole.

WPS parsing is passive and read-only. It uses management-frame metadata already supplied by the Windows WLAN stack and performs no additional association. When advertised, details can include state, setup lock, selected registrar, configuration methods, manufacturer, model, and device name. WLANScope does not retrieve or guess a WPS PIN, brute-force WPS, exploit an AP, or treat WPS presence as proof of vulnerability.

Nearby observation does not reveal the private IP configuration of an unassociated network. It cannot provide that network's private IP, subnet, gateway, DNS, DHCP, public IP, ISP, or last-mile technology without association or an external source.

### Observed Devices

- Bounded discovery on the routed local IPv4 subnet using self, gateway, Windows neighbor-cache, and ICMP evidence.
- Already-observed IPv6 neighbors from Windows; IPv6 address space is not swept.
- Optional PTR hostname resolution and optional local IEEE MA-L/OUI vendor lookup.
- Explicit self, gateway, router indication, neighbor state, reachability, and provenance evidence.

Observed Devices is not an authoritative list of all clients connected to a router or access point. Visibility depends on topology, segmentation, client isolation, host sleep, firewall and ICMP policy, and neighbor-cache state.

### Full Scan and Reporting

- One sequential snapshot across interfaces, current Wi-Fi, current network, nearby Wi-Fi, observed devices, and enrichment.
- Section-level Success, Partial, Failed, or Skipped outcomes without erasing independent results.
- Local JSON and Markdown exports from the same immutable `FullNetworkSnapshot`.
- Optional per-export pseudonymization of direct identifiers.

## Interactive Mode

Run the root command in an interactive terminal:

```powershell
wlanscope
```

The landing screen provides:

1. Current Network
2. Network Interfaces
3. Nearby Wi-Fi Networks
4. Observed Devices
5. Full Network Scan
6. Reports
7. About
0. Exit

`R` refreshes where offered, `B` or `0` returns from a screen, and `Q` or `0` exits at the root. Detail views reuse the current point-in-time snapshot; only an explicit refresh runs collection again. WLANScope performs no background monitoring.

The Reports workflow asks for format, destination, overwrite confirmation when needed, and whether identifiers should be anonymized. Anonymization is never enabled silently.

When either input or output is redirected, the root command prints help and exits without prompting, clearing the screen, or emitting ANSI styling. Automation should use explicit subcommands.

## Command-Line Usage

| Command | Purpose |
| --- | --- |
| `wlanscope` | Open the interactive terminal when stdin and stdout are terminals. |
| `wlanscope adapters` | List Windows network interfaces and available metadata. |
| `wlanscope current` | Inspect current IP, routing, DNS, and DHCP context. |
| `wlanscope wifi` | Inspect the current Wi-Fi connection. |
| `wlanscope wifi scan` | Observe nearby Wi-Fi networks and access points. |
| `wlanscope devices` | Observe hosts on the routed local IPv4 subnet. |
| `wlanscope scan` | Build a summarized full network and Wi-Fi snapshot. |

Nearby Wi-Fi detail selectors are one-based and operate on one scan:

```powershell
wlanscope wifi scan --details 1
wlanscope wifi scan --details 1 --access-point 1
```

`--access-point` requires `--details`. Device discovery and the device section of a full scan accept `--allow-large-range` under the policy below. Report options on `scan` are `--json`, `--markdown`, `--anonymize`, and `--force`. Use `--help` on the root or any command for exact options, and `--version` for package metadata.

### Local Range Policy

`devices` and the device section of `scan` select only the local IPv4 subnet derived from current routing context. They do not accept an arbitrary CIDR.

- Up to 256 usable addresses: allowed by default.
- 257 through 4,096 usable addresses: require `--allow-large-range`.
- More than 4,096 usable addresses: refused.

The flag authorizes only the selected routed local subnet; it does not enable arbitrary scanning.

### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Operational failure, including report-write failure. |
| `2` | Invalid usage, selection, or missing range authorization. |
| `3` | Partial result with useful data retained. |
| `130` | User cancellation. |

## Installation

There is no public package-index or repository URL for this prerelease. From a local copy of the repository, use PowerShell:

```powershell
cd WLANScope
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

A non-editable local installation is also supported:

```powershell
python -m pip install .
```

For development tools, install the `dev` extra:

```powershell
python -m pip install -e ".[dev]"
```

## Requirements

- Windows 10 or Windows 11.
- Python 3.12 or newer.
- Runtime dependencies: Rich and dnspython, installed by `pip`.

Field availability can vary with the Windows build, network driver, WLAN service, privacy and location settings, and local topology. Administrator access is not a blanket requirement; permission-limited sources degrade explicitly while independent sources remain usable.

## Reports

Reports are generated only by `scan` or the interactive Reports workflow:

```powershell
wlanscope scan --json report.json
wlanscope scan --markdown report.md
wlanscope scan --json report.json --markdown report.md
wlanscope scan --json report.json --anonymize
wlanscope scan --markdown report.md --anonymize
wlanscope scan --json report.json --markdown report.md --anonymize
wlanscope scan --json report.json --force
```

JSON and Markdown requested together consume the same `FullNetworkSnapshot`; no second scan occurs. Existing files are refused unless `--force` is present, parent directories must already exist, and destination updates use a temporary file followed by an atomic rename or replacement. JSON uses `schema_version` `1.0`, independently of the package version.

A normal report preserves real local identifiers, including IP and MAC addresses, SSIDs, BSSIDs, hostnames, profiles, interface identifiers, routes, gateways, and DNS or DHCP context.

An anonymized report is explicit opt-in. `--anonymize` replaces supported direct identifiers with first-seen aliases such as `IPV4-001`, `BSSID-001`, `WIFI-001`, and `HOST-001`. JSON and Markdown generated together share one operation-local mapping. The mapping is not stored, the original snapshot is not mutated, and reports generated without the flag remain unchanged.

This is pseudonymization for safer sharing, not a guarantee of complete or irreversible anonymity. Vendors, PHY details, channels, frequencies, timing, counts, statistics, statuses, and preserved relationships can still support inference. Review every report before public distribution.

## Architecture

The repository separates CLI and interactive entry points, Rich presentation, application orchestration, immutable domain models, Windows platform adapters, and snapshot-only reporting. Native memory ownership and malformed wireless input are contained at platform boundaries; optional-source failure retains independently collected data.

See [Architecture](docs/architecture.md) for dependency direction, Windows data sources, AP vendor enrichment, passive WPS parsing, report pseudonymization, and snapshot reuse.

## Security Model

WLANScope is intended for authorized defensive inspection. It reads local configuration and observable wireless metadata, and sends bounded ICMP Echo probes only within the selected routed local subnet. It does not extract Wi-Fi keys or credentials, inject packets, deauthenticate clients, poison ARP, connect or disconnect Wi-Fi, scan ports or services, fingerprint operating systems, exploit hosts, or mutate adapters and network configuration.

See [Security](docs/security.md) for collection boundaries, WPS handling, report data handling, excluded functionality, and authorized-use guidance.

## Limitations

Results are point-in-time observations, not continuous monitoring. Windows privacy policy, driver support, optional PowerShell/CIM sources, topology, routing, firewall policy, and radio conditions can produce partial or stale data. No ICMP response does not prove that a host is offline. Multiple BSSIDs do not prove a mesh deployment. Local OUI attribution is optional and identifies an assignment holder, not an exact device model.

See [Limitations](docs/limitations.md) for complete interpretation boundaries, including WPS visibility and report pseudonymization.

## Development

The source tree follows narrow boundaries:

- `src/wlanscope/presentation`: Rich theme, formatting, branding, reusable components, and renderers.
- `src/wlanscope/application`: use-case orchestration and snapshot reuse.
- `src/wlanscope/domain`: immutable platform-independent models and policies.
- `src/wlanscope/platform`: Native Windows, structured PowerShell/CIM, DNS PTR, local OUI, and wireless IE parsing adapters.
- `src/wlanscope/reporting`: deterministic serialization, per-export pseudonymization, and atomic local writing.

Code and tests are fully typed, tests remain offline, and expected source unavailability is represented explicitly rather than hidden.

## Testing

```powershell
python -m ruff check .
python -m ruff format --check .
python -m mypy src tests
python -m pytest
python -m build
```

The test suite uses synthetic fixtures and does not require Wi-Fi hardware, network access, Administrator privileges, or a particular machine configuration.

## License

WLANScope is licensed under the [Apache License 2.0](LICENSE).
