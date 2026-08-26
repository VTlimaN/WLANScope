# WLANScope

Windows Wireless & Network Reconnaissance

WLANScope is a Windows-focused cybersecurity and network visibility project created by sasser. Its goal is to provide reliable, structured observation of wireless and local network context for authorized Blue Team, administration, inventory, and troubleshooting work.

## Project status

WLANScope has completed its project foundation and is implementing Windows network visibility incrementally. The current implementation inventories Windows network interfaces and cumulative adapter counters, deeply inspects the current wireless connection and network profile, analyzes IPv4/IPv6, routing, DNS, and DHCP context, safely decodes high-value beacon information from nearby Wi-Fi observations, performs bounded discovery and enrichment of hosts observable on the routed local subnet, composes those results into a full network scan, and exports explicit local JSON and Markdown reports.

## Requirements

- Windows 10 or Windows 11
- Python 3.12 or newer

Python 3.12 is the minimum because the planned codebase does not require Python 3.13-only features. This preserves useful installation compatibility while retaining modern typing and standard-library capabilities. Development currently uses Python 3.13.

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## Current usage

```powershell
.\.venv\Scripts\wlanscope.exe
.\.venv\Scripts\wlanscope.exe --help
.\.venv\Scripts\wlanscope.exe --version
.\.venv\Scripts\wlanscope.exe adapters
.\.venv\Scripts\wlanscope.exe wifi
.\.venv\Scripts\wlanscope.exe wifi scan
.\.venv\Scripts\wlanscope.exe wifi scan --details 1
.\.venv\Scripts\wlanscope.exe wifi scan --details 1 --access-point 1
.\.venv\Scripts\wlanscope.exe current
.\.venv\Scripts\wlanscope.exe devices
.\.venv\Scripts\wlanscope.exe devices --allow-large-range
.\.venv\Scripts\wlanscope.exe scan
.\.venv\Scripts\wlanscope.exe scan --allow-large-range
.\.venv\Scripts\wlanscope.exe scan --json C:\Reports\scan.json
.\.venv\Scripts\wlanscope.exe scan --markdown C:\Reports\scan.md
.\.venv\Scripts\wlanscope.exe scan --json C:\Reports\scan.json --markdown C:\Reports\scan.md
.\.venv\Scripts\wlanscope.exe scan --json C:\Reports\scan.json --force
.\.venv\Scripts\python.exe -m wlanscope --help
.\.venv\Scripts\python.exe -m wlanscope --version
```

Available behavior:

- `wlanscope` opens the interactive terminal experience when both input and output are attached to a terminal. The main menu provides current network, interface, nearby Wi-Fi, observed-device, full-scan, report, and About workflows.
- `--help` displays the supported command surface;
- `--version` displays package metadata versioning;
- `adapters` lists interfaces reported by Windows, with structured IP Helper data and optional PowerShell enrichment.
- `wifi` inspects current wireless connections reported by the Native WLAN API.
- `wifi scan` requests a bounded Native WLAN scan and summarizes nearby networks and observed access points.
- `wifi scan --details NETWORK` selects a one-based network index from that scan and shows aggregate and BSS details.
- `wifi scan --details NETWORK --access-point AP` shows the selected access point from the same snapshot without rescanning.
- `current` presents the current IP assignments, default routes, metrics, DNS, and DHCP context.
- `devices` observes the local IPv4 subnet selected from routing context by combining the host, gateway, Windows neighbor cache, and bounded native ICMP Echo probes. It then attempts PTR resolution for observed hosts and local OUI lookup for usable MAC addresses.
- `devices --allow-large-range` explicitly authorizes local discovery for ranges containing 257 through 4,096 usable addresses. Larger ranges are refused.
- `scan` runs one summarized, sequential snapshot across adapters, current Wi-Fi, current network, nearby Wi-Fi, local devices, and device enrichment.
- `scan --allow-large-range` forwards the same explicit local-range authorization used by `devices`.
- `scan --json PATH` writes a versioned, machine-readable JSON report from the collected snapshot.
- `scan --markdown PATH` writes a human-readable technical Markdown report from the same snapshot.
- JSON and Markdown may be requested together without running a second scan. Existing files are refused unless `--force` is supplied, and the parent directory must already exist.

Every command provides focused help through `wlanscope COMMAND --help`; use `wlanscope wifi scan --help` for the nested Wi-Fi scan options. Normal results are written to standard output, while usage errors, operational failures, cancellation notices, and partial-result warnings use standard error. Redirected output is deterministic and does not prompt, animate progress, or require ANSI color support.

Interactive screens keep one snapshot while the user opens details or returns within that screen. Refresh is always explicit and performs a new collection only for the selected workflow. When stdin or stdout is redirected, the root command prints help and exits without reading input; scripts and automation should continue to use explicit subcommands.

CLI exit codes are consistent across commands:

- `0`: success;
- `1`: operational failure, including a requested report that could not be written;
- `2`: invalid usage, invalid selection, or missing explicit range authorization;
- `3`: partial result with useful data retained;
- `130`: canceled by the user.

Full scan status is `SUCCESS` when every section completes normally, `PARTIAL` when useful results coexist with a limited, failed, or skipped section, and `FAILED` when no principal section produces useful information. Individual commands remain available for detailed inspection; without explicit export flags, `scan` presents only a compact operational overview and creates no files.

Reports can contain IP and MAC addresses, SSIDs, BSSIDs, gateways, DNS topology, hostnames, vendor names, and wireless security metadata. They contain no Wi-Fi passwords, PSKs, credentials, profile XML, or other secrets. Reports are written only to paths explicitly supplied by the user and are never uploaded automatically. Protect exported files according to the sensitivity of the observed environment.

The Wi-Fi commands do not retrieve profile XML, collect credentials, connect to networks, or modify wireless state.

Deep inspection remains local and evidence-based. Current Wi-Fi details can include adapter capabilities, channel, actual RSSI, radio state, operation mode, and cumulative WLAN statistics when Windows and the driver expose them. Interface details can include cumulative traffic/error counters and optional hardware metadata. Nearby access-point details can include beacon timing, supported rates, documented capability flags, and a bounded interpretation of selected 802.11 information elements, including RSN security metadata.

Nearby Wi-Fi is observational. An SSID or BSSID observed without association does not reveal that network's IP configuration, gateway, DNS, DHCP, public IP, ISP, or last-mile technology. WLANScope performs no external public-IP or ISP lookup and never fills those fields through guesses.

Device discovery reports observed hosts, not an authoritative list of clients connected to a router. Firewalls, client isolation, sleeping devices, and stale or incomplete neighbor state can limit visibility. IPv6 neighbor entries can be observed, but WLANScope does not sweep IPv6 address space.

PTR names and vendor names are optional enrichment and may be unavailable. Vendor lookup performs no online request during discovery. WLANScope can read an IEEE public MA-L CSV export from `%LOCALAPPDATA%\WLANScope\data\oui.csv` when the file contains the `Registry`, `Assignment`, and `Organization Name` columns. No OUI registry is bundled because WLANScope does not assert redistribution rights for the upstream dataset. This milestone supports 24-bit MA-L assignments only.

## Architecture direction

The target architecture separates terminal presentation, application orchestration, domain models, Windows platform adapters, defensive discovery, and reporting. Only components required by the current milestone are created. See [Architecture](docs/architecture.md).

## Security boundaries

WLANScope is intended for systems and networks owned by the user or covered by explicit authorization. It will not include credential extraction, Wi-Fi key extraction, deauthentication, man-in-the-middle behavior, exploitation, or other offensive automation. See [Security](docs/security.md).

## Testing and quality

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy src tests
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m build
```

The standard test suite is offline and does not require Wi-Fi hardware, network access, Administrator privileges, or a particular machine configuration.

## Roadmap

- M0: project foundation, completed
- M1: Windows network interface inventory, implemented
- M2: current Wi-Fi analysis, implemented
- M3: IP, DNS, DHCP, and routing context, implemented
- M4: nearby Wi-Fi discovery, implemented
- M5: nearby Wi-Fi details, implemented
- M6: bounded local subnet discovery, implemented
- M7: device inventory enrichment, implemented
- M8: full scan orchestration, implemented
- M9: JSON and Markdown reporting, implemented
- M10: CLI polish and reliability, implemented
- M10.5: interactive terminal experience, implemented
- M10.6: data completeness and deep inspection, in development
- M10.7: CLI visual design and final UX
- M11: documentation and portfolio preparation
- M12: v1.0.0 release

The roadmap is finite and ends at v1.0.0. See [Limitations](docs/limitations.md) for the boundaries of planned behavior.

## License

Licensed under the Apache License 2.0.

## Author

sasser
