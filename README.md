# WLANScope

Windows Wireless & Network Reconnaissance

WLANScope is a Windows-focused cybersecurity and network visibility project created by sasser. Its goal is to provide reliable, structured observation of wireless and local network context for authorized Blue Team, administration, inventory, and troubleshooting work.

## Project status

WLANScope has completed its project foundation and is implementing Windows network visibility incrementally. The current implementation inventories Windows network interfaces, inspects the current wireless connection, analyzes current IPv4/IPv6, routing, DNS, and DHCP context, discovers and details nearby Wi-Fi networks, and performs bounded discovery and enrichment of hosts observable on the routed local subnet. Full scan orchestration and reporting remain planned work and are not implemented yet.

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
.\.venv\Scripts\python.exe -m wlanscope --help
.\.venv\Scripts\python.exe -m wlanscope --version
```

Available behavior:

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

The Wi-Fi commands do not retrieve profile XML, collect credentials, connect to networks, or modify wireless state.

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
- M8: full scan orchestration
- M9: TXT, JSON, and CSV reporting
- M10: CLI polish and reliability
- M11: documentation and portfolio preparation
- M12: v1.0.0 release

The roadmap is finite and ends at v1.0.0. See [Limitations](docs/limitations.md) for the boundaries of planned behavior.

## License

Licensed under the Apache License 2.0.

## Author

sasser
