# WLANScope

Windows Wireless & Network Reconnaissance

WLANScope is a Windows-focused cybersecurity and network visibility project created by sasser. Its goal is to provide reliable, structured observation of wireless and local network context for authorized Blue Team, administration, inventory, and troubleshooting work.

## Project status

WLANScope is in Milestone 0, Project Foundation. The current implementation provides an installable Python package, version metadata, and a minimal command-line entry point. Network collection, Wi-Fi analysis, device discovery, and reporting are planned work and are not implemented yet.

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
.\.venv\Scripts\python.exe -m wlanscope --help
.\.venv\Scripts\python.exe -m wlanscope --version
```

Only `--help` and `--version` are available in M0.

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

- M0: project foundation
- M1-M3: Windows interfaces and current network context
- M4-M5: nearby Wi-Fi discovery and details
- M6-M7: bounded local device discovery and enrichment
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

