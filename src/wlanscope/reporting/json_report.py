from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address

from wlanscope.domain.discovery import NeighborState
from wlanscope.domain.enrichment import EnrichedHost
from wlanscope.domain.full_scan import FullNetworkSnapshot
from wlanscope.domain.interfaces import NetworkInterface
from wlanscope.domain.nearby_wifi import WifiAccessPoint, WifiNetwork
from wlanscope.domain.network import (
    InterfaceNetworkContext,
    IpAddressAssignment,
    NativeNetworkValue,
    Route,
)
from wlanscope.domain.wifi import (
    NativeWifiValue,
    WifiConnection,
    WifiInterfaceSnapshot,
    WifiSsid,
)
from wlanscope.version import __version__

REPORT_SCHEMA_VERSION = "1.0"
type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LOCAL_PATH = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\s\"']+")


def serialize_json_report(snapshot: FullNetworkSnapshot) -> str:
    return (
        json.dumps(
            build_json_report(snapshot),
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )


def build_json_report(snapshot: FullNetworkSnapshot) -> dict[str, JsonValue]:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "WLANScope", "version": __version__},
        "scan": {
            "started_at": _timestamp(snapshot.started_at),
            "completed_at": _timestamp(snapshot.completed_at),
            "duration_seconds": snapshot.duration_seconds,
            "status": snapshot.status.name.lower(),
        },
        "sections": {
            result.section.name.lower(): {
                "status": result.status.name.lower(),
                "issues": [_issue(issue.message) for issue in result.issues],
            }
            for result in snapshot.sections
        },
        "data": {
            "interfaces": _interfaces(snapshot),
            "current_wifi": _current_wifi(snapshot),
            "current_network": _current_network(snapshot),
            "nearby_wifi": _nearby_wifi(snapshot),
            "devices": _devices(snapshot),
        },
        "issues": [
            {
                "section": issue.section.name.lower(),
                "message": _issue(issue.message),
            }
            for issue in snapshot.issues
        ],
    }


def _interfaces(snapshot: FullNetworkSnapshot) -> JsonValue:
    if snapshot.interfaces is None:
        return None
    return {
        "warnings": [_issue(message) for message in snapshot.interfaces.warnings],
        "items": [_interface(item) for item in snapshot.interfaces.interfaces],
    }


def _interface(item: NetworkInterface) -> dict[str, JsonValue]:
    return {
        "interface_index": item.interface_index,
        "stable_id": _text(item.stable_id),
        "alias": _text(item.alias),
        "friendly_name": _text(item.friendly_name),
        "description": _optional_text(item.description),
        "windows_interface_type": item.windows_interface_type,
        "kind": _enum(item.kind),
        "operational_state": _enum(item.operational_state),
        "administrative_state": _enum(item.administrative_state),
        "media_state": _enum(item.media_state),
        "mac_address": str(item.mac_address) if item.mac_address else None,
        "mtu": item.mtu,
        "receive_link_speed_bps": item.receive_link_speed_bps,
        "transmit_link_speed_bps": item.transmit_link_speed_bps,
        "is_hardware": item.is_hardware,
        "is_virtual": item.is_virtual,
        "is_hidden": item.is_hidden,
        "manufacturer": _optional_text(item.manufacturer),
        "driver_description": _optional_text(item.driver_description),
        "driver_version": _optional_text(item.driver_version),
    }


def _current_wifi(snapshot: FullNetworkSnapshot) -> JsonValue:
    if snapshot.current_wifi is None:
        return None
    return {
        "interfaces": [_wifi_interface(item) for item in snapshot.current_wifi.interfaces],
        "issues": [
            {
                "code": issue.code.name.lower(),
                "message": _issue(issue.message),
                "interface_id": issue.interface_id,
            }
            for issue in snapshot.current_wifi.issues
        ],
    }


def _wifi_interface(item: WifiInterfaceSnapshot) -> dict[str, JsonValue]:
    return {
        "interface_id": item.interface_id,
        "description": _text(item.description),
        "state": _native(item.state),
        "network_interface_index": (
            item.network_interface.interface_index if item.network_interface else None
        ),
        "connection": _wifi_connection(item.connection) if item.connection else None,
    }


def _wifi_connection(item: WifiConnection) -> dict[str, JsonValue]:
    return {
        "state": _native(item.state),
        "mode": _native(item.mode),
        "profile_name": _optional_text(item.profile_name),
        "ssid": _ssid(item.ssid),
        "bssid": str(item.bssid),
        "phy_type": _native(item.phy_type),
        "signal_quality_percent": item.signal_quality,
        "receive_rate_kbps": item.receive_rate_kbps,
        "transmit_rate_kbps": item.transmit_rate_kbps,
        "security": {
            "enabled": item.security.enabled,
            "authentication": _native(item.security.authentication),
            "cipher": _native(item.security.cipher),
        },
    }


def _current_network(snapshot: FullNetworkSnapshot) -> JsonValue:
    if snapshot.current_network is None:
        return None
    return {
        "interfaces": [_network_context(item) for item in snapshot.current_network.interfaces],
        "routes": [_route(item) for item in snapshot.current_network.routes],
        "issues": [
            {"source": issue.source.name.lower(), "message": _issue(issue.message)}
            for issue in snapshot.current_network.issues
        ],
    }


def _network_context(item: InterfaceNetworkContext) -> dict[str, JsonValue]:
    return {
        "interface_index": item.interface_index,
        "addresses": [_assignment(address) for address in item.addresses],
        "dns": (
            {
                "servers": [str(server) for server in item.dns.servers],
                "suffix": _optional_text(item.dns.suffix),
            }
            if item.dns
            else None
        ),
        "dhcp": {
            "ipv4_state": _enum(item.dhcp.ipv4_state),
            "ipv6_state": _enum(item.dhcp.ipv6_state),
            "server": str(item.dhcp.server) if item.dhcp.server else None,
        },
        "network_interface_id": (
            _text(item.network_interface.stable_id) if item.network_interface else None
        ),
        "wifi_interface_id": item.wifi_interface.interface_id if item.wifi_interface else None,
    }


def _assignment(item: IpAddressAssignment) -> dict[str, JsonValue]:
    return {
        "address": str(item.address),
        "address_family": _address_family(item.address),
        "prefix_length": item.prefix_length,
        "network": str(item.network),
        "interface_index": item.interface_index,
        "prefix_origin": _native(item.prefix_origin),
        "address_origin": _native(item.address_origin),
        "dad_state": _native(item.dad_state),
        "preferred_lifetime_seconds": item.preferred_lifetime_seconds,
        "valid_lifetime_seconds": item.valid_lifetime_seconds,
        "skip_as_source": item.skip_as_source,
        "scope_id": item.scope_id,
    }


def _route(item: Route) -> dict[str, JsonValue]:
    return {
        "destination": str(item.destination),
        "address_family": f"ipv{item.destination.version}",
        "next_hop": str(item.next_hop),
        "next_hop_scope_id": item.next_hop_scope_id,
        "interface_index": item.interface_index,
        "route_metric": item.route_metric,
        "interface_metric": item.interface_metric,
        "effective_metric": item.effective_metric,
        "protocol": _native(item.protocol),
        "origin": _native(item.origin),
        "is_default": item.is_default,
    }


def _nearby_wifi(snapshot: FullNetworkSnapshot) -> JsonValue:
    if snapshot.nearby_wifi is None:
        return None
    return {
        "interfaces": [
            {"interface_id": item.interface_id, "description": _text(item.description)}
            for item in snapshot.nearby_wifi.interfaces
        ],
        "networks": [_wifi_network(item) for item in snapshot.nearby_wifi.networks],
        "issues": [
            {
                "code": issue.code.name.lower(),
                "message": _issue(issue.message),
                "interface_id": issue.interface_id,
            }
            for issue in snapshot.nearby_wifi.issues
        ],
    }


def _wifi_network(item: WifiNetwork) -> dict[str, JsonValue]:
    return {
        "interface_id": item.interface_id,
        "interface_description": _text(item.interface_description),
        "ssid": _ssid(item.ssid),
        "connectable": item.connectable,
        "profile_name": _optional_text(item.profile_name),
        "signal_quality_percent": item.signal_quality,
        "security_enabled": item.security_enabled,
        "authentication": _native(item.authentication),
        "cipher": _native(item.cipher),
        "reported_bss_count": item.reported_bss_count,
        "observed_bss_count": len(item.access_points),
        "access_points": [_access_point(access_point) for access_point in item.access_points],
    }


def _access_point(item: WifiAccessPoint) -> dict[str, JsonValue]:
    return {
        "interface_id": item.interface_id,
        "ssid": _ssid(item.ssid),
        "bssid": str(item.bssid),
        "phy_type": _native(item.phy_type),
        "signal_quality_percent": item.signal_quality,
        "rssi_dbm": item.rssi_dbm,
        "center_frequency_khz": item.center_frequency_khz,
        "band": _enum(item.band),
        "channel": item.channel,
        "beacon_period_tu": item.beacon_period_tu,
        "capability_information": item.capability_information,
        "timestamp_us": item.timestamp_us,
        "host_timestamp": item.host_timestamp,
    }


def _devices(snapshot: FullNetworkSnapshot) -> JsonValue:
    if snapshot.devices is None:
        return None
    inventory = snapshot.devices
    plan = inventory.discovered.plan
    return {
        "discovery": {
            "interface_index": plan.interface_index,
            "subnet": str(plan.subnet),
            "local_addresses": [str(item) for item in plan.local_addresses],
            "gateways": [str(item) for item in plan.gateways],
            "usable_host_count": plan.usable_host_count,
            "targets_considered": len(plan.targets),
            "timeout_ms": plan.timeout_ms,
            "worker_count": plan.worker_count,
            "probes_executed": inventory.discovered.probes_executed,
            "canceled": inventory.discovered.canceled,
            "issues": [
                {"stage": _text(issue.stage), "message": _issue(issue.message)}
                for issue in inventory.discovered.issues
            ],
        },
        "hosts": [_host(item) for item in inventory.hosts],
        "enrichment_issues": [
            {"source": _text(issue.source), "message": _issue(issue.message)}
            for issue in inventory.issues
        ],
    }


def _host(item: EnrichedHost) -> dict[str, JsonValue]:
    discovered = item.discovered
    sources: list[JsonValue] = []
    sources.extend(sorted(source.name.lower() for source in discovered.sources))
    return {
        "interface_index": discovered.interface_index,
        "address": str(discovered.address),
        "address_family": _address_family(discovered.address),
        "mac_address": str(discovered.mac_address) if discovered.mac_address else None,
        "reachability": _enum(discovered.reachability),
        "discovery_sources": sources,
        "neighbor_state": _neighbor_state(discovered.neighbor_state),
        "hostname": {
            "state": _enum(item.hostname.state),
            "value": _optional_text(item.hostname.hostname),
            "source": _enum(item.hostname.source) if item.hostname.source else None,
        },
        "vendor": {
            "state": _enum(item.vendor.state),
            "value": _optional_text(item.vendor.vendor),
            "source": _enum(item.vendor.source) if item.vendor.source else None,
        },
    }


def _ssid(item: WifiSsid) -> dict[str, JsonValue]:
    return {
        "display": _text(item.display_text) if not item.is_empty else "<Hidden>",
        "raw_hex": item.raw.hex(),
        "hidden": item.is_empty,
    }


def _native(item: NativeWifiValue | NativeNetworkValue) -> str:
    value = _slug(item.display_name)
    return f"unknown_{item.native_value}" if value == "unknown" else value


def _neighbor_state(item: NeighborState | None) -> JsonValue:
    if item is None:
        return None
    value = _slug(item.display_name)
    return f"unknown_{item.native_value}" if value == "unknown" else value


def _enum(item: Enum) -> str:
    return item.name.lower()


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _address_family(value: IPv4Address | IPv6Address) -> str:
    return f"ipv{value.version}"


def _slug(value: str) -> str:
    known = value.split(" (", 1)[0]
    normalized = re.sub(r"[^a-z0-9]+", "_", known.casefold()).strip("_")
    return normalized or "unknown"


def _optional_text(value: str | None) -> str | None:
    return _text(value) if value is not None else None


def _text(value: str) -> str:
    return _CONTROL.sub("", _ANSI_ESCAPE.sub("", value))


def _issue(value: str) -> str:
    return _LOCAL_PATH.sub("<local-path>", _text(value))
