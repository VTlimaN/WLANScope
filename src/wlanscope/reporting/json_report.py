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
    WifiAuthCipherCapabilities,
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
        "statistics": (
            {
                "received_bytes": item.statistics.received_bytes,
                "sent_bytes": item.statistics.sent_bytes,
                "received_unicast_packets": item.statistics.received_unicast_packets,
                "sent_unicast_packets": item.statistics.sent_unicast_packets,
                "received_multicast_packets": item.statistics.received_multicast_packets,
                "sent_multicast_packets": item.statistics.sent_multicast_packets,
                "received_broadcast_packets": item.statistics.received_broadcast_packets,
                "sent_broadcast_packets": item.statistics.sent_broadcast_packets,
                "received_discards": item.statistics.received_discards,
                "outbound_discards": item.statistics.outbound_discards,
                "received_errors": item.statistics.received_errors,
                "outbound_errors": item.statistics.outbound_errors,
                "provenance": item.statistics.provenance,
            }
            if item.statistics
            else None
        ),
        "hardware": (
            {
                "connector_present": item.hardware.connector_present,
                "driver_date": _optional_text(item.hardware.driver_date),
                "device_id": _optional_text(item.hardware.device_id),
            }
            if item.hardware
            else None
        ),
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
        "provenance": item.provenance,
        "channel_number": item.channel_number,
        "rssi_dbm": item.rssi_dbm,
        "operation_mode": item.operation_mode,
        "management_frame_protection_capable": item.management_frame_protection_capable,
        "capabilities": (
            {
                "interface_type": item.capabilities.interface_type,
                "dot11d_supported": item.capabilities.dot11d_supported,
                "maximum_desired_ssids": item.capabilities.maximum_desired_ssids,
                "maximum_desired_bssids": item.capabilities.maximum_desired_bssids,
                "supported_phy_types": [
                    _native(phy) for phy in item.capabilities.supported_phy_types
                ],
                "infrastructure_security": _auth_cipher_capabilities(
                    item.capabilities.infrastructure_security
                ),
                "adhoc_security": _auth_cipher_capabilities(item.capabilities.adhoc_security),
            }
            if item.capabilities
            else None
        ),
        "radio_states": [
            {
                "phy_index": state.phy_index,
                "software_state": _native(state.software_state),
                "hardware_state": _native(state.hardware_state),
            }
            for state in item.radio_states
        ],
        "statistics": (
            {
                "four_way_handshake_failures": item.statistics.four_way_handshake_failures,
                "tkip_countermeasures": item.statistics.tkip_countermeasures,
                "unicast_transmitted_frames": item.statistics.unicast_transmitted_frames,
                "unicast_received_frames": item.statistics.unicast_received_frames,
                "multicast_transmitted_frames": item.statistics.multicast_transmitted_frames,
                "multicast_received_frames": item.statistics.multicast_received_frames,
                "decrypt_successes": item.statistics.decrypt_successes,
                "decrypt_failures": item.statistics.decrypt_failures,
                "phy_counters": [
                    {
                        "phy_index": counter.phy_index,
                        "transmitted_frames": counter.transmitted_frames,
                        "received_frames": counter.received_frames,
                        "failed_transmissions": counter.failed_transmissions,
                        "retry_frames": counter.retry_frames,
                        "multiple_retry_frames": counter.multiple_retry_frames,
                        "fcs_errors": counter.fcs_errors,
                    }
                    for counter in item.statistics.phy_counters
                ],
            }
            if item.statistics
            else None
        ),
    }


def _wifi_connection(item: WifiConnection) -> dict[str, JsonValue]:
    return {
        "state": _native(item.state),
        "mode": _native(item.mode),
        "bss_type": _native(item.bss_type) if item.bss_type is not None else None,
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


def _auth_cipher_capabilities(item: WifiAuthCipherCapabilities) -> dict[str, JsonValue]:
    return {
        "state": item.state.name.lower(),
        "pairs": [
            {
                "authentication": _native(pair.authentication),
                "cipher": _native(pair.cipher),
            }
            for pair in item.pairs
        ],
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
                "registration_enabled": item.dns.registration_enabled,
                "suffix_registration_enabled": item.dns.suffix_registration_enabled,
                "provenance": item.dns.provenance,
            }
            if item.dns
            else None
        ),
        "dhcp": {
            "ipv4_state": _enum(item.dhcp.ipv4_state),
            "ipv6_state": _enum(item.dhcp.ipv6_state),
            "server": str(item.dhcp.server) if item.dhcp.server else None,
            "lease_obtained": (
                _timestamp(item.dhcp.lease_obtained) if item.dhcp.lease_obtained else None
            ),
            "lease_expires": (
                _timestamp(item.dhcp.lease_expires) if item.dhcp.lease_expires else None
            ),
            "lease_provenance": item.dhcp.lease_provenance,
        },
        "profile": (
            {
                "name": _optional_text(item.profile.name),
                "interface_alias": _optional_text(item.profile.interface_alias),
                "category": _optional_text(item.profile.category),
                "ipv4_connectivity": _enum(item.profile.ipv4_connectivity),
                "ipv6_connectivity": _enum(item.profile.ipv6_connectivity),
                "provenance": item.profile.provenance,
            }
            if item.profile
            else None
        ),
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
        "classifications": list(item.classifications),
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
        "is_on_link": item.is_on_link,
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
        "bss_type": item.bss_type,
        "not_connectable_reason": item.not_connectable_reason,
        "supported_phy_types": [_native(phy) for phy in item.supported_phy_types],
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
        "beacon_interval_microseconds": item.beacon_interval_microseconds,
        "capability_information": item.capability_information,
        "timestamp_us": item.timestamp_us,
        "host_timestamp": item.host_timestamp,
        "host_observed_at": _timestamp(item.host_observed_at) if item.host_observed_at else None,
        "phy_id": item.phy_id,
        "bss_type": item.bss_type,
        "in_reg_domain": item.in_reg_domain,
        "supported_rates_mbps": list(item.supported_rates_mbps),
        "basic_rates_mbps": list(item.basic_rates_mbps),
        "capability_flags": list(item.capability_flags),
        "information_elements": _information_elements(item),
        "provenance": item.provenance,
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
        "router_indication": discovered.is_router,
        "address_classifications": list(discovered.address_classifications),
        "mac_locally_administered": (
            discovered.mac_address.is_locally_administered if discovered.mac_address else None
        ),
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


def _information_elements(item: WifiAccessPoint) -> dict[str, JsonValue]:
    summary = item.information_elements
    rsn = summary.rsn
    return {
        "available": summary.available,
        "supported_rates_mbps": list(summary.supported_rates_mbps),
        "country_code": summary.country_code,
        "rsn": (
            {
                "version": rsn.version,
                "group_cipher": rsn.group_cipher,
                "pairwise_ciphers": list(rsn.pairwise_ciphers),
                "akm_suites": list(rsn.akm_suites),
                "mfp_capable": rsn.mfp_capable,
                "mfp_required": rsn.mfp_required,
                "group_management_cipher": rsn.group_management_cipher,
            }
            if rsn
            else None
        ),
        "ht_capabilities_present": summary.ht_capabilities_present,
        "ht_operation_present": summary.ht_operation_present,
        "vht_capabilities_present": summary.vht_capabilities_present,
        "vht_operation_present": summary.vht_operation_present,
        "extended_capabilities_present": summary.extended_capabilities_present,
        "extension_element_ids": list(summary.extension_element_ids),
        "vendor_specific_ouis": list(summary.vendor_specific_ouis),
        "unknown_element_ids": list(summary.unknown_element_ids),
        "malformed": summary.malformed,
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
