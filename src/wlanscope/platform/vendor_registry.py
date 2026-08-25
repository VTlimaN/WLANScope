from __future__ import annotations

import csv
import os
from collections.abc import Sequence
from pathlib import Path

from wlanscope.domain.discovery import DiscoveredHost
from wlanscope.domain.enrichment import (
    EnrichmentSource,
    VendorResolution,
    VendorResolutionBatch,
    VendorResolutionState,
)
from wlanscope.domain.interfaces import MacAddress

REGISTRY_COLUMNS = frozenset({"Registry", "Assignment", "Organization Name"})


class VendorRegistryError(RuntimeError):
    pass


class LocalOuiVendorResolver:
    def __init__(self, registry_path: Path | None = None) -> None:
        self._registry_path = registry_path

    def resolve_many(self, hosts: Sequence[DiscoveredHost]) -> VendorResolutionBatch:
        path = self._registry_path or default_registry_path()
        if path is None or not path.is_file():
            return VendorResolutionBatch(
                tuple(_without_registry(host) for host in hosts),
            )
        try:
            registry = load_ieee_ma_l_registry(path)
        except (OSError, UnicodeError, VendorRegistryError) as error:
            return VendorResolutionBatch(
                tuple(_with_failed_registry(host) for host in hosts),
                f"Local OUI registry could not be loaded: {error}",
            )
        return VendorResolutionBatch(tuple(_resolve_vendor(host, registry) for host in hosts))


def default_registry_path() -> Path | None:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return None
    return Path(local_app_data) / "WLANScope" / "data" / "oui.csv"


def load_ieee_ma_l_registry(path: Path) -> dict[bytes, str]:
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None or not set(reader.fieldnames) >= REGISTRY_COLUMNS:
            raise VendorRegistryError("Registry header does not match the IEEE MA-L CSV format")
        registry: dict[bytes, str] = {}
        for row in reader:
            if row["Registry"].strip().upper() != "MA-L":
                continue
            prefix = _parse_assignment(row["Assignment"])
            organization = row["Organization Name"].strip()
            if not organization:
                raise VendorRegistryError("Registry contains an empty organization name")
            if prefix in registry:
                raise VendorRegistryError("Registry contains a duplicate MA-L assignment")
            registry[prefix] = organization
        return registry


def _parse_assignment(value: str) -> bytes:
    normalized = value.strip().replace(":", "").replace("-", "").replace(".", "")
    if len(normalized) != 6:
        raise VendorRegistryError("Registry contains an invalid MA-L assignment")
    try:
        return bytes.fromhex(normalized)
    except ValueError as error:
        raise VendorRegistryError("Registry contains an invalid MA-L assignment") from error


def _resolve_vendor(
    host: DiscoveredHost,
    registry: dict[bytes, str],
) -> VendorResolution:
    state = _mac_state(host.mac_address)
    if state is not None:
        return VendorResolution(host.interface_index, host.address, state)
    if host.mac_address is None:
        return VendorResolution(
            host.interface_index,
            host.address,
            VendorResolutionState.NOT_APPLICABLE,
        )
    vendor = registry.get(host.mac_address.octets[:3])
    if vendor is None:
        return VendorResolution(host.interface_index, host.address, VendorResolutionState.UNKNOWN)
    return VendorResolution(
        host.interface_index,
        host.address,
        VendorResolutionState.RESOLVED,
        vendor,
        EnrichmentSource.LOCAL_OUI_REGISTRY,
    )


def _without_registry(host: DiscoveredHost) -> VendorResolution:
    state = _mac_state(host.mac_address)
    if state is not None:
        return VendorResolution(host.interface_index, host.address, state)
    if host.mac_address is None:
        return VendorResolution(
            host.interface_index,
            host.address,
            VendorResolutionState.NOT_APPLICABLE,
        )
    return VendorResolution(
        host.interface_index,
        host.address,
        VendorResolutionState.REGISTRY_UNAVAILABLE,
    )


def _with_failed_registry(host: DiscoveredHost) -> VendorResolution:
    state = _mac_state(host.mac_address)
    return VendorResolution(
        host.interface_index,
        host.address,
        state or VendorResolutionState.FAILED,
    )


def _mac_state(mac_address: MacAddress | None) -> VendorResolutionState | None:
    if mac_address is None:
        return VendorResolutionState.NOT_APPLICABLE
    first_octet = mac_address.octets[0]
    if first_octet & 1:
        return VendorResolutionState.NOT_APPLICABLE
    if first_octet & 2:
        return VendorResolutionState.LOCALLY_ADMINISTERED
    return None
