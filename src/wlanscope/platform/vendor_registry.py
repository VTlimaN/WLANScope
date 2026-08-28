from __future__ import annotations

import csv
import io
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
from wlanscope.domain.nearby_wifi import WifiAccessPointVendor
from wlanscope.domain.wifi import WifiBssid

REGISTRY_COLUMNS = frozenset({"Registry", "Assignment", "Organization Name"})
MAX_REGISTRY_FILE_SIZE = 32 * 1024 * 1024
MAX_REGISTRY_ROWS = 1_000_000
MAX_ORGANIZATION_NAME_LENGTH = 512


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

    def resolve_bssids(
        self,
        bssids: Sequence[WifiBssid],
    ) -> tuple[WifiAccessPointVendor, ...]:
        path = self._registry_path or default_registry_path()
        if path is None or not path.is_file():
            return tuple(_without_ap_registry(bssid) for bssid in bssids)
        try:
            registry = load_ieee_ma_l_registry(path)
        except (OSError, UnicodeError, VendorRegistryError):
            return tuple(_without_ap_registry(bssid) for bssid in bssids)
        cache: dict[bytes, WifiAccessPointVendor] = {}
        results: list[WifiAccessPointVendor] = []
        for bssid in bssids:
            resolution = cache.get(bssid.octets)
            if resolution is None:
                resolution = _resolve_bssid(bssid, registry)
                cache[bssid.octets] = resolution
            results.append(resolution)
        return tuple(results)


def default_registry_path() -> Path | None:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return None
    return Path(local_app_data) / "WLANScope" / "data" / "oui.csv"


def load_ieee_ma_l_registry(path: Path) -> dict[bytes, str]:
    with path.open("rb") as source:
        raw = source.read(MAX_REGISTRY_FILE_SIZE + 1)
    if len(raw) > MAX_REGISTRY_FILE_SIZE:
        raise VendorRegistryError("Registry exceeds the supported file-size limit")
    with io.StringIO(raw.decode("utf-8-sig"), newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None or not set(reader.fieldnames) >= REGISTRY_COLUMNS:
            raise VendorRegistryError("Registry header does not match the IEEE MA-L CSV format")
        registry: dict[bytes, str] = {}
        for row_number, row in enumerate(reader, start=1):
            if row_number > MAX_REGISTRY_ROWS:
                raise VendorRegistryError("Registry exceeds the supported row limit")
            if row["Registry"].strip().upper() != "MA-L":
                continue
            prefix = _parse_assignment(row["Assignment"])
            organization = row["Organization Name"].strip()
            if not organization:
                raise VendorRegistryError("Registry contains an empty organization name")
            if len(organization) > MAX_ORGANIZATION_NAME_LENGTH:
                raise VendorRegistryError("Registry contains an oversized organization name")
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


def _resolve_bssid(
    bssid: WifiBssid,
    registry: dict[bytes, str],
) -> WifiAccessPointVendor:
    if bssid.octets[0] & 0x03:
        return WifiAccessPointVendor(VendorResolutionState.NOT_APPLICABLE)
    vendor = registry.get(bssid.octets[:3])
    if vendor is None:
        return WifiAccessPointVendor(VendorResolutionState.UNKNOWN)
    return WifiAccessPointVendor(
        VendorResolutionState.RESOLVED,
        vendor,
        EnrichmentSource.LOCAL_OUI_REGISTRY,
    )


def _without_ap_registry(bssid: WifiBssid) -> WifiAccessPointVendor:
    if bssid.octets[0] & 0x03:
        return WifiAccessPointVendor(VendorResolutionState.NOT_APPLICABLE)
    return WifiAccessPointVendor(VendorResolutionState.REGISTRY_UNAVAILABLE)
