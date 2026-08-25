from ipaddress import IPv4Address
from pathlib import Path

import pytest

from wlanscope.domain.discovery import DiscoveredHost, DiscoverySource, ReachabilityState
from wlanscope.domain.enrichment import VendorResolutionState
from wlanscope.domain.interfaces import MacAddress
from wlanscope.platform.vendor_registry import (
    LocalOuiVendorResolver,
    VendorRegistryError,
    load_ieee_ma_l_registry,
)


def host(mac: str | None, suffix: int = 10) -> DiscoveredHost:
    return DiscoveredHost(
        7,
        IPv4Address(f"192.0.2.{suffix}"),
        MacAddress.from_text(mac) if mac else None,
        ReachabilityState.NOT_PROBED,
        frozenset({DiscoverySource.NEIGHBOR_CACHE}),
    )


def write_registry(path: Path, rows: list[str]) -> None:
    content = "Registry,Assignment,Organization Name\n" + "\n".join(rows) + "\n"
    path.write_text(content, encoding="utf-8")


def test_known_synthetic_ma_l_resolves_from_local_registry(tmp_path: Path) -> None:
    registry_path = tmp_path / "oui.csv"
    write_registry(registry_path, ["MA-L,001122,Example Networks"])

    batch = LocalOuiVendorResolver(registry_path).resolve_many((host("00:11:22:33:44:55"),))

    assert batch.resolutions[0].state is VendorResolutionState.RESOLVED
    assert batch.resolutions[0].vendor == "Example Networks"


def test_unknown_oui_is_normal(tmp_path: Path) -> None:
    registry_path = tmp_path / "oui.csv"
    write_registry(registry_path, ["MA-L,001122,Example Networks"])

    batch = LocalOuiVendorResolver(registry_path).resolve_many((host("00:33:44:55:66:77"),))

    assert batch.resolutions[0].state is VendorResolutionState.UNKNOWN
    assert batch.systemic_issue is None


def test_absent_mac_is_not_applicable(tmp_path: Path) -> None:
    registry_path = tmp_path / "oui.csv"
    write_registry(registry_path, [])

    resolution = LocalOuiVendorResolver(registry_path).resolve_many((host(None),)).resolutions[0]

    assert resolution.state is VendorResolutionState.NOT_APPLICABLE


def test_locally_administered_mac_is_not_attributed(tmp_path: Path) -> None:
    registry_path = tmp_path / "oui.csv"
    write_registry(registry_path, ["MA-L,020000,Incorrect Attribution"])

    resolution = (
        LocalOuiVendorResolver(registry_path)
        .resolve_many((host("02:00:00:00:00:10"),))
        .resolutions[0]
    )

    assert resolution.state is VendorResolutionState.LOCALLY_ADMINISTERED
    assert resolution.vendor is None


def test_multicast_mac_is_not_applicable(tmp_path: Path) -> None:
    registry_path = tmp_path / "oui.csv"
    write_registry(registry_path, ["MA-L,01005E,Incorrect Attribution"])

    resolution = (
        LocalOuiVendorResolver(registry_path)
        .resolve_many((host("01:00:5E:00:00:01"),))
        .resolutions[0]
    )

    assert resolution.state is VendorResolutionState.NOT_APPLICABLE


def test_missing_registry_is_unavailable_without_systemic_warning(tmp_path: Path) -> None:
    batch = LocalOuiVendorResolver(tmp_path / "missing.csv").resolve_many(
        (host("00:11:22:33:44:55"), host(None, 11))
    )

    assert batch.resolutions[0].state is VendorResolutionState.REGISTRY_UNAVAILABLE
    assert batch.resolutions[1].state is VendorResolutionState.NOT_APPLICABLE
    assert batch.systemic_issue is None


@pytest.mark.parametrize(
    "content",
    [
        "wrong,header\nvalue,value\n",
        "Registry,Assignment,Organization Name\nMA-L,0011,Example\n",
        "Registry,Assignment,Organization Name\nMA-L,ZZ1122,Example\n",
        "Registry,Assignment,Organization Name\nMA-L,001122,\n",
        "Registry,Assignment,Organization Name\nMA-L,001122,One\nMA-L,00:11:22,Two\n",
    ],
)
def test_malformed_registry_is_rejected(tmp_path: Path, content: str) -> None:
    registry_path = tmp_path / "oui.csv"
    registry_path.write_text(content, encoding="utf-8")

    with pytest.raises(VendorRegistryError):
        load_ieee_ma_l_registry(registry_path)


def test_malformed_registry_becomes_systemic_issue(tmp_path: Path) -> None:
    registry_path = tmp_path / "oui.csv"
    registry_path.write_text("invalid\n", encoding="utf-8")

    batch = LocalOuiVendorResolver(registry_path).resolve_many(
        (host("00:11:22:33:44:55"), host("02:00:00:00:00:10", 11), host(None, 12))
    )

    assert batch.resolutions[0].state is VendorResolutionState.FAILED
    assert batch.resolutions[1].state is VendorResolutionState.LOCALLY_ADMINISTERED
    assert batch.resolutions[2].state is VendorResolutionState.NOT_APPLICABLE
    assert batch.systemic_issue is not None


def test_assignment_delimiters_are_normalized(tmp_path: Path) -> None:
    registry_path = tmp_path / "oui.csv"
    write_registry(registry_path, ["MA-L,00-11-22,Example Networks"])

    registry = load_ieee_ma_l_registry(registry_path)

    assert registry[bytes.fromhex("001122")] == "Example Networks"


def test_non_ma_l_rows_are_ignored(tmp_path: Path) -> None:
    registry_path = tmp_path / "oui.csv"
    write_registry(registry_path, ["MA-M,0011223,Example Medium"])

    assert load_ieee_ma_l_registry(registry_path) == {}
