from ipaddress import IPv4Address
from pathlib import Path

import pytest

from wlanscope.domain.discovery import DiscoveredHost, DiscoverySource, ReachabilityState
from wlanscope.domain.enrichment import VendorResolutionState
from wlanscope.domain.interfaces import MacAddress
from wlanscope.domain.wifi import WifiBssid
from wlanscope.platform import vendor_registry
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


def test_ap_bssid_vendor_states_reuse_local_registry(tmp_path: Path) -> None:
    registry_path = tmp_path / "oui.csv"
    write_registry(registry_path, ["MA-L,001122,Example Networks"])
    resolver = LocalOuiVendorResolver(registry_path)

    resolved, unknown, local = resolver.resolve_bssids(
        (
            WifiBssid(bytes.fromhex("001122334455")),
            WifiBssid(bytes.fromhex("003344556677")),
            WifiBssid(bytes.fromhex("020000000001")),
        )
    )

    assert resolved.state is VendorResolutionState.RESOLVED
    assert resolved.vendor == "Example Networks"
    assert unknown.state is VendorResolutionState.UNKNOWN
    assert local.state is VendorResolutionState.NOT_APPLICABLE


def test_ap_registry_missing_and_corrupt_are_unavailable(tmp_path: Path) -> None:
    bssid = WifiBssid(bytes.fromhex("001122334455"))
    missing = LocalOuiVendorResolver(tmp_path / "missing.csv").resolve_bssids((bssid,))[0]
    corrupt_path = tmp_path / "corrupt.csv"
    corrupt_path.write_text("invalid\n", encoding="utf-8")
    corrupt = LocalOuiVendorResolver(corrupt_path).resolve_bssids((bssid,))[0]

    assert missing.state is VendorResolutionState.REGISTRY_UNAVAILABLE
    assert corrupt.state is VendorResolutionState.REGISTRY_UNAVAILABLE


def test_ap_batch_loads_registry_once_and_preserves_bssid_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_path = tmp_path / "oui.csv"
    write_registry(registry_path, ["MA-L,001122,Example Networks"])
    original_loader = vendor_registry.load_ieee_ma_l_registry
    calls = 0

    def counting_loader(path: Path) -> dict[bytes, str]:
        nonlocal calls
        calls += 1
        return original_loader(path)

    monkeypatch.setattr(vendor_registry, "load_ieee_ma_l_registry", counting_loader)
    first = WifiBssid(bytes.fromhex("001122334455"))
    second = WifiBssid(bytes.fromhex("001122667788"))
    duplicate = WifiBssid(bytes.fromhex("001122334455"))

    resolutions = LocalOuiVendorResolver(registry_path).resolve_bssids((first, second, duplicate))

    assert calls == 1
    assert tuple(item.vendor for item in resolutions) == (
        "Example Networks",
        "Example Networks",
        "Example Networks",
    )
    assert resolutions[0] is resolutions[2]
