from ipaddress import ip_address, ip_network

import pytest

from wlanscope.domain.network import (
    AddressOrigin,
    CurrentNetworkSnapshot,
    DadState,
    DhcpConfiguration,
    DhcpState,
    DnsConfiguration,
    InterfaceNetworkContext,
    IpAddressAssignment,
    PrefixOrigin,
    Route,
    RouteOrigin,
    RouteProtocol,
)


@pytest.mark.parametrize(
    ("address", "prefix", "network"),
    [
        ("192.0.2.24", 24, "192.0.2.0/24"),
        ("2001:db8::1234", 64, "2001:db8::/64"),
        ("fe80::1", 128, "fe80::1/128"),
    ],
)
def test_assignment_derives_network(address: str, prefix: int, network: str) -> None:
    assert str(_assignment(address, prefix).network) == network


@pytest.mark.parametrize(
    ("address", "prefix"),
    [("192.0.2.1", -1), ("192.0.2.1", 33), ("2001:db8::1", 129)],
)
def test_assignment_rejects_invalid_prefix(address: str, prefix: int) -> None:
    with pytest.raises(ValueError, match="Prefix length"):
        _assignment(address, prefix)


def test_assignment_preserves_link_local_scope_and_source_state() -> None:
    assignment = _assignment("fe80::1", 64, scope_id=7, skip_as_source=True)

    assert assignment.address.is_link_local
    assert assignment.scope_id == 7
    assert assignment.skip_as_source


def test_dns_preserves_ipv4_ipv6_order() -> None:
    dns = DnsConfiguration(
        7,
        (ip_address("192.0.2.53"), ip_address("2001:db8::53")),
        "example.invalid",
    )

    assert [server.version for server in dns.servers] == [4, 6]


@pytest.mark.parametrize("state", list(DhcpState))
def test_dhcp_states_are_explicit(state: DhcpState) -> None:
    configuration = DhcpConfiguration(7, state, DhcpState.UNKNOWN)

    assert configuration.ipv4_state is state


def test_route_validates_address_family() -> None:
    with pytest.raises(ValueError, match="same address family"):
        _route("0.0.0.0/0", "2001:db8::1", 7, 10, 20)


def test_route_preserves_metric_components() -> None:
    route = _route("0.0.0.0/0", "192.0.2.1", 7, 10, 20)

    assert route.route_metric == 10
    assert route.interface_metric == 20
    assert route.effective_metric == 30
    assert route.is_default


def test_route_without_interface_metric_has_no_effective_metric() -> None:
    assert _route("::/0", "2001:db8::1", 7, 10, None).effective_metric is None


def test_unused_native_route_metric_has_no_effective_metric() -> None:
    assert _route("0.0.0.0/0", "192.0.2.1", 7, 0xFFFFFFFF, 20).effective_metric is None


def test_snapshot_preserves_multiple_gateways() -> None:
    first = _route("0.0.0.0/0", "192.0.2.1", 7, 10, 20)
    second = _route("0.0.0.0/0", "198.51.100.1", 8, 5, 50)
    snapshot = CurrentNetworkSnapshot((), (first, second))

    assert snapshot.default_routes == (first, second)
    assert snapshot.preferred_default_route(4) is first


def test_snapshot_keeps_ipv4_and_ipv6_default_selection_separate() -> None:
    ipv4 = _route("0.0.0.0/0", "192.0.2.1", 7, 10, 20)
    ipv6 = _route("::/0", "2001:db8::1", 8, 5, 10)
    snapshot = CurrentNetworkSnapshot((), (ipv4, ipv6))

    assert snapshot.preferred_default_route(4) is ipv4
    assert snapshot.preferred_default_route(6) is ipv6


def test_snapshot_does_not_claim_preference_when_metric_is_unknown_or_tied() -> None:
    unknown = CurrentNetworkSnapshot(
        (),
        (
            _route("0.0.0.0/0", "192.0.2.1", 7, 10, None),
            _route("0.0.0.0/0", "198.51.100.1", 8, 5, 20),
        ),
    )
    tied = CurrentNetworkSnapshot(
        (),
        (
            _route("0.0.0.0/0", "192.0.2.1", 7, 10, 20),
            _route("0.0.0.0/0", "198.51.100.1", 8, 20, 10),
        ),
    )

    assert unknown.preferred_default_route(4) is None
    assert tied.preferred_default_route(4) is None


def test_context_preserves_multiple_addresses_and_missing_gateway() -> None:
    addresses = (_assignment("192.0.2.24", 24), _assignment("2001:db8::24", 64))
    context = InterfaceNetworkContext(
        7,
        addresses,
        None,
        DhcpConfiguration(7, DhcpState.UNKNOWN, DhcpState.UNKNOWN),
    )

    assert context.addresses == addresses
    assert CurrentNetworkSnapshot((context,), ()).default_routes == ()


def _assignment(
    address: str,
    prefix: int,
    scope_id: int | None = None,
    skip_as_source: bool = False,
) -> IpAddressAssignment:
    return IpAddressAssignment(
        address=ip_address(address),
        prefix_length=prefix,
        interface_index=7,
        prefix_origin=PrefixOrigin(3),
        address_origin=AddressOrigin(3),
        dad_state=DadState(4),
        preferred_lifetime_seconds=3600,
        valid_lifetime_seconds=7200,
        skip_as_source=skip_as_source,
        scope_id=scope_id,
    )


def _route(
    destination: str,
    next_hop: str,
    interface_index: int,
    route_metric: int,
    interface_metric: int | None,
) -> Route:
    return Route(
        destination=ip_network(destination),
        next_hop=ip_address(next_hop),
        interface_index=interface_index,
        route_metric=route_metric,
        interface_metric=interface_metric,
        protocol=RouteProtocol(3),
        origin=RouteOrigin(2),
    )
