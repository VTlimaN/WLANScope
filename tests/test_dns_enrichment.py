from ipaddress import IPv4Address, IPv6Address
from threading import Event
from typing import cast

import dns.exception
import dns.resolver
import pytest

from wlanscope.domain.enrichment import HostnameResolutionState
from wlanscope.platform.dns import DnsPtrResolver


class FakeAnswer:
    def __init__(self, values: list[str]) -> None:
        self._values = values

    def __getitem__(self, index: int) -> str:
        return self._values[index]


class FakeResolver:
    timeout = 0.0
    lifetime = 0.0

    def __init__(self, responses: dict[str, list[str] | BaseException]) -> None:
        self.responses = responses
        self.queries: list[str] = []

    def resolve_address(self, address: str, lifetime: float) -> FakeAnswer:
        self.queries.append(address)
        response = self.responses[address]
        if isinstance(response, BaseException):
            raise response
        return FakeAnswer(response)


class FakeNxDomain(dns.resolver.NXDOMAIN):
    def __init__(self) -> None:
        Exception.__init__(self)


class FakeNoAnswer(dns.resolver.NoAnswer):
    def __init__(self) -> None:
        Exception.__init__(self)


class FakeTimeout(dns.exception.Timeout):
    def __init__(self) -> None:
        Exception.__init__(self)


class FakeNoNameservers(dns.resolver.NoNameservers):
    def __init__(self) -> None:
        Exception.__init__(self)


def service(resolver: FakeResolver) -> DnsPtrResolver:
    return DnsPtrResolver(
        timeout_seconds=0.25,
        lifetime_seconds=0.5,
        worker_count=4,
        resolver=cast(dns.resolver.Resolver, resolver),
    )


def test_ptr_resolves_ipv4_and_removes_one_trailing_dot() -> None:
    address = IPv4Address("192.0.2.10")
    resolver = FakeResolver({str(address): ["host.example."]})

    batch = service(resolver).resolve_many((address,), Event())

    assert batch.resolutions[0].state is HostnameResolutionState.RESOLVED
    assert batch.resolutions[0].hostname == "host.example"
    assert resolver.timeout == 0.25
    assert resolver.lifetime == 0.5


def test_ptr_resolves_observed_ipv6() -> None:
    address = IPv6Address("2001:db8::10")
    resolver = FakeResolver({str(address): ["host-v6.example."]})

    batch = service(resolver).resolve_many((address,), Event())

    assert batch.resolutions[0].hostname == "host-v6.example"


@pytest.mark.parametrize("error", [FakeNxDomain(), FakeNoAnswer()])
def test_no_ptr_is_normal_not_found(error: BaseException) -> None:
    address = IPv4Address("192.0.2.10")

    batch = service(FakeResolver({str(address): error})).resolve_many((address,), Event())

    assert batch.resolutions[0].state is HostnameResolutionState.NOT_FOUND
    assert batch.systemic_issue is None


def test_dns_timeout_is_distinct() -> None:
    address = IPv4Address("192.0.2.10")
    timeout = FakeTimeout()

    batch = service(FakeResolver({str(address): timeout})).resolve_many((address,), Event())

    assert batch.resolutions[0].state is HostnameResolutionState.TIMEOUT
    assert batch.systemic_issue is None


def test_dns_failure_for_every_host_is_systemic() -> None:
    addresses = (IPv4Address("192.0.2.10"), IPv4Address("192.0.2.11"))
    resolver = FakeResolver({str(address): FakeNoNameservers() for address in addresses})

    batch = service(resolver).resolve_many(addresses, Event())

    assert all(item.state is HostnameResolutionState.FAILED for item in batch.resolutions)
    assert batch.systemic_issue is not None


def test_malformed_empty_answer_is_failed() -> None:
    address = IPv4Address("192.0.2.10")

    batch = service(FakeResolver({str(address): []})).resolve_many((address,), Event())

    assert batch.resolutions[0].state is HostnameResolutionState.FAILED


def test_concurrent_results_remain_deterministically_associated() -> None:
    addresses = (
        IPv4Address("192.0.2.30"),
        IPv4Address("192.0.2.10"),
        IPv4Address("192.0.2.20"),
    )
    resolver = FakeResolver({str(address): [f"host-{address}.example."] for address in addresses})

    batch = service(resolver).resolve_many(addresses, Event())

    assert tuple(item.address for item in batch.resolutions) == tuple(sorted(addresses, key=int))
    assert set(resolver.queries) == {str(address) for address in addresses}


def test_markup_like_hostname_is_preserved_literally() -> None:
    address = IPv4Address("192.0.2.10")

    batch = service(FakeResolver({str(address): ["[bold]host[/bold]."]})).resolve_many(
        (address,), Event()
    )

    assert batch.resolutions[0].hostname == "[bold]host[/bold]"


def test_pre_canceled_resolution_attempts_no_query() -> None:
    cancellation = Event()
    cancellation.set()
    address = IPv4Address("192.0.2.10")
    resolver = FakeResolver({str(address): ["host.example."]})

    batch = service(resolver).resolve_many((address,), cancellation)

    assert batch.resolutions == ()
    assert resolver.queries == []


def test_invalid_dns_limits_are_rejected() -> None:
    with pytest.raises(ValueError, match="timeout"):
        DnsPtrResolver(timeout_seconds=0)
    with pytest.raises(ValueError, match="worker"):
        DnsPtrResolver(worker_count=0)
