from __future__ import annotations

from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from threading import Event

import dns.exception
import dns.resolver

from wlanscope.domain.discovery import HostAddress
from wlanscope.domain.enrichment import (
    EnrichmentSource,
    HostnameResolution,
    HostnameResolutionBatch,
    HostnameResolutionState,
)

DEFAULT_DNS_TIMEOUT_SECONDS = 0.75
DEFAULT_DNS_LIFETIME_SECONDS = 1.5
DEFAULT_DNS_WORKERS = 16


class DnsPtrResolver:
    def __init__(
        self,
        timeout_seconds: float = DEFAULT_DNS_TIMEOUT_SECONDS,
        lifetime_seconds: float = DEFAULT_DNS_LIFETIME_SECONDS,
        worker_count: int = DEFAULT_DNS_WORKERS,
        resolver: dns.resolver.Resolver | None = None,
    ) -> None:
        if timeout_seconds <= 0 or lifetime_seconds <= 0:
            raise ValueError("DNS timeout and lifetime must be positive")
        if worker_count < 1:
            raise ValueError("DNS worker count must be positive")
        self._timeout_seconds = timeout_seconds
        self._lifetime_seconds = lifetime_seconds
        self._worker_count = worker_count
        self._resolver = resolver

    def resolve_many(
        self,
        addresses: Sequence[HostAddress],
        cancel_event: Event,
    ) -> HostnameResolutionBatch:
        if not addresses or cancel_event.is_set():
            return HostnameResolutionBatch(())
        try:
            resolver = self._resolver or dns.resolver.Resolver(configure=True)
        except dns.resolver.NoResolverConfiguration as error:
            return HostnameResolutionBatch(
                tuple(_failed(address) for address in addresses),
                f"DNS resolver configuration is unavailable: {error}",
            )
        resolver.timeout = self._timeout_seconds
        resolver.lifetime = self._lifetime_seconds
        executor = ThreadPoolExecutor(max_workers=min(self._worker_count, len(addresses)))
        futures: dict[Future[HostnameResolution], HostAddress] = {}
        try:
            for address in addresses:
                if cancel_event.is_set():
                    break
                futures[executor.submit(self._resolve_one, resolver, address)] = address
            results: list[HostnameResolution] = []
            for future in as_completed(futures):
                if cancel_event.is_set():
                    break
                results.append(future.result())
            ordered = tuple(
                sorted(results, key=lambda item: (item.address.version, int(item.address)))
            )
            systemic_issue = None
            if ordered and all(item.state is HostnameResolutionState.FAILED for item in ordered):
                systemic_issue = "DNS resolver failed for every observed host"
            return HostnameResolutionBatch(ordered, systemic_issue)
        except KeyboardInterrupt:
            cancel_event.set()
            raise
        finally:
            if cancel_event.is_set():
                for future in futures:
                    future.cancel()
            executor.shutdown(wait=not cancel_event.is_set(), cancel_futures=True)

    def _resolve_one(
        self,
        resolver: dns.resolver.Resolver,
        address: HostAddress,
    ) -> HostnameResolution:
        try:
            answer = resolver.resolve_address(str(address), lifetime=self._lifetime_seconds)
            hostname = str(answer[0])
            if hostname.endswith("."):
                hostname = hostname[:-1]
            if not hostname:
                return _failed(address)
            return HostnameResolution(
                address,
                HostnameResolutionState.RESOLVED,
                hostname,
                EnrichmentSource.PTR,
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return HostnameResolution(address, HostnameResolutionState.NOT_FOUND)
        except dns.exception.Timeout:
            return HostnameResolution(address, HostnameResolutionState.TIMEOUT)
        except (dns.resolver.NoNameservers, dns.exception.DNSException):
            return _failed(address)
        except (IndexError, ValueError):
            return _failed(address)


def _failed(address: HostAddress) -> HostnameResolution:
    return HostnameResolution(address, HostnameResolutionState.FAILED)
