import ctypes
from ipaddress import IPv4Address
from threading import Event

import pytest

from wlanscope.domain.discovery import IcmpUnavailableError, ReachabilityState
from wlanscope.platform.windows.icmp import (
    INVALID_HANDLE_VALUE,
    IP_REQ_TIMED_OUT,
    NativeIcmpBindings,
    NativeIcmpProbeService,
    _IcmpEchoReply32,
)


class FakeIcmpBindings:
    def __init__(
        self,
        count: int = 1,
        error_code: int = 0,
        status: int = 0,
        response_address: str | None = None,
        handle: int = 10,
    ) -> None:
        self.count = count
        self.error_code = error_code
        self.status = status
        self.response_address = response_address
        self.handle = handle
        self.created = 0
        self.closed: list[int] = []

    def create_handle(self) -> int:
        self.created += 1
        return self.handle

    def close_handle(self, handle: int) -> bool:
        self.closed.append(handle)
        return True

    def send_echo(
        self,
        handle: int,
        destination: int,
        request: bytes,
        reply_buffer: ctypes.Array[ctypes.c_char],
        timeout_ms: int,
    ) -> tuple[int, int]:
        assert len(reply_buffer) >= 256
        if self.count:
            target = IPv4Address(destination.to_bytes(4, "little"))
            response = IPv4Address(self.response_address) if self.response_address else target
            reply = _IcmpEchoReply32.from_buffer(reply_buffer)
            reply.address = int.from_bytes(response.packed, "little")
            reply.status = self.status
            reply.round_trip_time = 4
        return self.count, self.error_code


class InterruptingBindings(FakeIcmpBindings):
    def send_echo(
        self,
        handle: int,
        destination: int,
        request: bytes,
        reply_buffer: ctypes.Array[ctypes.c_char],
        timeout_ms: int,
    ) -> tuple[int, int]:
        raise KeyboardInterrupt


def test_successful_probe_returns_response_and_releases_handle() -> None:
    bindings = FakeIcmpBindings()
    service = NativeIcmpProbeService(bindings, worker_count=1)

    results = service.probe_many((IPv4Address("192.0.2.10"),), Event())

    assert results[0].state is ReachabilityState.RESPONDED
    assert results[0].response_time_ms == 4
    assert bindings.closed == [10]


def test_timeout_is_no_response_and_releases_handle() -> None:
    bindings = FakeIcmpBindings(count=0, error_code=IP_REQ_TIMED_OUT)

    result = NativeIcmpProbeService(bindings, worker_count=1).probe_many(
        (IPv4Address("192.0.2.10"),), Event()
    )[0]

    assert result.state is ReachabilityState.NO_RESPONSE
    assert bindings.closed == [10]


def test_native_send_failure_is_probe_failed() -> None:
    bindings = FakeIcmpBindings(count=0, error_code=5)

    result = NativeIcmpProbeService(bindings, worker_count=1).probe_many(
        (IPv4Address("192.0.2.10"),), Event()
    )[0]

    assert result.state is ReachabilityState.PROBE_FAILED


def test_non_success_reply_status_is_no_response() -> None:
    bindings = FakeIcmpBindings(status=11003)

    result = NativeIcmpProbeService(bindings, worker_count=1).probe_many(
        (IPv4Address("192.0.2.10"),), Event()
    )[0]

    assert result.state is ReachabilityState.NO_RESPONSE


def test_mismatched_reply_address_is_probe_failed() -> None:
    bindings = FakeIcmpBindings(response_address="192.0.2.20")

    result = NativeIcmpProbeService(bindings, worker_count=1).probe_many(
        (IPv4Address("192.0.2.10"),), Event()
    )[0]

    assert result.state is ReachabilityState.PROBE_FAILED


@pytest.mark.parametrize("handle", [0, INVALID_HANDLE_VALUE])
def test_handle_creation_failure_is_reported(handle: int) -> None:
    bindings = FakeIcmpBindings(handle=handle)

    with pytest.raises(IcmpUnavailableError, match="IcmpCreateFile"):
        NativeIcmpProbeService(bindings, worker_count=1).probe_many(
            (IPv4Address("192.0.2.10"),), Event()
        )

    assert bindings.closed == []


def test_multiple_probe_results_are_sorted_deterministically() -> None:
    bindings = FakeIcmpBindings()
    targets = (IPv4Address("192.0.2.20"), IPv4Address("192.0.2.10"))

    results = NativeIcmpProbeService(bindings, worker_count=2).probe_many(targets, Event())

    assert tuple(result.address for result in results) == tuple(sorted(targets, key=int))
    assert bindings.created == 2
    assert len(bindings.closed) == 2


def test_pre_canceled_operation_submits_no_probe() -> None:
    cancellation = Event()
    cancellation.set()
    bindings = FakeIcmpBindings()

    results = NativeIcmpProbeService(bindings).probe_many(
        (IPv4Address("192.0.2.10"),), cancellation
    )

    assert results == ()
    assert bindings.created == 0


def test_keyboard_interrupt_signals_cancellation_and_releases_handle() -> None:
    cancellation = Event()
    bindings = InterruptingBindings()

    with pytest.raises(KeyboardInterrupt):
        NativeIcmpProbeService(bindings, worker_count=1).probe_many(
            (IPv4Address("192.0.2.10"),), cancellation
        )

    assert cancellation.is_set()
    assert bindings.closed == [10]


def test_invalid_service_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="timeout"):
        NativeIcmpProbeService(FakeIcmpBindings(), timeout_ms=0)
    with pytest.raises(ValueError, match="Worker"):
        NativeIcmpProbeService(FakeIcmpBindings(), worker_count=0)


def test_native_bindings_are_windows_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wlanscope.platform.windows.icmp.sys.platform", "linux")

    with pytest.raises(IcmpUnavailableError, match="require Windows"):
        NativeIcmpBindings()
