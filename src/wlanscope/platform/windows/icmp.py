from __future__ import annotations

import ctypes
import sys
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from ctypes import wintypes
from ipaddress import IPv4Address
from threading import Event
from typing import Protocol

from wlanscope.domain.discovery import (
    IcmpUnavailableError,
    ProbeResult,
    ReachabilityState,
)

DEFAULT_PROBE_TIMEOUT_MS = 750
DEFAULT_PROBE_WORKERS = 32
IP_SUCCESS = 0
IP_REQ_TIMED_OUT = 11010
REQUEST_PAYLOAD = b"WLANScope"
INVALID_HANDLE_VALUE = int(ctypes.c_void_p(-1).value or 0)
MINIMUM_REPLY_BUFFER_SIZE = 256


class _IpOptionInformation32(ctypes.Structure):
    _fields_ = [
        ("ttl", ctypes.c_ubyte),
        ("tos", ctypes.c_ubyte),
        ("flags", ctypes.c_ubyte),
        ("options_size", ctypes.c_ubyte),
        ("options_data", wintypes.ULONG),
    ]


class _IcmpEchoReply32(ctypes.Structure):
    _fields_ = [
        ("address", wintypes.ULONG),
        ("status", wintypes.ULONG),
        ("round_trip_time", wintypes.ULONG),
        ("data_size", wintypes.USHORT),
        ("reserved", wintypes.USHORT),
        ("data", wintypes.ULONG),
        ("options", _IpOptionInformation32),
    ]


class IcmpBindings(Protocol):
    def create_handle(self) -> int: ...

    def close_handle(self, handle: int) -> bool: ...

    def send_echo(
        self,
        handle: int,
        destination: int,
        request: bytes,
        reply_buffer: ctypes.Array[ctypes.c_char],
        timeout_ms: int,
    ) -> tuple[int, int]: ...


class NativeIcmpBindings:
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise IcmpUnavailableError("Windows ICMP APIs require Windows")
        library = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        self._create = library.IcmpCreateFile
        self._create.argtypes = []
        self._create.restype = wintypes.HANDLE
        self._close = library.IcmpCloseHandle
        self._close.argtypes = [wintypes.HANDLE]
        self._close.restype = wintypes.BOOL
        self._send = library.IcmpSendEcho2
        self._send.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.c_void_p,
            wintypes.USHORT,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.ULONG,
            wintypes.ULONG,
        ]
        self._send.restype = wintypes.ULONG

    def create_handle(self) -> int:
        handle = self._create()
        return int(handle or 0)

    def close_handle(self, handle: int) -> bool:
        return bool(self._close(wintypes.HANDLE(handle)))

    def send_echo(
        self,
        handle: int,
        destination: int,
        request: bytes,
        reply_buffer: ctypes.Array[ctypes.c_char],
        timeout_ms: int,
    ) -> tuple[int, int]:
        request_buffer = ctypes.create_string_buffer(request)
        count = int(
            self._send(
                wintypes.HANDLE(handle),
                None,
                None,
                None,
                destination,
                request_buffer,
                len(request),
                None,
                reply_buffer,
                len(reply_buffer),
                timeout_ms,
            )
        )
        return count, ctypes.get_last_error() if count == 0 else 0


class NativeIcmpProbeService:
    def __init__(
        self,
        bindings: IcmpBindings | None = None,
        timeout_ms: int = DEFAULT_PROBE_TIMEOUT_MS,
        worker_count: int = DEFAULT_PROBE_WORKERS,
    ) -> None:
        if timeout_ms < 1:
            raise ValueError("Probe timeout must be positive")
        if worker_count < 1:
            raise ValueError("Worker count must be positive")
        self._bindings = bindings
        self.timeout_ms = timeout_ms
        self.worker_count = worker_count

    def probe_many(
        self,
        targets: Sequence[IPv4Address],
        cancel_event: Event,
    ) -> tuple[ProbeResult, ...]:
        if cancel_event.is_set() or not targets:
            return ()
        bindings = self._bindings or NativeIcmpBindings()
        executor = ThreadPoolExecutor(max_workers=min(self.worker_count, len(targets)))
        futures: dict[Future[ProbeResult], IPv4Address] = {}
        try:
            for target in targets:
                if cancel_event.is_set():
                    break
                futures[executor.submit(self._probe, bindings, target)] = target
            results: list[ProbeResult] = []
            for future in as_completed(futures):
                if cancel_event.is_set():
                    break
                results.append(future.result())
            return tuple(sorted(results, key=lambda result: int(result.address)))
        except KeyboardInterrupt:
            cancel_event.set()
            raise
        finally:
            if cancel_event.is_set():
                for future in futures:
                    future.cancel()
            executor.shutdown(wait=not cancel_event.is_set(), cancel_futures=True)

    def _probe(self, bindings: IcmpBindings, target: IPv4Address) -> ProbeResult:
        handle = bindings.create_handle()
        if not handle or handle == INVALID_HANDLE_VALUE:
            raise IcmpUnavailableError("IcmpCreateFile failed")
        try:
            required_size = ctypes.sizeof(_IcmpEchoReply32) + len(REQUEST_PAYLOAD) + 8
            buffer_size = max(required_size, MINIMUM_REPLY_BUFFER_SIZE)
            reply_buffer = ctypes.create_string_buffer(buffer_size)
            destination = int.from_bytes(target.packed, "little")
            count, error_code = bindings.send_echo(
                handle,
                destination,
                REQUEST_PAYLOAD,
                reply_buffer,
                self.timeout_ms,
            )
            if count == 0:
                state = (
                    ReachabilityState.NO_RESPONSE
                    if error_code == IP_REQ_TIMED_OUT
                    else ReachabilityState.PROBE_FAILED
                )
                return ProbeResult(target, state)
            reply = _IcmpEchoReply32.from_buffer(reply_buffer)
            reply_address = IPv4Address(int(reply.address).to_bytes(4, "little"))
            if reply_address != target:
                return ProbeResult(target, ReachabilityState.PROBE_FAILED)
            if int(reply.status) != IP_SUCCESS:
                return ProbeResult(target, ReachabilityState.NO_RESPONSE)
            return ProbeResult(target, ReachabilityState.RESPONDED, int(reply.round_trip_time))
        finally:
            bindings.close_handle(handle)
