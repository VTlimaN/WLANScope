from collections.abc import Sequence
from dataclasses import replace
from typing import Protocol

from wlanscope.domain.interfaces import (
    AdapterEnrichment,
    AdministrativeState,
    InterfaceEnrichmentError,
    InterfaceInventory,
    InterfaceKind,
    MediaState,
    NetworkInterface,
    OperationalState,
)


class InterfaceCollector(Protocol):
    def collect(self) -> tuple[NetworkInterface, ...]: ...


class InterfaceEnrichmentCollector(Protocol):
    def collect(self) -> tuple[AdapterEnrichment, ...]: ...


class ListNetworkInterfaces:
    def __init__(
        self,
        primary_collector: InterfaceCollector,
        enrichment_collector: InterfaceEnrichmentCollector | None = None,
    ) -> None:
        self._primary_collector = primary_collector
        self._enrichment_collector = enrichment_collector

    def execute(self) -> InterfaceInventory:
        interfaces = self._primary_collector.collect()
        warnings: tuple[str, ...] = ()

        if self._enrichment_collector is not None:
            try:
                enrichments = self._enrichment_collector.collect()
            except InterfaceEnrichmentError as error:
                warnings = (str(error),)
            else:
                interfaces = merge_interface_enrichments(interfaces, enrichments)

        return InterfaceInventory(sort_interfaces(interfaces), warnings)


def merge_interface_enrichments(
    interfaces: Sequence[NetworkInterface],
    enrichments: Sequence[AdapterEnrichment],
) -> tuple[NetworkInterface, ...]:
    by_stable_id = {interface.stable_id.casefold(): interface for interface in interfaces}
    by_index = {interface.interface_index: interface for interface in interfaces}
    merged = {interface.stable_id.casefold(): interface for interface in interfaces}

    for enrichment in enrichments:
        interface = _find_interface(enrichment, by_stable_id, by_index)
        if interface is None:
            continue
        merged[interface.stable_id.casefold()] = _merge_interface(interface, enrichment)

    return tuple(merged.values())


def sort_interfaces(interfaces: Sequence[NetworkInterface]) -> tuple[NetworkInterface, ...]:
    state_priority = {
        OperationalState.UP: 0,
        OperationalState.DORMANT: 1,
        OperationalState.DOWN: 2,
        OperationalState.LOWER_LAYER_DOWN: 3,
        OperationalState.NOT_PRESENT: 4,
        OperationalState.TESTING: 5,
        OperationalState.UNKNOWN: 6,
    }
    return tuple(
        sorted(
            interfaces,
            key=lambda interface: (
                state_priority[interface.operational_state],
                interface.interface_index,
                interface.stable_id.casefold(),
            ),
        )
    )


def _find_interface(
    enrichment: AdapterEnrichment,
    by_stable_id: dict[str, NetworkInterface],
    by_index: dict[int, NetworkInterface],
) -> NetworkInterface | None:
    if enrichment.stable_id is not None:
        return by_stable_id.get(enrichment.stable_id.casefold())
    if enrichment.interface_index is not None:
        return by_index.get(enrichment.interface_index)
    return None


def _merge_interface(
    interface: NetworkInterface,
    enrichment: AdapterEnrichment,
) -> NetworkInterface:
    is_virtual = interface.is_virtual
    if is_virtual is None:
        is_virtual = enrichment.is_virtual

    kind = interface.kind
    if kind is InterfaceKind.OTHER and is_virtual is True:
        kind = InterfaceKind.VIRTUAL

    administrative_state = interface.administrative_state
    if administrative_state is AdministrativeState.UNKNOWN:
        administrative_state = enrichment.administrative_state

    media_state = interface.media_state
    if media_state is MediaState.UNKNOWN:
        media_state = enrichment.media_state

    return replace(
        interface,
        kind=kind,
        administrative_state=administrative_state,
        media_state=media_state,
        is_virtual=is_virtual,
        is_hidden=enrichment.is_hidden,
        manufacturer=enrichment.manufacturer,
        driver_description=enrichment.driver_description,
        driver_version=enrichment.driver_version,
        receive_link_speed_bps=(
            interface.receive_link_speed_bps or enrichment.receive_link_speed_bps
        ),
        transmit_link_speed_bps=(
            interface.transmit_link_speed_bps or enrichment.transmit_link_speed_bps
        ),
    )
