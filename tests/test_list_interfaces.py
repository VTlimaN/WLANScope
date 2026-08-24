from wlanscope.application.list_interfaces import ListNetworkInterfaces
from wlanscope.domain.interfaces import (
    AdapterEnrichment,
    AdministrativeState,
    InterfaceCollectionError,
    InterfaceEnrichmentError,
    InterfaceKind,
    MacAddress,
    MediaState,
    NetworkInterface,
    OperationalState,
)


def test_enrichment_merges_by_stable_identifier() -> None:
    primary = _interface(7)
    inventory = ListNetworkInterfaces(
        StaticPrimaryCollector((primary,)),
        StaticEnrichmentCollector(
            (
                AdapterEnrichment(
                    stable_id=primary.stable_id,
                    interface_index=99,
                    manufacturer="Example Networks",
                    driver_version="1.2.3",
                ),
            )
        ),
    ).execute()

    assert inventory.interfaces[0].manufacturer == "Example Networks"
    assert inventory.interfaces[0].driver_version == "1.2.3"


def test_interface_without_enrichment_is_preserved() -> None:
    inventory = ListNetworkInterfaces(
        StaticPrimaryCollector((_interface(7),)),
        StaticEnrichmentCollector(()),
    ).execute()

    assert inventory.interfaces == (_interface(7),)


def test_extra_enrichment_is_not_added_to_primary_inventory() -> None:
    inventory = ListNetworkInterfaces(
        StaticPrimaryCollector((_interface(7),)),
        StaticEnrichmentCollector(
            (
                AdapterEnrichment(
                    stable_id="bbbbbbbb-0000-0000-0000-000000000002",
                    interface_index=18,
                    manufacturer="Unmatched Adapter",
                ),
            )
        ),
    ).execute()

    assert len(inventory.interfaces) == 1
    assert inventory.interfaces[0].manufacturer is None


def test_conflicting_lower_priority_data_does_not_replace_primary_data() -> None:
    primary = _interface(
        7,
        administrative_state=AdministrativeState.UP,
        media_state=MediaState.CONNECTED,
        receive_link_speed_bps=1_000_000_000,
    )
    enrichment = AdapterEnrichment(
        stable_id=primary.stable_id,
        interface_index=primary.interface_index,
        administrative_state=AdministrativeState.DOWN,
        media_state=MediaState.DISCONNECTED,
        receive_link_speed_bps=100_000_000,
    )

    merged = (
        ListNetworkInterfaces(
            StaticPrimaryCollector((primary,)),
            StaticEnrichmentCollector((enrichment,)),
        )
        .execute()
        .interfaces[0]
    )

    assert merged.administrative_state is AdministrativeState.UP
    assert merged.media_state is MediaState.CONNECTED
    assert merged.receive_link_speed_bps == 1_000_000_000


def test_interfaces_are_sorted_by_state_then_index() -> None:
    interfaces = (
        _interface(18, operational_state=OperationalState.DOWN),
        _interface(21, operational_state=OperationalState.UP),
        _interface(7, operational_state=OperationalState.UP),
    )

    inventory = ListNetworkInterfaces(StaticPrimaryCollector(interfaces)).execute()

    assert [interface.interface_index for interface in inventory.interfaces] == [7, 21, 18]


def test_enrichment_failure_returns_primary_inventory_with_warning() -> None:
    inventory = ListNetworkInterfaces(
        StaticPrimaryCollector((_interface(7),)),
        FailingEnrichmentCollector(),
    ).execute()

    assert len(inventory.interfaces) == 1
    assert inventory.is_partial
    assert inventory.warnings == ("Adapter enrichment unavailable",)


def test_primary_failure_is_not_suppressed() -> None:
    use_case = ListNetworkInterfaces(FailingPrimaryCollector())

    try:
        use_case.execute()
    except PrimaryCollectionFailure as error:
        assert str(error) == "Primary collection unavailable"
    else:
        raise AssertionError("Primary collector failure was suppressed")


class StaticPrimaryCollector:
    def __init__(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        self._interfaces = interfaces

    def collect(self) -> tuple[NetworkInterface, ...]:
        return self._interfaces


class StaticEnrichmentCollector:
    def __init__(self, enrichments: tuple[AdapterEnrichment, ...]) -> None:
        self._enrichments = enrichments

    def collect(self) -> tuple[AdapterEnrichment, ...]:
        return self._enrichments


class FailingEnrichmentCollector:
    def collect(self) -> tuple[AdapterEnrichment, ...]:
        raise InterfaceEnrichmentError("Adapter enrichment unavailable")


class PrimaryCollectionFailure(InterfaceCollectionError):
    pass


class FailingPrimaryCollector:
    def collect(self) -> tuple[NetworkInterface, ...]:
        raise PrimaryCollectionFailure("Primary collection unavailable")


def _interface(
    interface_index: int,
    operational_state: OperationalState = OperationalState.UP,
    administrative_state: AdministrativeState = AdministrativeState.UP,
    media_state: MediaState = MediaState.CONNECTED,
    receive_link_speed_bps: int | None = 1_000_000_000,
) -> NetworkInterface:
    suffix = f"{interface_index:012d}"
    return NetworkInterface(
        interface_index=interface_index,
        stable_id=f"aaaaaaaa-0000-0000-0000-{suffix}",
        alias=f"Adapter {interface_index}",
        friendly_name=f"Adapter {interface_index}",
        description="Sanitized adapter",
        windows_interface_type=6,
        kind=InterfaceKind.ETHERNET,
        operational_state=operational_state,
        administrative_state=administrative_state,
        media_state=media_state,
        mac_address=MacAddress.from_text("02:00:00:00:00:01"),
        mtu=1500,
        receive_link_speed_bps=receive_link_speed_bps,
        transmit_link_speed_bps=1_000_000_000,
        is_hardware=True,
    )
