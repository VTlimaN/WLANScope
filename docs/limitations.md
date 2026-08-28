# Limitations

WLANScope reports evidence observable from one Windows endpoint at a point in time. The following boundaries are part of the intended v1 scope and are important when interpreting results.

## Platform, Privacy, and Driver Support

- Windows 10 and Windows 11 are the only supported operating systems.
- SSID, BSSID, nearby-network, and BSS visibility can depend on Windows location settings, user consent, WLAN service state, adapter state, policy, Windows build, hardware, and driver support.
- Location consent is separate from Administrator access. Elevation does not guarantee access to privacy-controlled wireless data, and WLANScope does not bypass denial.
- Native WLAN can omit optional capability, radio, RSSI, operation-mode, management-frame-protection, or statistics fields.
- NetAdapter and CIM metadata can be unavailable or policy-restricted while primary IP Helper data remains usable.
- Adapter manufacturer, driver, connector, PnP, hidden, virtual, hardware, and cumulative counter fields depend on driver and cmdlet support.
- DHCP lease timestamps are optional CIM enrichment and can remain unavailable when DHCP state and server data are otherwise known.
- Network profile name, category, and IPv4/IPv6 connectivity classifications depend on `Get-NetConnectionProfile`.

WLAN and adapter statistics are cumulative snapshots, not instantaneous throughput measurements. Drivers can omit or stop updating individual counters. Realtime per-link MLO structures, `Get-NetAdapterHardwareInfo`, and vendor-specific advanced properties are deliberately outside the stable cross-version data contract.

## Nearby Wi-Fi

- Nearby scans depend on Windows-managed scan behavior. Windows can deny a scan or withhold available-network or BSS data.
- The radio environment can change between scan completion, available-network retrieval, and BSS retrieval, so results are not atomic.
- Multiple WLAN interfaces can observe the same environment differently; their observations remain distinct.
- Detail views reuse one snapshot. A network or access point can change or disappear immediately afterward.
- Duplicate visible SSIDs and hidden networks are selected by one-based position and interface-specific identity, not by display text alone.
- A hidden network can expose an empty SSID; WLANScope displays it as hidden and does not infer an identity.
- Multiple BSSIDs do not prove a mesh deployment or multi-link operation.
- Information Element parsing intentionally covers a bounded set of documented high-value fields. HE and EHT extension presence is retained without decoding every complex capability payload.

Observation of an unassociated nearby network does not provide its private IP address, subnet, gateway, DNS, DHCP, public IP, ISP, or last-mile technology. WLANScope does not guess these values or use external services to fill them.

### AP Vendor Attribution

- AP vendor attribution requires the optional user-provided IEEE MA-L CSV registry at `%LOCALAPPDATA%\WLANScope\data\oui.csv`.
- The registry is not bundled or downloaded and can be absent, incomplete, stale, or malformed.
- Only validated 24-bit MA-L assignments are covered. Other assignment sizes remain unavailable.
- Locally administered, randomized, or multicast BSSIDs cannot be reliably mapped to a global organization and are reported as not applicable.
- An unknown global BSSID prefix remains unknown rather than being treated as a registry failure.
- Attribution belongs to one BSSID/AP observation and must not be generalized to every AP advertising the same SSID.
- An OUI organization identifies an address-assignment holder; it does not prove the exact AP model, device type, ownership, or current manufacturer.

### Passive WPS Metadata

- WPS detection covers only Vendor Specific Information Elements present in the observed beacon or probe response supplied by Windows WLAN.
- Missing IE data is distinct from an available IE set in which WPS was not observed.
- Absence in one snapshot does not prove historical behavior, hidden configuration, or future advertisements.
- Malformed attributes can yield partial metadata while WPS presence remains known.
- WLANScope does not retrieve or guess a WPS PIN and performs no brute force, exploitation, or vulnerability assessment.
- WPS presence alone is not evidence that an AP is vulnerable.

## Current Network

- Current addresses, routes, profiles, DNS, DHCP, and Wi-Fi state are collected through sequential calls and are not an atomic snapshot.
- Interfaces and associations can change during collection.
- Multiple default routes, including VPN routes, are preserved. WLANScope does not assert one preferred route when effective metrics are missing or tied.
- Connection medium and Windows IPv4/IPv6 connectivity can be observed locally; fiber, cable, DSL, satellite, ISP identity, and other last-mile details cannot be established from the approved sources.
- DNS suffix search policy is not collected. Adapter-specific suffix and registration state can still be available.

## Observed Devices

Observed Devices contains hosts visible from the local endpoint, not every client connected to a router or access point.

- Firewalls, ICMP policy, wireless client isolation, VLAN and subnet boundaries, routing policy, VPNs, host sleep, and network segmentation can reduce visibility.
- No ICMP response does not prove that a host is offline or unreachable by other protocols.
- Neighbor-cache data can be incomplete or stale and can retain observations that are no longer current.
- Active discovery is limited to the routed local IPv4 subnet selected from current routing context. Arbitrary target CIDRs are not accepted.
- Up to 256 usable addresses are allowed by default, 257 through 4,096 require explicit authorization, and larger ranges are refused.
- IPv6 address spaces are not swept. Only IPv6 neighbors already exposed by Windows are included.
- Self, gateway, neighbor router indication, reachability, hostname, and vendor are evidence, not a guessed device type.

## PTR and Device Vendor Enrichment

- PTR records are optional, can be absent or stale, and identify DNS names rather than NetBIOS, mDNS, LLMNR, or DHCP names.
- Resolver timeouts and failures can leave a hostname unavailable without invalidating the observed host.
- Device vendor lookup uses the same optional local IEEE MA-L registry as AP enrichment.
- Locally administered, randomized, multicast, absent, and invalid host MAC addresses are not attributed to a global organization.
- Vendor information does not establish device type, operating system, role, or ownership.

## Snapshots and Reports

- Interactive views are point-in-time; only explicit Refresh collects again. There is no background monitoring.
- Full-scan sections run sequentially and can observe different moments as network or radio state changes.
- Optional or privacy-restricted sources can make a section or full scan partial while preserving useful independent data.
- JSON and Markdown preserve the completed full snapshot, including partial or failed section status; serialization does not make collection atomic.
- JSON schema `1.0` is separate from package versioning.
- Redirected output is deterministic, but diagnostics and partial-result warnings use standard error; pipelines that need them must capture both streams.
- Interactive mode requires terminal input and output. The root command prints help when either stream is redirected.
- Compact layouts omit secondary columns below 100 terminal columns; detail views and reports retain collected data.

Normal reports can expose local identifiers and topology. An anonymized report pseudonymizes supported direct identifiers while intentionally preserving useful technical context and relationships. Vendor, PHY, channel, frequency, timing, count, statistics, status, and correlation patterns can remain.

Pseudonymization is not a formal guarantee of statistical anonymity or safe publication. The mapping is operation-local and not persisted, but public sharing still requires judgment and review.

## Deliberately Excluded

WLANScope does not provide public-IP or ISP lookup, last-mile technology detection, arbitrary network targeting, port or service discovery, banner grabbing, OS fingerprinting, credential or Wi-Fi key access, WPS attacks, packet capture or injection, connection automation, network mutation, exploitation, historical storage, monitoring, or offensive wireless operations.
