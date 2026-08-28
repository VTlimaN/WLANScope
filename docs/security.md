# Security

## Security Model

WLANScope is a defensive, endpoint-local inspection tool. It prefers structured Windows APIs, preserves operating-system privacy decisions, confines active observation to bounded ICMP Echo probes on the selected routed local subnet, and represents unavailable sources explicitly.

The application does not request global Administrator access for convenience, auto-elevate, weaken execution policy, or bypass Windows location consent. Privacy settings, policy, Windows build, or driver support can deny individual sources; independent sources continue where possible.

Unexpected programming errors are not globally suppressed. Expected operational failures become source-aware issues, partial results, or documented exit codes.

## What WLANScope Does

- Reads local interface, address, route, DNS, DHCP, network-profile, and neighbor information.
- Inspects current Wi-Fi association, capabilities, radio state, and cumulative statistics when exposed by Windows.
- Requests a Windows-managed nearby Wi-Fi scan and observes available-network, BSS, beacon, and probe-response metadata.
- Parses selected 802.11 Information Elements with strict buffer and length bounds.
- Observes hosts on the routed local IPv4 subnet through self, gateway, neighbor-cache, and bounded ICMP evidence.
- Includes IPv6 neighbors already reported by Windows without sweeping IPv6 address space.
- Attempts PTR resolution only for already-observed hosts.
- Performs optional vendor attribution from a user-provided local IEEE MA-L CSV registry.
- Generates local JSON and Markdown reports only at user-supplied paths.
- Optionally pseudonymizes supported direct report identifiers for safer sharing.

Nearby Wi-Fi scanning is observational. It does not associate with observed networks or reveal their private IP configuration.

## Passive Wireless Analysis

Beacon and probe-response Information Elements are untrusted wireless input. Native BSS bounds, offsets, and sizes are validated before copying. Parsing is bounded, non-recursive, deterministic, malformed-safe, and tolerant of unknown elements. WLANScope stores selected interpreted metadata rather than full raw IE blobs.

WPS data is parsed passively from observed management-frame metadata supplied by the Windows WLAN stack. WLANScope can report factual advertised fields such as WPS state, setup-lock status, selected registrar, configuration methods, and device metadata. It does not retrieve or guess a PIN, brute-force WPS, execute Pixie Dust, invoke Reaver, generate attack commands, or classify an AP as vulnerable merely because WPS is present.

AP/BSSID vendor attribution reuses the same optional local IEEE MA-L registry as observed-device enrichment. The registry is read locally and never downloaded or queried through a remote API during collection. Locally administered BSSIDs are not assigned a global vendor.

Native WLAN and IP Helper handles and buffers remain inside platform adapters and are released on successful and exceptional paths. Structured PowerShell runs without a user profile or shell, uses fixed scripts and timeouts, and does not change execution policy.

## Report Data Handling

Terminal output and normal reports can contain sensitive local identifiers such as:

- IPv4 and IPv6 addresses and prefixes;
- MAC addresses, SSIDs, and BSSIDs;
- interface, profile, route, gateway, DNS, and DHCP information;
- hostnames, vendor names, observation evidence, and wireless security metadata.

Interactive and command views do not persist this data automatically. JSON and Markdown are written only when explicitly requested. Existing destinations are protected unless overwrite is explicit, parent directories must already exist, and final updates use a temporary file followed by an atomic rename or replacement. WLANScope does not configure destination ACLs; access control, retention, and sharing remain the user's responsibility.

Report anonymization is explicit opt-in pseudonymization of supported direct identifiers. One operation-local mapping is shared when JSON and Markdown are generated together. The original-to-alias mapping is not persisted, and the immutable source snapshot is not modified.

An anonymized report is not a formal guarantee of anonymity. Vendor, radio, timing, count, statistical, status, and relationship data can remain and may support inference. Review sanitized output before public distribution. A normal report retains original identifiers.

Reports do not contain passwords, PSKs, credentials, profile XML, or key material because WLANScope never collects those values. Both report formats consume the same completed `FullNetworkSnapshot` and can preserve partial or failed section status without rerunning collection.

## What WLANScope Does Not Do

WLANScope does not implement:

- password, token, credential, Wi-Fi PSK, plaintext profile-key, or profile-XML extraction;
- password cracking, WPS PIN recovery, WPS attacks, or authentication bypass;
- deauthentication, evil twin, man-in-the-middle, or ARP-poisoning behavior;
- packet capture or injection;
- adapter, route, address, DNS, DHCP, profile, radio, or other network mutation;
- automated Wi-Fi connection or disconnection;
- arbitrary CIDR targeting or IPv6 address-space sweeping;
- port scanning, service discovery, banner grabbing, TTL guessing, or OS fingerprinting;
- exploit or attack-command automation, persistence, or malware behavior;
- AP client enumeration for attack planning;
- public-IP, ISP, last-mile, geolocation, WHOIS, or external MAC-vendor lookup;
- report upload, synchronization, or transmission.

No ICMP response is interpreted as proof that a host is offline. Host sleep, filtering, client isolation, segmentation, and topology can suppress a response.

## Authorized Use

Use WLANScope only on systems and networks you are authorized to inspect.
