# Security

## Authorized use

WLANScope is designed for defensive visibility, network inventory, diagnostics, Blue Team workflows, and security engineering on systems and networks owned by the user or covered by explicit authorization.

Users are responsible for obtaining authorization and complying with applicable policies and laws before collecting network information.

## Privilege model

The application will collect the maximum useful information available to a normal Windows user. It will not request global Administrator access for convenience, autoelevate, or weaken operating-system controls. A collector that lacks permission will report that limitation and allow independent work to continue.

Windows location consent is distinct from Administrator access. WLANScope will respect location privacy decisions and will not attempt to bypass them.

The current Wi-Fi command reads non-secret profile and connection metadata through the Native WLAN API. An access-denied result is reported without falling back to a mechanism intended to evade Windows privacy controls.

Nearby Wi-Fi discovery is passive, read-only observation after a Windows-managed scan request. It does not bypass location restrictions, deauthenticate clients, connect or disconnect networks, modify profiles, or request profile key material.

Current network analysis is read-only. WLANScope does not create or remove addresses or routes, change metrics or DNS servers, renew DHCP leases, or modify adapter configuration.

Local device discovery is confined to the IPv4 subnet selected from the host's default routing context. It reads the Windows neighbor cache and sends only bounded ICMP Echo requests. It does not accept arbitrary target CIDRs. Ranges above 256 usable addresses require an explicit command-line authorization, and ranges above 4,096 are refused. IPv6 is not swept.

Device enrichment sends PTR queries only for hosts already observed by local discovery. It does not brute-force DNS names, enumerate zones, use NetBIOS, LLMNR, or mDNS, or initiate service discovery. Vendor lookup reads an optional local registry once per execution and never calls an external MAC service for each host.

## Prohibited capabilities

WLANScope will not implement:

- credential or token extraction;
- stored PSK or Wi-Fi key extraction;
- password cracking;
- deauthentication;
- evil twin automation;
- ARP poisoning or man-in-the-middle behavior;
- packet injection;
- port or service scanning;
- exploit automation;
- persistence or malware behavior;
- authentication or access-control bypass.

The approved v1 scope also excludes port scanning and service exploitation.

## Sensitive output

The adapters, Wi-Fi, and devices commands may display local interface names, MAC addresses, SSIDs, BSSIDs, security metadata, profile names, PTR hostnames, and vendor organizations in the terminal. They do not persist this information automatically and never request profile key material or credentials.

Future reports may contain internal hostnames, IP addresses, prefixes, gateways, DNS and DHCP servers, MAC addresses, SSIDs, BSSIDs, routes, adapter details, and other infrastructure topology metadata. Users must protect, retain, and share these reports according to their organization's data-handling requirements.

Reports will be created only when explicitly requested and will not contain credentials or Wi-Fi secrets.

## Reporting vulnerabilities

Security vulnerabilities should be reported privately to the project maintainer when a private reporting channel becomes available. Public reports should not include credentials, sensitive network captures, or identifying infrastructure data.
