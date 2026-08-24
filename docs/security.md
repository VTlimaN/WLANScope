# Security

## Authorized use

WLANScope is designed for defensive visibility, network inventory, diagnostics, Blue Team workflows, and security engineering on systems and networks owned by the user or covered by explicit authorization.

Users are responsible for obtaining authorization and complying with applicable policies and laws before collecting network information.

## Privilege model

The application will collect the maximum useful information available to a normal Windows user. It will not request global Administrator access for convenience, autoelevate, or weaken operating-system controls. A collector that lacks permission will report that limitation and allow independent work to continue.

Windows location consent is distinct from Administrator access. WLANScope will respect location privacy decisions and will not attempt to bypass them.

## Prohibited capabilities

WLANScope will not implement:

- credential or token extraction;
- stored PSK or Wi-Fi key extraction;
- password cracking;
- deauthentication;
- evil twin automation;
- ARP poisoning or man-in-the-middle behavior;
- packet injection;
- exploit automation;
- persistence or malware behavior;
- authentication or access-control bypass.

The approved v1 scope also excludes port scanning and service exploitation.

## Sensitive output

The current adapters command may display local interface names and MAC addresses in the terminal. It does not persist this inventory automatically.

Future reports may contain internal hostnames, IP addresses, MAC addresses, SSIDs, BSSIDs, routes, adapter details, and other infrastructure metadata. Users must protect, retain, and share these reports according to their organization's data-handling requirements.

Reports will be created only when explicitly requested and will not contain credentials or Wi-Fi secrets.

## Reporting vulnerabilities

Security vulnerabilities should be reported privately to the project maintainer when a private reporting channel becomes available. Public reports should not include credentials, sensitive network captures, or identifying infrastructure data.
