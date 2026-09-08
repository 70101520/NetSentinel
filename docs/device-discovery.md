# Device discovery foundation

NetSentinel scans only administrator-configured RFC1918 IPv4 CIDRs. A canonical CIDR, bounded host count, bounded concurrency, short timeout, and an explicit port list prevent the discovery interface from becoming an unrestricted network scanner. Public, documentation, IPv6, oversized, and malformed ranges are rejected.

The foundation uses non-invasive TCP connection probes. An accepted or refused connection establishes reachability; timeouts do not. Reverse DNS and observed open ports are informational and never used as strong identity. Discovery does not perform credentialed probing, vulnerability scanning, packet capture, OS fingerprinting, or firewall modification.

Discovered observations are stored separately from enrolled devices. Exact current IP association can label an observation as agent-installed, but it does not merge, delete, or change an enrolled device identity. MAC and DHCP enrichment across routed VLANs requires a later authenticated pfSense connector; missing data is shown as unknown rather than invented.

Administrators can register named private networks, attach VLAN/site labels, set a future scheduling interval, and run a bounded scan manually. Inter-VLAN routing and narrowly scoped firewall policy remain external prerequisites. This module does not implement proxy enforcement, URL filtering, bandwidth control, TLS inspection, or automatic pfSense changes.
