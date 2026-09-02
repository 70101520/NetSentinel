# Windows agent architecture

The agent is a signed Windows service running under a least-privilege service identity. A small privileged helper owns only approved proxy-setting operations through a versioned local IPC contract and restrictive ACL. There is no hidden process or malware-like persistence.

Enrollment uses a short-lived one-time token to establish a unique device identity and certificate. Credentials are non-exportable where TPM/CNG permits, rotated before expiry, and revocable server-side. Heartbeats contain monotonically increasing sequence numbers and report hostname, user, interfaces, OS, boot time, gateway, DNS, proxy state, and version. Server receipt time determines liveness; ping is only supplemental evidence.

Desired proxy state is signed/versioned. Drift remediation is administrator-configurable, excludes declared internal destinations, creates an alert, and records before/after audit evidence. Uninstall, protection disablement, and server changes require authorized signed commands and remain visible in Windows and central audit logs.
