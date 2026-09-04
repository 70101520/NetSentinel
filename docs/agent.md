# Windows agent architecture

The agent is a signed Windows service running under a least-privilege service identity. A small privileged helper owns only approved proxy-setting operations through a versioned local IPC contract and restrictive ACL. There is no hidden process or malware-like persistence.

The current server foundation uses a short-lived, maximum-use enrollment token to establish a unique installation ID, agent identity, and per-device credential. Only keyed SHA-256 derivatives are stored. Enrollment tokens can be listed as metadata and revoked; endpoints can be revoked without deleting inventory or history; an administrator can rotate a device credential. A duplicate installation ID is rejected with HTTP 409 and requires explicit administrative recovery. Enrollment token creation/revocation, endpoint revocation, credential rotation, and assignment changes are audited. Routine heartbeats are not administrative audit events.

Heartbeats report the bounded foundation fields: hostname, user, interfaces, OS, boot time, gateway, DNS, uptime, and agent version. Server receipt time determines liveness. A bounded background evaluator uses the `(current_status, last_heartbeat)` index, row locking with `SKIP LOCKED`, and a configurable batch size to transition stale ONLINE devices to OFFLINE. A later valid heartbeat creates one OFFLINE-to-ONLINE transition; routine online refreshes do not create transition rows.

`loadtest/agent_simulator.py` is test tooling, not the production Windows Agent. It writes device identities and raw test credentials to an ignored state file with owner-only permissions where supported. Protect and delete that file after recovery/endurance testing. A later invocation using the same `--state-file` resumes heartbeat without enrollment.

Desired proxy state is signed/versioned. Drift remediation is administrator-configurable, excludes declared internal destinations, creates an alert, and records before/after audit evidence. Uninstall, protection disablement, and server changes require authorized signed commands and remain visible in Windows and central audit logs.
