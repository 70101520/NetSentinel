# Endpoint control modes

NetSentinel uses one Windows Agent binary with two server-authoritative operating modes.

## Monitoring only

`MONITOR_ONLY` is the default and fail-safe mode. The agent continues authenticated heartbeat, health, CPU, memory, disk, and network telemetry. NetSentinel returns an effective disabled proxy configuration, and the agent restores only the WinHTTP baseline it captured before NetSentinel management. Endpoint Internet traffic continues through its normal pfSense/LAN path.

## Web controlled

`WEB_CONTROLLED` allows a valid per-device proxy configuration to become effective. The installer records a requested mode, but the portal administrator confirms it during pairing approval. Later mode changes require the `agents.manage` permission and are audited. Changing mode increments desired proxy state so an online agent reconciles promptly.

This mode is a control-plane foundation, not a claim of complete browser enforcement. The current Windows component manages WinHTTP only. Production web control additionally requires the managed filtering gateway, browser/user proxy coverage, and pfSense anti-bypass rules for the controlled endpoint scope. Direct TCP 80/443 and UDP 443 bypass must be addressed while allowing the management API, DNS, NTP, internal services, and the gateway. TLS interception is not enabled; HTTPS filtering is limited to host/domain information until a separately approved certificate lifecycle exists.

## Safety rules

- Unknown networks are never enrolled or controlled automatically.
- A local installer choice cannot change an already enrolled endpoint's authoritative server mode.
- Missing or invalid web-gateway configuration leaves proxy state disabled.
- Monitoring remains available in either mode.
- Mode changes and proxy configuration changes are separate audited actions.