# Windows Agent proxy configuration foundation

## Scope and mechanism

This foundation manages the machine-wide WinHTTP default proxy. WinHTTP is the minimum safe scope for a Windows service running as `NT AUTHORITY\LocalService`; it supports system services without impersonating an interactive user. It does not configure WinINET, PAC files, browsers, or user profiles. Browser proxy coverage requires a separately designed, least-privilege user-context component and is intentionally outside this module.

The management client uses a dedicated HTTP handler with operating-system proxy discovery disabled. Consequently, the agent-to-management API path never depends on the configured explicit proxy and remains available for recovery when that proxy is down. TLS certificate validation remains the platform default and cannot be disabled by proxy configuration.

## Desired configuration and validation

An administrator stores `disabled` or `configured` state per device. Enabled state requires a validated hostname/IP token, port 1–65535, at most 64 validated bypass entries, and a positive monotonic version. Shell metacharacters, whitespace, URL schemes, semicolons, unsupported modes, and partial configurations are rejected before Windows is changed. Values are passed directly to the WinHTTP API—no shell, PowerShell, `netsh`, arbitrary registry path, or command interpolation is used.

The agent retrieves only its own configuration using its enrolled credential. Heartbeats report desired/applied versions, state, drift, bounded error text, effective host/port, and only a bypass count. Credentials and authorization headers are never part of proxy state or logs.

## Baseline, apply, drift, and recovery

Before the first proxy operation, the agent captures the original WinHTTP state into protected ProgramData as `proxy-baseline.json`. Atomic creation prevents normal restarts from overwriting it. Existing agent directory ACLs protect this non-secret but security-relevant state from ordinary-user modification.

For configured state, the agent writes `host:port` and the validated semicolon-delimited bypass list through `WinHttpSetDefaultProxyConfiguration`. Identical desired/applied versions and matching state cause no write. Drift is checked at the normal heartbeat interval; a mismatch is reported and restored once during that bounded reconciliation cycle, without a tight enforcement loop.

If retrieval fails, the last successful configuration remains untouched. Apply failures keep the service alive, preserve the previous applied version, and are reported on heartbeat. Disabling management restores the captured baseline. Controlled uninstall stops the service, restores the baseline, and aborts safely if restoration fails before removing binaries. Identity retention and `-RemoveIdentity` behavior otherwise remain unchanged.

## Known limitations

- WinINET and browser-user proxy settings are not managed.
- This is configured-state reconciliation, not tamper-resistant enforcement.
- No proxy credentials, PAC, TLS inspection, URL filtering, or production traffic routing is included.
- Real-VM validation must use a controlled non-production proxy endpoint and must restore the baseline before closure.
