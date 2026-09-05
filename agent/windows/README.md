# NetSentinel Windows Agent service foundation

This directory contains enrollment, machine-bound identity/credential persistence, authenticated heartbeat, recovery scheduling, bounded diagnostics, reproducible service installation, and the WinHTTP proxy-configuration foundation. It does not enforce browser proxy settings, inspect traffic, inventory software, implement tamper protection, or expose a local control port. Proxy scope, baseline restoration, management-plane bypass, and limitations are documented in `docs/windows-agent-proxy-configuration.md`.

## Runtime and service model

The agent is a self-contained .NET 8 Windows Worker Service (`win-x64`) hosted by the Windows Service Control Manager as `NetSentinelAgent`. SCM configures automatic startup and bounded recovery restarts. The Generic Host passes SCM stop/shutdown into a cancellation token, and all waits are cancellable. The current service runs as `NT AUTHORITY\LocalService`; this foundation requires outbound HTTP(S), read-only machine/network/session metadata, and write access only to its protected ProgramData directory. It does not request LocalSystem, administrator, debug, driver, firewall, or impersonation privileges.

Versioning follows SemVer. This foundation reports `0.1.0`. A self-contained, versioned publish directory leaves a future signed installer/update boundary, but remote update is intentionally absent.

## Local security model

`%ProgramData%\NetSentinel\Agent` is ACL-restricted to SYSTEM, Administrators, and LocalService. The stable random installation UUID and non-secret diagnostic state live in `state.json`. The issued agent credential and temporary enrollment token are separate DPAPI `LocalMachine` blobs with application entropy. The directory ACL is essential because machine-scope DPAPI alone does not authorize callers.

The installer sends the enrollment token through standard input, never a command-line argument. After successful enrollment the credential is saved first, state is committed, and the protected bootstrap token is deleted. A failed connection leaves the protected token available for controlled retry. Raw tokens, credentials, and authentication headers are never logged. Uninstall retains identity by default to prevent accidental duplicate enrollment; `-RemoveIdentity` explicitly removes local state and secrets. Neither mode deletes server inventory/history.

## Build, install, and diagnostics

```powershell
.\publish.ps1
.\install-agent.ps1 -ServerUrl https://netsentinel.example.org -EnrollmentToken $token
Get-Service NetSentinelAgent
& "$env:ProgramFiles\NetSentinel\Agent\NetSentinel.Agent.exe" status
```

For a controlled HTTP-only LAN test, installation additionally requires `-AllowHttp`; certificate validation is never disabled. Configure the Windows machine to trust the organizational/public CA for production HTTPS.

Logs roll daily or at 10 MiB and retain at most 14 files. Status contains only enrollment state, device ID, reachability, timestamps, failure count, and version.

Uninstall with `.\uninstall-agent.ps1`; identity is retained. Use `-RemoveIdentity` only to deliberately remove protected state and credentials.

## Scheduling and recovery

The server heartbeat interval is honored subject to the local minimum. Transient HTTP, timeout, DNS, and network failures use 5, 15, 30, then 60-second bounded backoff. Every delay receives ±15% jitter. Success returns to the normal interval. HTTP 401/403 marks `CredentialInvalid`, stops retries, and requires administrator recovery; revocation is never bypassed.

Heartbeat contains only approved bounded foundation data. Interactive username is read through Windows Terminal Services without impersonation or access to user content.

## Tests and validation

`dotnet test NetSentinel.Agent.sln -c Release` covers identity/state reuse, corrupt state, DPAPI storage, bootstrap-token lifecycle, heartbeat success/revocation/transient classification, and DNS/network failure. GitHub Actions builds, tests, and publishes on `windows-latest`.

Before production recommendation, use a dedicated Windows VM for install/enroll, portal visibility, service restart, reboot/automatic start, unchanged identity, API outage/recovery, revocation, standard-user ACL denial, secret scans, idle/heartbeat CPU and RAM, log growth, and clean uninstall. Record actual evidence; never infer Windows reboot or performance results from CI.
