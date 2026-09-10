# NetSentinel Windows Agent service foundation

This directory contains enrollment, machine-bound identity/credential persistence, authenticated heartbeat, recovery scheduling, bounded diagnostics, reproducible service installation, and the WinHTTP proxy-configuration foundation. It does not enforce browser proxy settings, inspect traffic, inventory software, implement tamper protection, or expose a local control port. Proxy scope, baseline restoration, management-plane bypass, and limitations are documented in `docs/windows-agent-proxy-configuration.md`.

## Runtime and service model

The agent is a self-contained .NET 8 Windows Worker Service (`win-x64`) hosted by the Windows Service Control Manager as `NetSentinelAgent`. SCM configures automatic startup and bounded recovery restarts. The Generic Host passes SCM stop/shutdown into a cancellation token, and all waits are cancellable. The current service runs as `NT AUTHORITY\LocalService`; this foundation requires outbound HTTP(S), read-only machine/network/session metadata, and write access only to its protected ProgramData directory. It does not request LocalSystem, administrator, debug, driver, firewall, or impersonation privileges.

Versioning follows SemVer. This release reports `0.7.0`. CI produces both the self-contained binary bundle and a Windows Setup executable. Remote unattended update is intentionally absent.

## Local security model

`%ProgramData%\NetSentinel\Agent` is ACL-restricted to SYSTEM, Administrators, and LocalService. The stable random installation UUID and non-secret diagnostic state live in `state.json`. The issued agent credential and temporary enrollment token are separate DPAPI `LocalMachine` blobs with application entropy. The directory ACL is essential because machine-scope DPAPI alone does not authorize callers.

The normal Setup workflow does not require an enrollment token. It generates a random local pairing secret, stores it with machine-scope DPAPI, and sends it only in the enrollment request body; the server retains only its derived hash. The endpoint remains pending until an administrator explicitly approves its hostname, IP address, and pairing code on the portal Agents page. Only that endpoint can claim the resulting credential. The credential is saved before the temporary pairing secret is deleted. Raw pairing secrets, credentials, and authentication headers are never shown in the portal or logged. Uninstall retains identity by default to prevent accidental duplicate enrollment; `-RemoveIdentity` explicitly removes local state and secrets. Neither mode deletes server inventory/history.

## Build, install, and diagnostics

Download the `NetSentinel-Agent-Setup-win-x64` artifact from a successful CI run and start the Setup executable as an administrator. Enter the NetSentinel server URL. Monitoring is always selected; optionally select Full control and blocking. HTTP can be selected only for a controlled test lab; production enrollment requires HTTPS. After Setup completes, approve the matching pending computer on **Agents** in the portal. The service claims its credential and begins heartbeat reporting automatically.

The legacy `install-agent.ps1` token workflow remains available only for controlled recovery and automated validation. Administrators can query the installed service with `Get-Service NetSentinelAgent`; ordinary end users do not need to run commands.

Upgrade an existing enrolled service with `./update-agent.ps1 -SourceDirectory ./publish` from elevated PowerShell. The update preserves ProgramData identity and DPAPI credentials, never requires a new enrollment token, and restores the previous binaries if the service cannot restart.

For a controlled HTTP-only LAN test, installation additionally requires `-AllowHttp`; certificate validation is never disabled. Configure the Windows machine to trust the organizational/public CA for production HTTPS.

Logs roll daily or at 10 MiB and retain at most 14 files. Status contains only enrollment state, device ID, reachability, timestamps, failure count, and version.

Uninstall with `.\uninstall-agent.ps1`; identity is retained. Use `-RemoveIdentity` only to deliberately remove protected state and credentials.

## Scheduling and recovery

The normal online heartbeat interval is 5 seconds. Network rates use one default-route adapter and carry their measured sample window and adapter name. The portal refreshes agent state every 5 seconds and the server declares an abruptly disconnected endpoint offline after four missed heartbeats (20 seconds). A graceful Windows service stop also sends a bounded authenticated offline notification. Transient HTTP, timeout, DNS, and network failures use 5, 15, 30, then 60-second bounded backoff. Every delay receives ±15% jitter. Success returns to the normal interval. HTTP 401/403 marks `CredentialInvalid`, stops retries, and requires administrator recovery; revocation is never bypassed.

Heartbeat contains only approved bounded foundation data, including current CPU, memory, fixed-disk and selected default-route-interface throughput measurements. Interactive username is read through Windows Terminal Services without impersonation or access to user content.

## Tests and validation

`dotnet test NetSentinel.Agent.sln -c Release` covers identity/state reuse, corrupt state, DPAPI storage, pairing-secret lifecycle, pairing response handling, bootstrap-token lifecycle, heartbeat success/revocation/transient classification, and DNS/network failure. GitHub Actions builds, tests, compiles the Setup executable, and publishes both artifacts on `windows-latest`.

Before production recommendation, use a dedicated Windows VM for install/enroll, portal visibility, service restart, reboot/automatic start, unchanged identity, API outage/recovery, revocation, standard-user ACL denial, secret scans, idle/heartbeat CPU and RAM, log growth, and clean uninstall. Record actual evidence; never infer Windows reboot or performance results from CI.
