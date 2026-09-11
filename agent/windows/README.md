# NetSentinel Windows Agent service foundation

This directory contains enrollment, machine-bound identity/credential persistence, authenticated heartbeat, recovery scheduling, bounded diagnostics, browser and WinHTTP proxy enforcement, an administrator Agent Settings UI, and signed maintenance commands. Full-control mode applies mandatory Edge, Chrome and Firefox proxy policy plus machine WinINET/WinHTTP state; HTTPS visibility remains destination-domain only and does not decrypt content.

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

## Free internal lab code signing

This is private organizational trust, not a publicly trusted certificate. Generate the stable lab certificate once on a controlled Windows administrator workstation:

```powershell
.\signing\New-NetSentinelLabSigningCertificate.ps1
```

The ignored `certificates/netsentinel-lab` directory contains the private PFX and two files used to create the repository secrets `NETSENTINEL_LAB_SIGNING_PFX_BASE64` and `NETSENTINEL_LAB_SIGNING_PASSWORD`. Never commit, upload as an artifact, email, or place those private files on the portal. After both GitHub Actions secrets are configured, CI signs the published Agent executable and Inno Setup executable with the same identity, verifies both signatures, publishes `SHA256SUMS.txt` with Setup, and publishes the safe public `.cer` as a separate trust-certificate artifact.

The generator restricts this directory to the current Windows user, SYSTEM, and local Administrators, and refuses to overwrite existing signing material unless an intentional `-Force` rotation is requested.

CI publishes the safe public certificate separately as `NetSentinel-Lab-Trust-Certificate`, so it can be downloaded and trusted before downloading the executable artifact. Before running a lab-signed installer, distribute that `.cer` through a trusted administrator channel and trust it on each managed test endpoint:

```powershell
.\signing\Install-NetSentinelLabTrust.ps1 -CertificatePath .\NetSentinel-Lab-Code-Signing.cer
```

Review and accept the confirmation prompt. For domain computers, deploy the same public certificate using Group Policy to **Trusted Root Certification Authorities** and **Trusted Publishers**. Never deploy the private PFX. Public/unmanaged distribution still requires a certificate from a public trust provider.

Logs roll daily or at 10 MiB and retain at most 14 files. Status contains only enrollment state, device ID, reachability, timestamps, failure count, and version.

Interactive uninstall is gated by the per-device password or current one-time recovery code configured in the portal. The password and recovery code are never stored: the server and Agent receive only PBKDF2-SHA256 verifiers. Portal remote uninstall is a ten-minute device-scoped HMAC-signed command, verified by the LocalService Agent and again by the separate LocalSystem maintenance broker before proxy restoration and removal. The main monitoring Agent remains LocalService.

The protection boundary is standard Windows users and non-elevated processes. A trusted local Windows administrator ultimately controls the machine and cannot be made cryptographically subordinate to an endpoint application without a separately managed EDR/tamper-protection trust root.

## Scheduling and recovery

The normal online heartbeat interval is 5 seconds. Network rates use one default-route adapter and carry their measured sample window and adapter name. The portal refreshes agent state every 5 seconds and the server declares an abruptly disconnected endpoint offline after four missed heartbeats (20 seconds). A graceful Windows service stop also sends a bounded authenticated offline notification. Transient HTTP, timeout, DNS, and network failures use 5, 15, 30, then 60-second bounded backoff. Every delay receives ±15% jitter. Success returns to the normal interval. HTTP 401/403 marks `CredentialInvalid`, stops retries, and requires administrator recovery; revocation is never bypassed.

Heartbeat contains only approved bounded foundation data, including current CPU, memory, fixed-disk and selected default-route-interface throughput measurements. Interactive username is read through Windows Terminal Services without impersonation or access to user content.

## Tests and validation

`dotnet test NetSentinel.Agent.sln -c Release` covers identity/state reuse, corrupt state, DPAPI storage, pairing-secret lifecycle, pairing response handling, bootstrap-token lifecycle, heartbeat success/revocation/transient classification, and DNS/network failure. GitHub Actions builds, tests, compiles the Setup executable, and publishes both artifacts on `windows-latest`.

Before production recommendation, use a dedicated Windows VM for install/enroll, portal visibility, service restart, reboot/automatic start, unchanged identity, API outage/recovery, revocation, standard-user ACL denial, secret scans, idle/heartbeat CPU and RAM, log growth, and clean uninstall. Record actual evidence; never infer Windows reboot or performance results from CI.
