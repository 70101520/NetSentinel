# Windows Agent installed-service validation gate

Validation date: 2026-09-05. Branch: `feature/windows-agent-service-foundation`.

## Environment and installation

- Target: controlled VMware Windows test VM, not production.
- Windows 10 Pro 10.0.19045 build 19045, 64-bit; 2 logical processors; 2 GiB RAM.
- Agent 0.1.0 self-contained `win-x64`; no machine .NET runtime was installed.
- Authenticated remote session was an elevated local Administrator.
- Fresh baseline had no NetSentinel service, Program Files directory, or ProgramData state.
- The official installer registered `NetSentinelAgent` as Running, Automatic, `NT AUTHORITY\LocalService`, with binary `C:\Program Files\NetSentinel\Agent\NetSentinel.Agent.exe`.
- Machine execution policy remained unchanged (`Undefined` machine policy, effective `Restricted`). The unsigned lab script was invoked with a process-only bypass. Production packaging should be signed.
- SCM recovery actions are restart after 5, 15, and 60 seconds, resetting after 86400 seconds.

## Enrollment, secrets, identity, and status

- First installed-service enrollment succeeded and created exactly one matching online record. Local and server device IDs matched.
- Initial installation ID was `56ebe684-869b-4885-ab94-c756f88653fe`; initial device ID was `17937183-9aa0-441a-9751-2daca9b063ca`.
- `credential.dpapi` existed as a non-plaintext 310-byte blob; `bootstrap.dpapi` was removed after enrollment.
- ProgramData inheritance was disabled and access was limited to SYSTEM, Administrators, and LocalService. Ordinary-user principals had no data-directory access rule. Ordinary users had read/execute but no write rule on the executable.
- Configuration contained only server URL and explicit lab `AllowHttp`; logs/config contained no credential header, bearer token, password, token, credential, or secret field.
- Status reported only service guidance, enrollment, device ID, server state, heartbeat/success timestamps, failure count, and agent version.

## Restart and reboot

- Graceful SCM stop reached Stopped; start returned Running. Identity was unchanged, heartbeat resumed, failures remained zero, and no duplicate enrollment occurred.
- A real Windows reboot was observed (down then WinRM return). Boot time changed to 2026-09-05 13:57:40 local time.
- Without interactive login, SCM automatically started the service as LocalService. Installation/device identity remained unchanged and portal status returned online.

## Failure and recovery behavior

- Two Windows Firewall outage attempts were invalid because all firewall profiles were already disabled on the test VM. No firewall profile was enabled or weakened for validation, and both temporary rules were removed.
- A real server-side PostgreSQL stop produced API HTTP 503 for 126.6 seconds. The service and process stayed stable, reached five bounded failures, marked the server unreachable, remained Enrolled, retained identity/credential, did not create a bootstrap token, and did not re-enroll.
- During 503 retry: average CPU 0.104%, peak CPU 0.938%; RAM 26.3 MiB start, 28.92 MiB peak, 23.8 MiB end.
- After PostgreSQL health returned, the same identity automatically returned Reachable with zero failures and resumed heartbeat. The portal returned the current device online.
- DNS failure was not applicable because the controlled management URL used an IP address.
- Endpoint revocation produced `CredentialInvalid` in 30.1 seconds, one failure, and one rejection log. The service/process remained stable and did not continue a retry storm during the following 90 seconds.

## Stability and performance

- Installed-service endurance duration: 30.01 minutes, 61 samples at 30-second cadence.
- One process ID throughout; service always Running; maximum heartbeat failures zero.
- Idle/normal average CPU 0.048%; peak CPU 1.094%.
- Working set: 19.69 MiB start, 30.45 MiB peak, 14.46 MiB end (growth -5.22 MiB).
- Private memory: 13.32 MiB start, 18.36 MiB peak, 15.12 MiB end.
- Separate 75-second heartbeat window: average CPU 0.042%, peak CPU 3.125%; RAM 43.37 MiB start/peak and 21.37 MiB end.
- No process restart, memory-growth indication, or healthy-condition heartbeat failure was observed.

## Uninstall, reinstall, and recovery

- Official default uninstall removed the service, process, and binaries while retaining state/credential. Server device history remained REVOKED.
- Default reinstall intentionally reused the retained identity and revoked credential, remained `CredentialInvalid`, and did not silently bypass revocation or re-enroll. Its unused bootstrap token was revoked server-side.
- Explicit `-RemoveIdentity` removed local agent state. Controlled reinstall enrolled installation `f59bb49c-9a38-453f-8530-006a363d5cd4` as device `2a07f213-c214-47bc-ac89-556e3f21672a`, removed bootstrap state, and returned online.
- The server intentionally contains two records for the hostname: one preserved revoked historical identity and one current online identity.

## Logs, Windows events, TLS, and access limitations

- Logs roll daily or at 10 MiB and retain 14 files. Current log size was 1991 bytes; the 10 MiB rollover threshold was not artificially reached, so physical rollover remains unobserved.
- Three Service Control Manager 7045 informational installation events were present. No matching Application error event was found.
- The lab endpoint was HTTP-only and required explicit `AllowHttp`. No certificate validation bypass exists. Trusted-certificate success and untrusted-certificate rejection remain production deployment prerequisites.
- ACLs demonstrate that ordinary users cannot read/write ProgramData secrets or modify binaries. A separate standard-user interactive sign-in was not performed.
- Windows Firewall profiles were already disabled independently of NetSentinel and remain a lab-machine security risk.

## Administrator recovery and repository validation

- Added console-only `reset-admin-password EMAIL`: hidden double prompt, 14-character minimum, existence check, Argon2id replacement, lockout clearing, and password-free audit event.
- Tests cover success, missing account, short value, mismatch, old/new authentication, lockout clearing, and preservation of unrelated user/device/role/permission/audit data.
- GitHub Actions run `33854995975`: backend, frontend, and Windows-agent jobs all passed for commit `298da1e`.
- Existing API/database/Redis readiness and four pre-existing device records were verified after administrator recovery. No database volume was deleted or recreated.

## Gate assessment

Mandatory installed-service functions passed: elevated install, SCM start, real enrollment/heartbeat, secure credential reuse, restart, reboot auto-start, stable identity, real 503 outage/recovery, revoked behavior, graceful stop, 30-minute stability/performance, uninstall/reinstall, tests, and CI.

Remaining deployment risks are signed installer packaging, production HTTPS/trust validation, physical 10 MiB log rollover observation, a real standard-user access attempt, and the test VM's pre-existing disabled firewall profiles. The portal administrator password disclosed by the operator during setup must be rotated privately before treating the lab credential as secure.

## Final security closure

Closure validation completed on 2026-09-05 without merging the feature branch.

- The disclosed portal administrator credential was rotated through the hidden, confirmed CLI prompt. The refreshed credential authenticated successfully; API, PostgreSQL, and Redis readiness remained healthy. The new value was not recorded.
- A short-lived test CA signed an IP-SAN certificate for a temporary HTTPS reverse proxy. After importing only that CA into the Windows Local Machine root store, the agent used `https://192.168.80.131:8443` with `AllowHttp=false`, advanced its heartbeat, and remained Reachable with zero failures.
- A separate self-signed certificate on port 8444 was deliberately left untrusted. The agent remained Running and Enrolled, marked the server Unreachable, reached two bounded failures, did not advance LastSuccess, and retained its credential/device identity. Restoring the trusted endpoint returned it to Reachable and zero failures without HTTP fallback.
- Temporary HTTPS containers, CA trust, certificates, keys, and proxy configuration were removed. The controlled lab's original explicit HTTP configuration was restored and heartbeat revalidated. Enterprise deployment requires a publicly or organizationally trusted certificate with the management DNS/IP in SAN; certificate-validation bypasses are prohibited.
- Physical 10 MiB rollover was exercised by extending only non-secret closed agent logs beyond the production threshold and restarting through SCM. Sixteen roll attempts produced numbered files; retention deleted the oldest and held exactly 14 files. Observed sizes were 713 bytes minimum and 10,486,784 bytes maximum, totaling 136,328,905 bytes. Logging continued in the new active file. A closed-file scan found zero credential-header, bearer, password, or enrollment-token patterns. Production/default limits were never changed.
- An interactive temporary standard user, `DESKTOP-IMHGHC0\NSClosureStd`, was confirmed non-administrative. Actual operations were denied for credential read, DPAPI decrypt, executable overwrite, configuration overwrite, SCM configuration change, and service stop. The service remained Running/Automatic. The account, profile, probe, and result file were removed.
- All Domain, Private, and Public Windows Firewall profiles were enabled from their pre-existing disabled state. WinRM remained accessible and the agent continued heartbeat over trusted HTTPS with zero failures. NetSentinel Agent does not require Windows Firewall to be disabled and required no broad inbound rule.
- Final live state: portal login succeeded; API/database/Redis were healthy; one of two intentional hostname records was online (the other is preserved revoked history); device `2a07f213-c214-47bc-ac89-556e3f21672a` was Running, Automatic, Enrolled, Reachable, and at zero failures.
- A password-hidden scan compared all three current test credentials against tracked files and full Git patch history: zero matches. No tracked `.env`, DPAPI credential XML, private key, test certificate, or temporary helper was present. Local agent build had zero errors/warnings and all 10 tests passed.

Final closure criteria are satisfied, subject to the final repository CI run recorded with the closure commit.
