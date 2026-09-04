# Endpoint enrollment and heartbeat stabilization gate

Branch: `feature/endpoint-enrollment-heartbeat`

The gate covers only enrollment, credential lifecycle, heartbeat/current state, automatic offline/reconnect transitions, device foundation details, the Devices portal detail surface, and related test tooling. It does not authorize work on the full Windows Agent or later modules.

## Verified behavior

- Enrollment throttle: Redis counter scoped to source IP and a keyed token identifier; heartbeat traffic uses no such counter.
- Token lifecycle: create/list/revoke, natural expiry, maximum usage, and usage count; raw token creation-only.
- Endpoint lifecycle: revoke retains inventory/history and denies heartbeat; rotation invalidates the old credential and returns the new credential once.
- Duplicate installation: deterministic HTTP 409; no extra device or token use.
- Liveness: bounded indexed evaluator marks stale devices OFFLINE without a portal read; reconnect creates one ONLINE transition.
- Dependency loss: PostgreSQL errors are logged by type without credentials and mapped to generic HTTP 503.
- Portal/API: server-side filtering/pagination and a minimal real-API details view with recent transitions.
- Simulator: ignored owner-readable state file supports restart recovery and 55–65 second sustained jitter.

## Verification record

Environment: Ubuntu test VM `192.168.80.131`, PostgreSQL 16, Redis 7, Compose-limited API (1 CPU/512 MiB), PostgreSQL (1.5 CPU/1 GiB), and Redis (0.5 CPU/256 MiB).

- Automated tests: 23 collected, 23 passed, 0 failed in 1.46 seconds; Ruff selected fatal rules passed. The tests use PostgreSQL and Redis and cover lifecycle, authentication, rate limiting, state, details, pagination, and filters.
- API restart: persisted identities resumed 500/500 heartbeats without re-enrollment or duplicates after readiness.
- PostgreSQL outage: heartbeat returned HTTP 503 with a generic response; the same credential returned HTTP 200 after PostgreSQL readiness recovered.
- Automatic liveness: a stale ONLINE device became OFFLINE within the evaluator cycle; its resumed heartbeat changed it to ONLINE and added exactly one reconnect transition.
- Sustained workload: 500 endpoints for 1,800.059 seconds, randomized 55–65 second intervals, 14,984 successful heartbeats, 0 errors, average 8.324 requests/second.
- Sustained latency: p50 8.733 ms, p95 11.895 ms, p99 13.042 ms. First five minutes: 9.147/12.216/13.901 ms. Last five minutes: 8.514/11.623/12.580 ms. No degradation was observed.
- Burst/headroom: 500/500 succeeded in 1.283 seconds (389.846 requests/second), 0 errors; p50 65.429 ms, p95 204.871 ms, p99 291.362 ms.
- Continuous resources: 352 samples at approximately five-second cadence. VM CPU average/peak 4.378%/9.0%; RAM average/peak 746.682/788 MiB; one-minute load average/peak 0.295/0.92.
- API CPU average/peak 4.409%/9.94%; RAM average/peak 90.238/90.59 MiB. First/last 20-sample RAM averages were 89.782/90.340 MiB (bounded 0.558 MiB delta).
- PostgreSQL CPU average/peak 1.152%/5.83%; RAM average/peak 57.037/58.20 MiB. The 3.925 MiB warm-up delta is consistent with bounded database cache growth; no continued growth or connection leak appeared.
- Redis CPU average/peak 0.954%/2.84%; RAM average/peak 13.491/13.78 MiB; first/last averages 13.535/13.480 MiB.
- Database connections average/peak 8.713/9 and remained 9 at later checkpoints.
- Stale-selection `EXPLAIN (ANALYZE, BUFFERS)`: 0.319 ms execution, 86 shared-buffer hits, 25 KiB sort. At 1,003 rows PostgreSQL correctly preferred a sequential scan and rejected 1,000 fresh rows; the `(current_status, last_heartbeat)` index and bounded `LIMIT 500 ... FOR UPDATE SKIP LOCKED` support growth. Recheck the plan at production cardinality.
- Typical routine heartbeat performs one indexed device/credential row lookup with a row lock and one device update/commit. It does not read or write transition/audit rows unless status changes.
- CI: GitHub Actions run 33723994820 succeeded for commit `4aeb156`.

## Security review

Raw enrollment and device credentials are returned only at creation/rotation, are not logged, and only keyed derivatives are stored. Agent authentication is independent of portal JWT. Token usage is locked atomically; expiry, revocation, and maximum usage are enforced. Endpoint payloads/body size are bounded, endpoints cannot self-assign group/department, revoked endpoints are denied, and database dependency errors use a generic 503 response. Administrative boundary events are audited while routine heartbeats are not.

## Recommendation

PASS — endpoint enrollment and heartbeat ready to merge into develop.

Remaining risks: TLS termination/secret-vault hardening remains a deployment obligation, and the stale-selection query plan should be rechecked at much larger production cardinality. These do not invalidate this scoped gate.
