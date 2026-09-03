# Durable telemetry pipeline

`POST /api/v1/telemetry/events` validates a bounded batch and authenticates `X-Service-Token` credentials separately from portal users. HTTP 202 means Redis accepted the events; it does not mean PostgreSQL persistence. Tokens are printed once by `python -m app.cli create-service-token NAME KIND`; only an HMAC-SHA256 derivative is stored and credentials support expiry and revocation.

Events enter `netsentinel:telemetry`. Workers in consumer group `telemetry-workers` reserve globally unique IDs in `telemetry.event_ids`, bulk-insert new events, and acknowledge only after commit. Duplicate IDs are acknowledged without a second row. `XAUTOCLAIM` recovers stale pending entries.

Infrastructure failures such as PostgreSQL downtime, connection timeouts, pool exhaustion, restarts, and temporary network errors remain pending without ACK or DLQ expiry. They use capped exponential backoff and expose a blocked worker state. Data and integrity errors are event-specific; only those can exhaust the attempt threshold and move to `netsentinel:telemetry:dlq`. Inspect with `redis-cli XRANGE netsentinel:telemetry:dlq - + COUNT 20`; output may contain sensitive URLs.

The API rejects input at the critical stream threshold rather than trimming unprocessed events. HTTP 202 means accepted into the Redis queue, not guaranteed zero-loss disk persistence. Redis AOF `everysec` can lose roughly the latest second during a host crash. Production options include stronger AOF persistence, Redis replication/HA, or—if later SLA evidence requires it—a dedicated durable messaging platform. No heavier broker is introduced now. One worker is suitable for the 2-vCPU VM; additional workers use unique identities in the same group.

Machine credentials are cached by UUID; keys and values never contain raw tokens. `SERVICE_CREDENTIAL_CACHE_TTL_SECONDS` controls cache lifetime. Revocation can take up to that TTL to propagate, while credential expiry caps the lifetime.

Processed records are ACKed and deleted because PostgreSQL is the telemetry system of record and Redis is a bounded queue. Pending records are never deleted before commit. Legacy acknowledged entries can be removed with `XDEL` only after confirming they are absent from the pending list; unlimited processed history is intentionally avoided.

The default PostgreSQL partition prevents ingestion failure when a monthly partition is missing. Operations should create near-term monthly partitions and drop expired partitions for retention. Full HTTPS paths may be unavailable without TLS inspection; never submit bodies, cookies, credentials, or authorization headers.

## Preliminary VM baseline (2026-09-02)

Run `python3 loadtest/telemetry_load.py --url http://HOST:8080/api/v1/telemetry/events --token "$SERVICE_TOKEN" --events 5000 --batch 100 --concurrency 4`. The harness never prints the token. On the 2-vCPU, approximately 4-GB validation VM, 500 single-event requests distributed across 500 simulated endpoint names accepted 423.3 events/s (p50 14.57 ms, p95 20.96 ms, p99 241.19 ms). A 5,000-event sustained probe in batches of 100 at concurrency 4 accepted 15,428.0 events/s (p50 20.24 ms, p95 39.75 ms, p99 91.85 ms). A 5,000-event burst at concurrency 16 accepted 10,633.5 events/s (p50 74.06 ms, p95 330.21 ms, p99 335.71 ms). Across 194 observed worker batches, database-write latency was p50 4.851 ms, p95 41.236 ms, and p99 49.142 ms.

These short telemetry-only probes establish a functional baseline, not production capacity. The post-run container snapshot was API 74 MiB, worker 54.52 MiB, PostgreSQL 40.52 MiB, and Redis 4.414 MiB; it is not a sampled peak.

## Stabilization gate measurements (2026-09-02)

A practical 5.4-minute controlled run used 500 simulated endpoints, 75-event batches, two concurrent requests, and approximately 4,500 events/minute. It generated, accepted, and uniquely persisted 24,450 events with zero request errors, duplicates, DLQ growth, or unexplained loss. Approximate API latency was p50 41.07 ms, p95 44.59 ms, p99 60.21 ms. Worker database latency across 537 samples was p50 6.261 ms, p95 25.795 ms, p99 46.759 ms. Sampled peaks were queue length 3 legacy acknowledged entries, pending 0, lag 0, API 1.02%/65.78 MiB, worker 1.68%/53.33 MiB, PostgreSQL 2.45%/41.39 MiB, Redis 3.05%/4.70 MiB, and VM RAM 23.25%. VM CPU peak was not captured reliably; a 30–60 minute endurance run with host CPU sampling remains required before a final production merge recommendation.

During a 46-second PostgreSQL outage, 900 valid events remained pending, worker use was 2.19% CPU/52.73 MiB, no DLQ records were added, and the queue recovered 30.159 seconds after PostgreSQL returned. With a temporary 1,000-entry critical threshold and the worker stopped, 1,000 new events were accepted, queue length reached 1,003 including legacy entries, and the next event returned HTTP 503. The backlog drained in 1.943 seconds after worker restart.

## Final endurance gate (2026-09-03)

One continuous run started at 05:10:30.150930759 UTC and ended at 05:42:21.358513237 UTC (31m51.208s). It simulated 500 endpoints using 75-event request batches, two concurrent requests, about 0.94 requests/s, and 70.64 events/s. All 135,000 generated events were accepted and uniquely persisted; rejections, duplicates, unexplained loss, and DLQ growth were zero. The three legacy acknowledged stream entries remained untouched.

Across 228 time-series samples, API latency was p50 47.64 ms, p95 58.64 ms, p99 69.94 ms. First-five-minute values were 47.40/58.89/69.94 ms and last-five-minute values were 46.88/55.56/60.38 ms, showing no degradation. The final 900 worker samples measured database persistence at p50 11.212 ms, p95 19.264 ms, p99 24.263 ms. Peak stream length was 152 (149 above the legacy baseline), pending 149, and consumer lag zero; all returned to 3/0/0.

Host CPU averaged 16.21%, with p95 and peak briefly reaching 100% while the process-per-interval test harness generated payloads; host load average peaked at 1.22 and the queue did not grow continuously. VM RAM moved from 749 MiB to 833 MiB and peaked at 22.21%. API averaged/peaked at 0.64%/1.39% CPU and 77.95/78.66/78.66 MiB start/peak/end RAM. Worker was 0.98%/2.44% and 52.20/53.05/53.05 MiB; PostgreSQL 0.75%/3.43% and 73.12/136.10/136.10 MiB; Redis 1.29%/3.23% and 14.29/14.96/14.64 MiB. PostgreSQL connections stayed at nine, database size grew from 41,344,023 to 99,433,495 bytes, minimum free disk was 132,543 MiB, and no service errors, OOMs, or new restarts occurred.
