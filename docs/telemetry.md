# Durable telemetry pipeline

`POST /api/v1/telemetry/events` validates a bounded batch and authenticates `X-Service-Token` credentials separately from portal users. HTTP 202 means Redis accepted the events; it does not mean PostgreSQL persistence. Tokens are printed once by `python -m app.cli create-service-token NAME KIND`; only an HMAC-SHA256 derivative is stored and credentials support expiry and revocation.

Events enter `netsentinel:telemetry`. Workers in consumer group `telemetry-workers` reserve globally unique IDs in `telemetry.event_ids`, bulk-insert new events, and acknowledge only after commit. Duplicate IDs are acknowledged without a second row. `XAUTOCLAIM` recovers stale pending entries.

Database failures leave entries pending and use capped exponential backoff. At the configured attempt threshold, records move to `netsentinel:telemetry:dlq`. Inspect with `redis-cli XRANGE netsentinel:telemetry:dlq - + COUNT 20`; output may contain sensitive URLs.

The API rejects input at the critical stream threshold rather than trimming unprocessed events. Redis AOF is enabled; `appendfsync everysec` can lose roughly the latest second during host failure. Stronger durability requires `appendfsync always` or a durable broker, at a throughput cost. One worker is suitable for the 2-vCPU VM; additional workers use unique identities in the same group.

The default PostgreSQL partition prevents ingestion failure when a monthly partition is missing. Operations should create near-term monthly partitions and drop expired partitions for retention. Full HTTPS paths may be unavailable without TLS inspection; never submit bodies, cookies, credentials, or authorization headers.

## Preliminary VM baseline (2026-09-02)

Run `python3 loadtest/telemetry_load.py --url http://HOST:8080/api/v1/telemetry/events --token "$SERVICE_TOKEN" --events 5000 --batch 100 --concurrency 4`. The harness never prints the token. On the 2-vCPU, approximately 4-GB validation VM, 500 single-event requests distributed across 500 simulated endpoint names accepted 423.3 events/s (p50 14.57 ms, p95 20.96 ms, p99 241.19 ms). A 5,000-event sustained probe in batches of 100 at concurrency 4 accepted 15,428.0 events/s (p50 20.24 ms, p95 39.75 ms, p99 91.85 ms). A 5,000-event burst at concurrency 16 accepted 10,633.5 events/s (p50 74.06 ms, p95 330.21 ms, p99 335.71 ms). Across 194 observed worker batches, database-write latency was p50 4.851 ms, p95 41.236 ms, and p99 49.142 ms.

These short telemetry-only probes establish a functional baseline, not production capacity. The post-run container snapshot was API 74 MiB, worker 54.52 MiB, PostgreSQL 40.52 MiB, and Redis 4.414 MiB; it is not a sampled peak. Future capacity work should capture time-series CPU/RAM and queue-depth peaks during a longer steady-state run.
