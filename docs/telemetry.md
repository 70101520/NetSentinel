# Durable telemetry pipeline

`POST /api/v1/telemetry/events` validates a bounded batch and authenticates `X-Service-Token` credentials separately from portal users. HTTP 202 means Redis accepted the events; it does not mean PostgreSQL persistence. Tokens are printed once by `python -m app.cli create-service-token NAME KIND`; only an HMAC-SHA256 derivative is stored and credentials support expiry and revocation.

Events enter `netsentinel:telemetry`. Workers in consumer group `telemetry-workers` reserve globally unique IDs in `telemetry.event_ids`, bulk-insert new events, and acknowledge only after commit. Duplicate IDs are acknowledged without a second row. `XAUTOCLAIM` recovers stale pending entries.

Database failures leave entries pending and use capped exponential backoff. At the configured attempt threshold, records move to `netsentinel:telemetry:dlq`. Inspect with `redis-cli XRANGE netsentinel:telemetry:dlq - + COUNT 20`; output may contain sensitive URLs.

The API rejects input at the critical stream threshold rather than trimming unprocessed events. Redis AOF is enabled; `appendfsync everysec` can lose roughly the latest second during host failure. Stronger durability requires `appendfsync always` or a durable broker, at a throughput cost. One worker is suitable for the 2-vCPU VM; additional workers use unique identities in the same group.

The default PostgreSQL partition prevents ingestion failure when a monthly partition is missing. Operations should create near-term monthly partitions and drop expired partitions for retention. Full HTTPS paths may be unavailable without TLS inspection; never submit bodies, cookies, credentials, or authorization headers.
