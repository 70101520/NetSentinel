# Phase 1 performance baseline plan

No endpoint-capacity claim is valid until this plan runs on representative hardware.

Run heartbeat and telemetry tests independently, then together. Heartbeats simulate 500 unique devices at 30- and 60-second intervals with a 10% reconnect burst. Telemetry starts at 100 events/s and steps through 500, 1,000, and 2,500 events/s for 15 minutes per stage.

Record throughput, errors, p50/p95/p99 latency, policy-evaluation latency, CPU, RSS, disk IOPS, database connections/locks, Redis memory/operations, queue depth, worker lag, table/index growth, and WAL rate. Capture steady state and worker-outage recovery.

Acceptance gates: heartbeat p95 below 250 ms with errors below 0.1%; future cached policy evaluation p99 below 10 ms without PostgreSQL; no event loss across worker restart; bounded recovery and connections; responsive portal queries during ingestion.

Durable telemetry and authenticated heartbeat ingestion now exist. Endpoint stabilization measures a separate 500-device burst/headroom cycle and a 30-minute realistic run with randomized 55–65 second intervals. During the realistic run, sample VM, API, PostgreSQL, and Redis CPU/RAM plus database connections about every five seconds. Compare the first and last five-minute latency windows and retain `EXPLAIN ANALYZE` output for the indexed stale-device selection. Recorded results belong in `docs/endpoint-heartbeat-gate.md`; telemetry results remain independent.
