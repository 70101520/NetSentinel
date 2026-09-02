# Phase 1 performance baseline plan

No endpoint-capacity claim is valid until this plan runs on representative hardware.

Run heartbeat and telemetry tests independently, then together. Heartbeats simulate 500 unique devices at 30- and 60-second intervals with a 10% reconnect burst. Telemetry starts at 100 events/s and steps through 500, 1,000, and 2,500 events/s for 15 minutes per stage.

Record throughput, errors, p50/p95/p99 latency, policy-evaluation latency, CPU, RSS, disk IOPS, database connections/locks, Redis memory/operations, queue depth, worker lag, table/index growth, and WAL rate. Capture steady state and worker-outage recovery.

Acceptance gates: heartbeat p95 below 250 ms with errors below 0.1%; future cached policy evaluation p99 below 10 ms without PostgreSQL; no event loss across worker restart; bounded recovery and connections; responsive portal queries during ingestion.

The Phase 1 code does not yet expose heartbeat or telemetry ingestion endpoints, a durable consumer group, or metrics. Throughput testing is therefore blocked; this establishes measurements, not results.
