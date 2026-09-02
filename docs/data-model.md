# Data model

Configuration tables use UUID primary keys, UTC timestamps, foreign keys, uniqueness constraints, and explicit tenant-ready `organization_id` boundaries in the next multi-tenant phase. Core entities are users, roles, permissions, role permissions, devices, interfaces, groups, departments, locations, policies, policy versions, policy rules, categories, enrollment tokens, agent credentials, heartbeats, alerts, firewall integrations, and audit events.

High-volume data is separated: `telemetry.proxy_events` is range-partitioned by `occurred_at`; `(occurred_at, device_id)`, `(domain, occurred_at)`, `(user_id, occurred_at)`, and `(action, occurred_at)` indexes support common queries. `telemetry.bandwidth_hourly` and daily/monthly rollups support reports. Detailed retention defaults to 30 days, aggregates to 365 days, and audit retention is policy controlled.

Audit events are insert-only to the application role. In production, grant INSERT/SELECT but not UPDATE/DELETE, ship hashes and copies to append-only external storage, and use a separate retention role. Database constraints, not just UI behavior, enforce invariants.
