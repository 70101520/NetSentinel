# Deployment and operations

The Compose topology is suitable for a secured single Ubuntu LTS host. Put the portal behind an organizational TLS certificate, bind management ports only to management networks, configure a firewall, run containers as non-root where images permit, scan/pin images, and move secrets to Docker secrets or a vault before production.

Back up PostgreSQL with encrypted daily base backups plus WAL archiving and regularly tested point-in-time recovery. Back up configuration, CA/certificates, and enrollment metadata separately with restricted keys. Redis is disposable. Restore to an isolated host, restore the database/WAL, restore secrets and CA, start services, verify `/health/ready`, validate policy versions, and only then restore traffic.

Schedule monthly partition creation and retention jobs. Alert before 75/85/95% disk usage. Export structured JSON logs and metrics to independent monitoring. Health endpoints distinguish liveness from dependency readiness. Maintenance mode suppresses only expected derived alerts and never stops audit collection.

Proxy-bypass enforcement on pfSense: endpoint VLANs may reach private approved services and the proxy; direct Internet TCP 80/443 is denied; proxy nodes alone may egress 80/443. Test exceptions for OS updates, captive portals, QUIC/UDP 443, DNS-over-HTTPS, and internal applications before enforcement.

## Endpoint enrollment and liveness

Enrollment throttling is isolated from heartbeat traffic and keyed by source IP plus a non-reversible enrollment-token identifier. Configure `AGENT_ENROLLMENT_RATE_LIMIT` and `AGENT_ENROLLMENT_RATE_WINDOW_SECONDS` for the deployment/NAT topology. Token maximum use is enforced under a PostgreSQL row lock. `AGENT_HEARTBEAT_TIMEOUT_SECONDS`, `AGENT_OFFLINE_EVALUATOR_INTERVAL_SECONDS`, and `AGENT_OFFLINE_EVALUATOR_BATCH_SIZE` control automatic offline processing.

Administrative APIs under `/api/v1/agents` create/list/revoke enrollment tokens, revoke endpoints, rotate credentials, and update group/department assignment. The raw enrollment token is returned only by creation. The raw rotated credential is returned only by rotation. Never put either value in command history, tickets, or logs.

For controlled console-only administrator password recovery, run `docker compose exec api python -m app.cli reset-admin-password EMAIL`. The email is the only command-line value; the CLI verifies the account exists, prompts twice with hidden input, enforces the password length policy, clears login lockout state, preserves identity and authorization relationships, and writes an audit event without password material. Never pipe a password to this command or place one in shell history.

During PostgreSQL loss, an agent heartbeat returns HTTP 503 with `Database service unavailable`; it never acknowledges the heartbeat. After database readiness returns, the same credential can retry safely. API process restart requires no re-enrollment because identity and credential derivatives are durable in PostgreSQL.

Recovery test tooling example:

```text
python3 loadtest/agent_simulator.py --url http://localhost:8080 \
  --enrollment-token REDACTED --devices 500 \
  --state-file loadtest/agent-identities.state.json --burst

python3 loadtest/agent_simulator.py --url http://localhost:8080 \
  --devices 500 --state-file loadtest/agent-identities.state.json --burst
```

The state file and generated result/sample files are ignored by Git. Remove them securely when validation is complete.
