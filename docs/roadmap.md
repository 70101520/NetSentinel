# Phased delivery and risks

1. Foundation: schemas, migrations, authentication/RBAC, audit, device/enrollment, policy contract, event ingestion, health, portal shell, deployment.
2. Operational visibility: durable ingestion, live activity, discovery reconciliation, device timeline, bandwidth rollups, alerts, reports and exports.
3. Enforcement: production proxy adapter, signed policy bundles, safe deployment/rollback, temporary access, Windows agent and drift control.
4. Network integration: pfSense discovery and desired-state inter-VLAN policies with dry run, diff, approval, apply, and rollback.
5. Enterprise hardening: AD/LDAP/Entra, MFA, HA, external categorization/reputation feeds, staged rollouts, disaster exercises.

Highest-risk areas are HTTPS visibility without interception, trustworthy device/user attribution, Windows proxy behavior across applications, policy correctness under cache/network failure, firewall change safety, high-volume event retention, privacy/legal controls, and certificate lifecycle. Each requires a lab environment, adversarial tests, rollback criteria, and measurable acceptance gates before production rollout.
