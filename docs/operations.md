# Deployment and operations

The Compose topology is suitable for a secured single Ubuntu LTS host. Put the portal behind an organizational TLS certificate, bind management ports only to management networks, configure a firewall, run containers as non-root where images permit, scan/pin images, and move secrets to Docker secrets or a vault before production.

Back up PostgreSQL with encrypted daily base backups plus WAL archiving and regularly tested point-in-time recovery. Back up configuration, CA/certificates, and enrollment metadata separately with restricted keys. Redis is disposable. Restore to an isolated host, restore the database/WAL, restore secrets and CA, start services, verify `/health/ready`, validate policy versions, and only then restore traffic.

Schedule monthly partition creation and retention jobs. Alert before 75/85/95% disk usage. Export structured JSON logs and metrics to independent monitoring. Health endpoints distinguish liveness from dependency readiness. Maintenance mode suppresses only expected derived alerts and never stops audit collection.

Proxy-bypass enforcement on pfSense: endpoint VLANs may reach private approved services and the proxy; direct Internet TCP 80/443 is denied; proxy nodes alone may egress 80/443. Test exceptions for OS updates, captive portals, QUIC/UDP 443, DNS-over-HTTPS, and internal applications before enforcement.
