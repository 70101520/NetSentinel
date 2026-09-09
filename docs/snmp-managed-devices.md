# SNMP-managed device foundation

The Agents page can register explicitly approved RFC1918 IPv4 network appliances for agentless SNMP monitoring. This foundation supports SNMPv3 `authPriv` only, with HMAC-SHA-256 authentication and AES-128 privacy. SNMPv1 and plaintext SNMPv2c communities are intentionally rejected.

An administrator supplies the target name, IPv4 address, UDP port, SNMPv3 username, authentication passphrase, privacy passphrase, and planned polling interval. Creation immediately performs bounded read-only GET requests for `sysDescr.0` and `sysName.0`. Manual **Test** repeats that operation. No SET request, walk, discovery, or public-address target is allowed.

Authentication and privacy passphrases are encrypted before database persistence with a dedicated Fernet key from `SNMP_CREDENTIAL_KEY`. Responses, audit events, logs, and portal lists never include either passphrase or ciphertext. Configure the key through the deployment secret mechanism; do not commit it. Losing the key requires replacing the affected SNMP registrations, while changing it without a controlled rotation makes existing ciphertext unreadable.

This slice does not yet schedule periodic polling or collect CPU, memory, interface, traffic, environmental, or vendor-specific OIDs. Those features require a dedicated poller, bounded concurrency, device-specific capability handling, retention, and real appliance validation.
