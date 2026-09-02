# Security model

- Passwords use Argon2id. Access JWTs are short lived, issuer/audience validated, and contain a session identifier; refresh sessions are server-side, rotated, revocable, and stored as hashes.
- Permissions—not role names—authorize every route. Denied administrative attempts are audited. The portal is not a security boundary.
- Enrollment tokens are single-use, short lived, scoped, and stored only as hashes. Successful enrollment issues a unique device credential; production agents use OS-protected storage and mTLS certificates with rotation and revocation.
- Secrets come from the environment or a secret manager. Production terminates TLS at a hardened ingress, restricts trusted proxies/CORS, and never logs tokens, passwords, complete request bodies, or TLS key material.
- State-changing browser endpoints use SameSite secure cookies plus CSRF tokens when cookie authentication is enabled. The initial bearer-token API requires explicit Authorization headers.
- Policy compilation validates wildcard boundaries and normalizes domains with IDNA. TLS interception is absent in Phase 1; a future optional module requires an enterprise CA, explicit bypass rules, key protection, legal review, and certificate pinning handling.
- Rate limits apply by source, account, endpoint, and device credential. Lockout uses progressive delays and audited thresholds to resist both guessing and denial of service.

Threats requiring dedicated testing include proxy bypass, spoofed identity, enrollment replay, event forgery/replay, SSRF in integrations, regex/rule denial of service, policy-cache staleness, privilege escalation, malicious domains/IDNs, credential extraction, and audit tampering.
