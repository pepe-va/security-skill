# Needs validation — invoice-app (run-1)

Prioritized leads with a source-grounded trace but a decisive fact outside the repository. No severity is assigned (the skill forbids severity on needs-validation records). Do not send audit traffic to a live deployment; the owner-observed checks are passive observations.

---

## NV1 — Possible cleartext transmission of credentials and tokens (no TLS in source)

Fingerprint: `invoice-app/app.py:no-tls-transport`

### Source trace and verified evidence
- sink `app.py:62` — `make_server("127.0.0.1", 8080, app).serve_forever()` serves plain HTTP; there is no TLS wrapper and no HTTPS redirect anywhere in source.
- `app.py:30` — `POST /login` reads `user` and `password` from the request body.
- `app.py:33` — the response returns the session token, later sent in the `Authorization` header on every request.
- `README.md:3` — documents the service on `127.0.0.1:8080` with no mention of TLS or a proxy.

### Affected boundary
Network path between client and service: if exposed beyond loopback without a TLS terminator, credentials (on `/login`) and bearer tokens (on every request) would be observable to a network attacker.

### Exact blockers
1. The repository does not record whether the service is exposed beyond loopback, nor whether a TLS-terminating proxy (nginx, API gateway, service mesh) encrypts the channel in the real deployment.
2. There is no deployment configuration, manifest or IaC that fixes the transport mode.

### Resolution plans
- **Local**: review the real environment's deployment configuration (systemd units, Dockerfile/compose, ingress manifests) to confirm whether a TLS terminator sits in front of the service and whether HTTPS is enforced.
- **Owner-observed (deployment)**: on the exposed environment, observe which scheme the service answers with (http/https), whether there is a forced redirect to HTTPS, and whether the cleartext port is reachable from outside the host.

### Resolution criteria
- Confirms to FAIL if the service is reachable over plain HTTP from beyond the host with no TLS in front (ASVS 5.0.0 v5.0.0-12.2.1; CWE-319; A04:2025).
- Rejects if a TLS terminator enforces HTTPS for all external connectivity and the cleartext port is not externally reachable.
