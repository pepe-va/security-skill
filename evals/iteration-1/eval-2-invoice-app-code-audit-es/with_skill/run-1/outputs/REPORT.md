# Security audit — invoice-app (run-1)

## 1. Run parameters and scope

- **Profile**: standard · **Mode**: 2 (source-code audit) · **Target**: `cybersec-skill-workspace/fixtures/invoice-app` (read-only).
- **Source ref**: no VCS in the repository; content hash `sha256(README.md, app.py, auth.py, seed.py) = 9028bab187a5eb4979ceccce8e9b77d06611ecd6290de7d59f4e99983d3af256`.
- **Execution policy**: `sandboxed-source-and-local-only`. Source was read read-only; the only target code run was the WSGI application driven in-process by a harness inside a bwrap sandbox with no network, an empty environment, read-only source, writes confined to scratch, and CPU/memory/process/file-size/wall-clock limits. No packages were installed; the target repository was not modified.
- **Prior runs**: none for this repository. This is the first pass; no coverage is inherited.
- **Independent verification**: **false**. No isolated sub-agents were available, so one agent performed hunting and then validation in sequence. Hunting was closed before validation began, and each candidate was validated by trying to refute it. Confirmed findings were reviewed by the same agent that found them.
- **Coverage**: full pass over the whole repository (not quick, not scoped, not budget-limited). This does not mean the target is exhaustively proven free of other issues.

## 2. Security posture

A very small WSGI invoicing service. The password cryptography is correct (PBKDF2-HMAC-SHA512 with 600,000 iterations, 16-byte random salt, constant-time compare, 256-bit `secrets` tokens) and most database access is parameterized. Two routes, however, break per-user data isolation, and together they let any authenticated user read every other user's invoices (including IBANs) and the stored password hashes. A third item — serving over plain HTTP — depends on deployment facts not present in the repository and is left as a lead to validate.

## 3. Confirmed findings

| Severity | Title | Boundary | Observed result |
|---|---|---|---|
| High (CVSS-B 7.1) | SQL injection in `GET /search` | Authenticated user -> cross-user data + credential store | Boolean and UNION payloads returned all owners' invoices and dumped the `users` table (PBKDF2 hashes) |
| High (CVSS-B 7.1) | IDOR in `GET /invoices/<id>` | Authenticated user -> another user's invoice | `bob` read `alice`'s invoice (incl. IBAN) by id |

### 3.1 SQL injection in `GET /search` (`invoice-app/app.py:search-sql-injection`)

- **Where**: `app.py:52` (q from query string) -> `app.py:53` (f-string into SQL) -> `app.py:55` (`db().execute(sql)`).
- **Lower-trust principal**: any authenticated user (the route sits behind `current_user`).
- **Bounded reproduction** (in-process, sandboxed): seed with `seed.py`; `POST /login` as `bob`; `GET /search?q=' OR 1=1 -- ` returns both owners' invoices; `GET /search?q=' UNION SELECT id, username || ':' || hex(pw_hash), 0 FROM users -- ` returns `alice:<hash>` and `bob:<hash>`.
- **Condition**: a valid session; rows exist. Impact is read-only because `sqlite3.execute` runs a single statement (no chained write).
- **Actual result**: owner filter bypassed and full read of invoices plus the credential table.
- **Priority rationale**: high — a low-privilege authenticated principal fully defeats per-user isolation with real consequences (cross-tenant read + credential-hash disclosure). Not critical because it requires authentication and yields no write/execution.
- **Smallest fix**: parameterize — `WHERE owner_id = ? AND customer LIKE '%' || ? || '%'` with `(user["id"], q)`. Never build SQL with f-strings.
- **Sources**: OWASP ASVS 5.0.0 v5.0.0-1.2.4 (violated-requirement); CWE-89 (weakness); OWASP Top 10:2025 A05:2025 (risk-category); CVSS 4.0 (severity-basis).

### 3.2 IDOR in `GET /invoices/<id>` (`invoice-app/app.py:invoices-id-missing-owner-check`)

- **Where**: `app.py:39` (id from path) -> `app.py:41` (`SELECT ... WHERE id = ?`, no `owner_id`).
- **Lower-trust principal**: any authenticated user.
- **Bounded reproduction** (sandboxed): as `bob`, `GET /invoices/1` returns `{"id":1,"owner_id":1,"customer":"Acme Ltd","amount":1200.0,"iban":"DE00 0000 0000 0000 0000 01"}` — alice's invoice. The sibling `GET /invoices` returned only bob's own invoice, confirming the owner scope is present elsewhere and missing here.
- **Actual result**: cross-user read of invoice data (amount, IBAN) by enumerating sequential integer ids.
- **Priority rationale**: high — same anchor as above (per-user isolation fully defeated); read-only, authenticated.
- **Smallest fix**: add `AND owner_id = ?` with `user["id"]` to the query (or 404/403 when the owner differs).
- **Sources**: OWASP ASVS 5.0.0 v5.0.0-8.2.2 (violated-requirement); CWE-639 (weakness); OWASP Top 10:2025 A01:2025 and OWASP API Top 10 2023 API1:2023 (risk-category); CVSS 4.0 (severity-basis).

## 4. Needs validation

| Title | Trace | Blocker | Local next step | Owner-observed check |
|---|---|---|---|---|
| Possible cleartext transmission (no TLS in source) | `app.py:62` serves plain HTTP on 127.0.0.1 | Repository does not record external exposure or a TLS-terminating proxy | Review deployment config (systemd/Docker/ingress) for a TLS terminator and HTTPS enforcement | On the exposed environment, observe the scheme (http/https), any forced HTTPS redirect, and whether the cleartext port is reachable from outside the host |

No severity is assigned to this lead (ASVS 5.0.0 v5.0.0-12.2.1; CWE-319; A04:2025). See `NEEDS-VALIDATION.md`.

## 5. Hardening notes and positive patterns

**Positive patterns.** PBKDF2-HMAC-SHA512 (600k) with a 16-byte random per-user salt and `hmac.compare_digest` (`auth.py:11-18`); 256-bit `secrets.token_urlsafe` session tokens (`auth.py:20`); parameterized queries on `/login` and `/invoices` (`auth.py:17`, `app.py:48`); JSON responses with fixed error strings and no stack-trace leakage; no `eval`/`exec`, dynamic import, debug flag or unprotected admin/debug/metrics route.

**Hardening notes** (no reachable boundary violation on their own):

1. Insufficient session expiration — tokens never expire and there is no logout route (CWE-613, ASVS v5.0.0-7.4.1).
2. No brute-force / rate-limit control on `/login` (ASVS v5.0.0-6.3.1).
3. Username-enumeration timing oracle: PBKDF2 is skipped for unknown users, so response time distinguishes them (ASVS v5.0.0-6.3.8, L3).
4. Shared hardcoded demo password for both seeded accounts (CWE-798) — dummy data; never seed a real deployment with it.
5. `wsgiref.simple_server` is a single-threaded reference server with no body/connection limits — not for production.
6. Data minimization: `/invoices/<id>` returns `owner_id` and `iban`; return only what is needed.

## 6. Coverage summary

Nine coverage units, all reached in wave 1 (first pass, no prior ledger):

- **covered**: 6 (GET /invoices owner scoping; /login password verification; session lifecycle; pre-auth work imbalance; routing/error "obvious things"; seed demo credentials).
- **candidate**: 3 — two confirmed (SQLi, IDOR) and one needs-validation (no-TLS transport).
- **blocked / deferred / out_of_scope**: 0.

No independent final-clean critic agent was available; verification was not independent (see section 1). The coverage claim is the ledger (`coverage-ledger.json`), not this prose. Absence of findings outside these units is not proof of their absence.
