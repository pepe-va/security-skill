# Findings detail — invoice-app (run-1)

Complete source path and target-neutral local reproduction for each confirmed medium/high/critical record. Reproduction was performed in-process against the WSGI application inside a bwrap sandbox (no network, empty environment, read-only source, scratch-only writes, CPU/memory/process/file-size/wall-clock limits), using a dummy two-tenant database seeded by `seed.py` (alice id 1, bob id 2). HTTP shapes below describe those in-process WSGI calls; no live endpoint was contacted.

---

## F1 — SQL injection in `GET /search` (high · CVSS-B 7.1)

Fingerprint: `invoice-app/app.py:search-sql-injection`

### Ordered trace and evidence
1. entrypoint `app.py:52` — `q = parse_qs(environ.get("QUERY_STRING", "")).get("q", [""])[0]` reads the client-controlled `q`.
2. propagation `app.py:53` — `sql = f"SELECT id, customer, amount FROM invoices WHERE owner_id = {user['id']} AND customer LIKE '%{q}%'"` interpolates `q` into the SQL string with an f-string.
3. sink `app.py:55` — `rows = db().execute(sql).fetchall()` runs the concatenated statement with no bound parameters.
Supporting evidence: `seed.py:9` (the `users` table stores `salt` and `pw_hash`, reachable via UNION from the same connection).

### Dummy attacker / principal and affected resource
- Attacker: low-trust authenticated user `bob` (id 2), who should only search his own invoices.
- Affected: `alice`'s invoices and the entire `users` credential table (both dummy tenants).

### Native input and bounded instructions
1. Seed: run `seed.py` so `invoices.db` holds alice (id 1) and bob (id 2) with invoices id 1 (owner 1) and id 2 (owner 2).
2. Authenticate: `POST /login` with body `user=bob&password=demo-password`; capture the returned token.
3. Boolean payload: `GET /search?q=' OR 1=1 -- ` with `Authorization: Bearer <token>` (q URL-encoded).
4. UNION payload: `GET /search?q=' UNION SELECT id, username || ':' || hex(pw_hash), 0 FROM users -- ` with the same header.

### Observed output and the invariant it proves
- Boolean payload returned invoices for ids 1 and 2 — the `owner_id = 2` predicate was bypassed (effective WHERE became `(owner_id=2 AND customer LIKE '%') OR 1=1`).
- UNION payload returned rows `alice:<hex pw_hash>` and `bob:<hex pw_hash>`.
- Invariant broken: user input must not change the SQL structure or the owner predicate. It does.

### Conditions and containment
- Needs any valid session. Impact is read-only: `sqlite3.Connection.execute` runs a single statement, so no stacked write/DDL was possible via this sink. No network access was used.

### Source-level remediation and regression case
- Fix (`app.py`): `rows = db().execute("SELECT id, customer, amount FROM invoices WHERE owner_id = ? AND customer LIKE '%' || ? || '%'", (user["id"], q)).fetchall()`.
- Regression: a test asserting that `q = "' OR 1=1 -- "` returns only the caller's own matching invoices, and that `q` containing `UNION SELECT` yields zero cross-table rows.

---

## F2 — IDOR in `GET /invoices/<id>` (high · CVSS-B 7.1)

Fingerprint: `invoice-app/app.py:invoices-id-missing-owner-check`

### Ordered trace and evidence
1. entrypoint `app.py:39` — the route matches `/invoices/<id>` and `invoice_id = path.rsplit("/", 1)[-1]` takes the client-controlled id.
2. sink `app.py:41` — `SELECT id, owner_id, customer, amount, iban FROM invoices WHERE id = ?` runs with `(invoice_id,)` only.
Supporting evidence: `app.py:48` (the sibling `GET /invoices` filters `WHERE owner_id = ?`, showing the control that is missing here); `seed.py:10` (ids are sequential INTEGER PRIMARY KEY, trivially enumerable).

### Dummy attacker / principal and affected resource
- Attacker: authenticated user `bob` (id 2).
- Affected: `alice`'s invoice (id 1), including her IBAN.

### Native input and bounded instructions
1. Seed and authenticate as `bob` (as in F1).
2. `GET /invoices/1` with `Authorization: Bearer <bob token>`.
3. Baseline for contrast: `GET /invoices` with the same token.

### Observed output and the invariant it proves
- `GET /invoices/1` returned `{"id":1,"owner_id":1,"customer":"Acme Ltd","amount":1200.0,"iban":"DE00 0000 0000 0000 0000 01"}` — alice's invoice.
- Baseline `GET /invoices` returned only `[{"id":2,"customer":"Globex","amount":830.5}]` — bob's own invoice.
- Invariant broken: an invoice read must be bound to the authenticated owner. On this route it is not.

### Conditions and containment
- Needs any valid session; ids are sequential so an attacker can read every invoice by enumeration. Read-only. No network access was used.

### Source-level remediation and regression case
- Fix (`app.py`): `row = db().execute("SELECT id, owner_id, customer, amount, iban FROM invoices WHERE id = ? AND owner_id = ?", (invoice_id, user["id"])).fetchone()` (and/or return 404 when the owner differs).
- Regression: a test asserting that requesting another user's invoice id returns 404/403 and no row data.
