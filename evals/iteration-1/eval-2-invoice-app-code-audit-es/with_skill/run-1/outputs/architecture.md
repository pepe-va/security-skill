# Architecture — invoice-app (run-1)

## 1. Product, principals and protected resources

Demo invoicing API (`README.md:1-4`). Principals:

- **Unauthenticated client**: can only call `POST /login` (`app.py:27-33`).
- **Authenticated user** (in the seed, `alice` id 1 and `bob` id 2; `seed.py:12-15`): presents `Authorization: Bearer <token>` (`app.py:35-37`, `auth.py:25-29`). By design should see only **their own** invoices: the data model carries `owner_id` (`seed.py:10`) and `GET /invoices` filters by it (`app.py:47-49`).
- **Operator**: runs `seed.py` and `app.py`. There is no admin role, registration or password change.

Protected resources: each user's invoices (customer, amount and **IBAN**; `seed.py:10,16-18`), credentials (`users.salt`, `users.pw_hash`) and the in-memory session tokens (`auth.py:8`).

## 2. Comparable baseline

No source-grounded comparable exists: this is a minimal WSGI service with no framework. Omitted.

## 3. Stack and visible deployment

Python 3, standard library only: `wsgiref.simple_server`, `sqlite3`, `hashlib`, `hmac` and `secrets`. No dependency manifests, CI, containers or IaC. The only execution path is `python seed.py` (creates `invoices.db` in the current directory) plus `python app.py`, which serves on `127.0.0.1:8080` (`app.py:61-62`). There is no proxy, TLS or deployment configuration in the repository. There are no tests. Local checking is done with a harness that calls the WSGI function `app.app` directly, opening no sockets, inside a bwrap sandbox: no network, empty environment, read-only source, a limited tmpfs and CPU/memory/process/file-size/wall-clock limits.

## 4. Entry surfaces and source-to-sink paths

| Surface | Controlled input | Sink |
|---|---|---|
| `POST /login` (`app.py:27-33`) | body `user`, `password` | `auth.py:17` parameterized SELECT; `auth.py:18` PBKDF2 + `hmac.compare_digest`; `auth.py:20-21` token |
| `Authorization` header (`app.py:35`) | bearer token | `auth.py:28` lookup in `SESSIONS` |
| `GET /invoices/<id>` (`app.py:39-45`) | last path segment | `app.py:41-42` parameterized SELECT **without `owner_id`** |
| `GET /invoices` (`app.py:47-49`) | none (uses `user["id"]`) | parameterized SELECT with `owner_id = ?` |
| `GET /search?q=` (`app.py:51-56`) | `q` from the query string | `app.py:53-55` SQL built with an **f-string** interpolating `q` |
| `seed.py` | none at runtime; defines the initial data | `seed.py:15` fixed password `demo-password` for both users |

## 5. Trust boundaries and strongest control

- Unauthenticated -> authenticated: `auth.login` (PBKDF2-SHA512 with 600,000 iterations, 16-byte random salt, constant-time compare, `secrets.token_urlsafe(32)` token).
- User -> another user's data: the `owner_id` predicate is applied on `/invoices` and `/search`, but on `/search` the value of `q` enters unparameterized into the same statement, and on `/invoices/<id>` the predicate is absent.
- Session lifetime: in-memory dictionary, with no expiry and no logout.

## 6. Starting paths

`app.py`, `auth.py`, `seed.py`, `README.md`.

## 7. Prior runs

No prior ledger or `findings.json` exists for this repository. This is the first pass and there are no inherited exclusions.

## 8. Companion selection

- **WEB-PROTOCOL-AND-AUTH.md**: HTTP API with password login and bearer session tokens (*Session fixation and invalidation*, *Cookie scope and transport* for cleartext transport). Framing/cache, federated identity, MFA, API-key and mTLS classes are excluded because there is no proxy, cache, IdP, MFA, API keys or mTLS in the code.
- **DATA-ISOLATION-AND-LIFECYCLE.md**: store with per-row owner (`owner_id`) and several read paths (*Missing tenant or owner enforcement*).
- **RESOURCE-EXHAUSTION-AND-AVAILABILITY.md**: expensive work before authentication (PBKDF2 on `/login`) on the wsgiref reference server (*Pre-authentication work imbalance*).
- **Excluded**: CLIENT-SIDE (no browser code; JSON responses), SUPPLY-CHAIN-AND-RELEASE (no third-party dependencies, CI or releases), CLOUD-AND-DEPLOYMENT (no IaC or containers), PROTOCOLS-RPC-AND-MESSAGING (no RPC or queues), DESKTOP-MOBILE-AND-LOCAL-IPC (the loopback listener is the HTTP API itself, covered by WEB-PROTOCOL-AND-AUTH; there is no OS-level IPC or privileged helper), MEMORY-SAFETY-AND-BINARY (pure Python) and AI-AND-LLM (no models).
