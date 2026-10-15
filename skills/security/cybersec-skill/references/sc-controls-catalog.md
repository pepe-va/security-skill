# Master catalogue of SC controls

## What an SC control is

An SC control **creates no new standard**. It is a *binding*: it groups the requirements of different sources that express the same demand, and adds what the source does not prescribe — the agent's concrete action, the verification method and the result criterion.

**Inviolable rule:** the compliance criterion is still the **original requirement**. An SC control may be more explicit, never less demanding. On conflict, the source wins.

## Schema

| Field | Meaning |
|---|---|
| **SC ID** | Stable identifier `SC-<domain>-<nn>`. |
| **Applies to** | Systems and components it concerns. |
| **Phase** | Lifecycle phases in which to consult it. |
| **Requirement** | What it demands, in one sentence. |
| **Agent action** | What to do or demand while working. |
| **Verification** | How to check it. |
| **Evidence** | Which proof supports the result. |
| **PASS / FAIL / NOT APPLICABLE** | Conditions for each state. NOT VERIFIED is always possible for lack of access. |
| **Traceability** | Versioned identifiers in the sources. Every identifier is checked by `scripts/verify_ids.py`. |

## State of this catalogue

**A seed, not a complete catalogue.** It covers the most frequent, highest-impact intersections between the standards incorporated. It does not replace consulting the standard: when no control fits your case, go straight to the standard file. Growing it is pending work recorded in `governance.md`.

In audit mode, an SC control is never a finding's source: cite the requirements in its *Traceability* line (`audit/README.md` → *Sources*).

## How to extend a control's traceability

The **Traceability** line cites identifiers of standards whose text this skill holds. To reach ISO 27001, ISO 42001, EU AI Act, DORA, SOC 2, PCI DSS and the other crosswalk frameworks, use the official ASI crosswalk:

1. In `crosswalk/README.md`, the **inverse index** gives the ASI risks associated with the SC control.
2. The risk page (`crosswalk/ASI0n.md`) lists the candidate controls in each framework.

**The three links of that chain are not worth the same:**

| Link | Provenance | Value |
|---|---|---|
| SC control → ASI risk | editorial of this skill | orientation |
| ASI risk → framework control | official crosswalk, `confidence: unreviewed` | navigation hint |
| framework control → requirement | the standard, if this skill holds its text | compliance criterion |

A finding supported only by the first two links is NOT VERIFIED, not FAIL.

---

## Domain AUTH — identity, authentication and authorisation

### SC-AUTH-01 — Authorisation enforced in a trusted service layer
**Applies to:** web, API, backend, agents · **Phase:** design, implementation, review
**Requirement:** access control is enforced in trusted server code or in the API, never only in the client or in logic the consumer can manipulate.
**Agent action:** when reviewing an endpoint, find where access is decided. If the only check is in the frontend, in a request parameter or in a decision delegated to an LLM, it is a finding.
**Verification:** call the endpoint directly, bypassing the UI, with lower-privilege credentials.
**Evidence:** the endpoint's response to that call.
**PASS:** the unauthorised request is rejected server-side. **FAIL:** it is served. **NOT APPLICABLE:** the resource is intentionally public and documented as such.
**Traceability:** `v5.0.0-8.3.1` · `A01:2025` · `API5:2023` · `CWE-602` · LLM03 (complete mediation)
**Related:** SC-AUTH-02, SC-AI-02

### SC-AUTH-02 — Object- and field-level authorisation
**Applies to:** API, backend, multi-tenant · **Phase:** design, implementation, review
**Requirement:** access is restricted to the data items and the specific fields the consumer has explicit permission for (IDOR/BOLA and BOPLA).
**Agent action:** for every endpoint receiving a resource identifier, check that ownership of the record is validated, not just the role. For every response, check it does not return the whole object.
**Verification:** replace the identifier with someone else's; inspect the returned fields.
**Evidence:** response to a foreign identifier and the list of fields returned.
**PASS:** the foreign object is denied and only authorised fields are returned. **FAIL:** either fails. **NOT APPLICABLE:** no data access by identifier.
**Traceability:** `v5.0.0-8.2.2`, `v5.0.0-8.2.3`, `v5.0.0-15.3.1`, `v5.0.0-8.4.1` (multi-tenant) · `A01:2025` · `API1:2023`, `API3:2023` · `CWE-639`

### SC-AUTH-03 — Session lifecycle
**Applies to:** web, API with sessions · **Phase:** implementation, review
**Requirement:** a new session token on authentication, effective termination on logout and when the account is disabled or deleted, and full validation of self-contained tokens.
**Agent action:** check regeneration at login, server-side invalidation at logout, and for JWT signature validation, an allow-listed algorithm (never `None`), `aud`, `iss`, `nbf`/`exp` and token type.
**Verification:** reuse the pre-login token and the post-logout token.
**Evidence:** result of both reuses and the token-validation code.
**PASS:** both tokens are rejected and validation is complete. **FAIL:** either is accepted or a validation is missing.
**Traceability:** `v5.0.0-7.2.4`, `v5.0.0-7.4.1`, `v5.0.0-7.4.2`, `v5.0.0-9.1.1`, `v5.0.0-9.1.2`, `v5.0.0-9.2.1`, `v5.0.0-9.2.2`, `v5.0.0-9.2.3` · `A07:2025` · `CWE-384`, `CWE-613` · 800-63B-4 `§5.1`

### SC-AUTH-04 — Authenticator strength matches the assurance level
**Applies to:** every component that authenticates people · **Phase:** design, implementation, review
**Requirement:** the authenticators accepted match the assurance level required by the data and actions behind the login: multi-factor where required, password rules as in the standard (length, no composition rules, no forced rotation, breached-password checks), and recovery that does not bypass enabled factors.
**Agent action:** state the target AAL first (`standards/nist-800-63b-4.md` §2), then check the authenticator types and the recovery path against it. A password reset that skips MFA defeats the whole level.
**Verification:** review the authentication and recovery flows; try a recovery on an MFA-enabled test account.
**Evidence:** the configured authenticators and the observed recovery behaviour.
**PASS:** authenticators and recovery meet the AAL. **FAIL:** a weaker path exists. **NOT APPLICABLE:** authentication is fully delegated to an external IdP (then assess the IdP configuration).
**Traceability:** `v5.0.0-6.3.3`, `v5.0.0-6.4.3`, `v5.0.0-6.2.5`, `v5.0.0-6.2.10` · 800-63B-4 `§3.1.1.2` · `A07:2025` · `API2:2023` · `CWE-308`

---

## Domain IN — input and execution

### SC-IN-01 — Single, prior canonical decoding
**Applies to:** every component receiving input · **Phase:** implementation, review
**Requirement:** input is decoded to canonical form **once**, only when that encoding is expected, and **before** processing — never after validating or sanitising.
**Agent action:** trace the chain of decodings. Double decoding, or decoding after validation, is a finding.
**Verification:** review the data flow from input to first use.
**Evidence:** the flow's code.
**PASS:** single, prior decoding. **FAIL:** multiple or later.
**Traceability:** `v5.0.0-1.1.1` · `A05:2025` · `CWE-180`

### SC-IN-02 — Parameterised queries
**Applies to:** every component with data or interpreter access · **Phase:** implementation, review
**Requirement:** queries (SQL, HQL, NoSQL, Cypher), operating-system calls and dynamic expressions use parameterisation, not concatenation. Escaping does not replace parameterisation.
**Agent action:** look for input concatenated into queries or commands, use of `eval`, SpEL or equivalents, and dynamic template building with untrusted input.
**Verification:** code review + SAST.
**Evidence:** the code that builds the query or command.
**PASS:** every path uses parameterisation or a safe API. **FAIL:** at least one concatenation with untrusted input exists.
**Traceability:** `v5.0.0-1.2.4`, `v5.0.0-1.2.5`, `v5.0.0-1.3.2`, `v5.0.0-1.3.7` · `A05:2025` · SSDF `PW.5.1` · `CWE-89`, `CWE-78`
**Related:** SC-AI-07 when the query is built by an LLM

### SC-IN-03 — Positive validation in a trusted service layer
**Applies to:** web, API, backend · **Phase:** implementation, review
**Requirement:** input is validated against an allow list of values, patterns and ranges, or against an expected structure, in a trusted service layer. Client-side validation is not a security control.
**Agent action:** check that server-side validation exists for every input that feeds a business or security decision.
**Verification:** direct request to the service bypassing the client.
**Evidence:** the service's response to invalid input sent directly.
**PASS:** the service rejects. **FAIL:** it accepts.
**Traceability:** `v5.0.0-2.2.1`, `v5.0.0-2.2.2` · SSDF `PW.5.1` · `CWE-20`

### SC-RPC-01 — Safe deserialisation of untrusted data
**Applies to:** services, queues, RPC, caches and files that deserialise · **Phase:** implementation, review
**Requirement:** untrusted data is deserialised with an allow list of types (or a data-only format), never into arbitrary objects.
**Agent action:** find every deserialiser fed by a lower-trust source — message brokers, cookies, caches, uploaded files, inter-service calls — and check the type restrictions.
**Verification:** code review of deserialiser configuration; a bounded local test with an unexpected type.
**Evidence:** the configuration and the test result.
**PASS:** unexpected types are rejected. **FAIL:** arbitrary types are instantiated. **NOT APPLICABLE:** no deserialisation of lower-trust data.
**Traceability:** `v5.0.0-1.5.2` · `A08:2025` · `CWE-502`
**Audit companion:** `audit/upstream/PROTOCOLS-RPC-AND-MESSAGING.md`

---

## Domain OUT — output

### SC-OUT-01 — Context-aware output encoding
**Applies to:** web, frontend, API, any interpreted sink · **Phase:** implementation, review
**Requirement:** output is encoded or escaped **as the final step** before the target interpreter, with the encoding of that context (HTML, HTML attribute, CSS, JavaScript, JSON, URL, HTTP header, terminal).
**Agent action:** identify each sink and check that its encoding matches that specific sink, not a generic one.
**Verification:** inject a test payload per context.
**Evidence:** the resulting rendering or execution.
**PASS:** the payload is inert in every context. **FAIL:** it is interpreted in any.
**Traceability:** `v5.0.0-1.1.2`, `v5.0.0-1.2.1`, `v5.0.0-1.2.2`, `v5.0.0-1.2.3`, `v5.0.0-3.2.2` · `A05:2025` · `CWE-79`, `CWE-116` · LLM10

### SC-CLI-01 — Cross-window messages only from trusted origins
**Applies to:** browser frontends, embedded widgets, extensions · **Phase:** implementation, review
**Requirement:** messages received through `postMessage` (and equivalent cross-window channels) are discarded unless their origin is trusted and their syntax valid.
**Agent action:** find every `message` listener; check the origin comparison (exact match, not `indexOf` or suffix) and the schema check before use.
**Verification:** code review; a local page posting from a foreign origin.
**Evidence:** the listener code and the observed behaviour.
**PASS:** foreign or malformed messages are ignored. **FAIL:** they are processed. **NOT APPLICABLE:** no cross-window messaging.
**Traceability:** `v5.0.0-3.5.5` · `CWE-346`
**Audit companion:** `audit/upstream/CLIENT-SIDE.md`

---

## Domain SEC — secrets and cryptography

### SC-SEC-01 — Secrets outside code and build artifacts
**Applies to:** everything · **Phase:** implementation, build, deployment
**Requirement:** secrets are created, stored, controlled and destroyed in a secret-management solution. **They may not be in source code or build artifacts.** Access follows least privilege.
**Agent action:** secret scanning on code **and on repository history**; review pipeline definitions, configuration files and, with an LLM, the system prompt.
**Verification:** automated scanning + inspection of the deployed configuration.
**Evidence:** scan output and the secret manager's configuration.
**PASS:** no live secret outside the manager. **FAIL:** one appears, even in history — then it must be **rotated**, not just deleted.
**Traceability:** `v5.0.0-13.3.1`, `v5.0.0-13.3.2` · `A02:2025` · SSDF `PO.5.1` · `CWE-798` · LLM08 (mitigation 1), LLM02 (tier 1 item 4)

### SC-SEC-02 — Password storage with an adaptive derivation function
**Applies to:** every system with its own passwords · **Phase:** implementation, review
**Requirement:** passwords stored with a computationally intensive, salted KDF with a work factor tuned to current guidance.
**Agent action:** identify the algorithm. MD5, SHA-1, SHA-256 without derivation or an unsalted hash are an immediate FAIL.
**Verification:** review the registration and password-verification code.
**Evidence:** the algorithm and its parameters.
**PASS:** Argon2, yescrypt, scrypt or PBKDF2-HMAC-SHA-512 with justified parameters. **NOT APPLICABLE:** authentication fully delegated to an IdP.
**Traceability:** `v5.0.0-11.4.2`, `v5.0.0-11.4.4` · `A04:2025` · `CWE-916`

### SC-CRY-01 — Approved algorithms, modes and randomness
**Applies to:** every component that encrypts, signs or generates unguessable values · **Phase:** implementation, review
**Requirement:** authenticated encryption with approved ciphers and modes, at least 128 bits of effective security, and a CSPRNG with at least 128 bits of entropy for values that must be unguessable.
**Agent action:** look for ECB, PKCS#1 v1.5, MD5, SHA-1, reused IVs or nonces, and non-cryptographic generators. **UUIDs do not meet the entropy requirement.**
**Verification:** cryptographic inventory + code review.
**Evidence:** the inventory and the code of the cryptographic operations.
**PASS:** everything on the approved list with correct parameters. **FAIL:** any forbidden primitive or mode.
**Traceability:** `v5.0.0-11.3.1`, `v5.0.0-11.3.2`, `v5.0.0-11.2.3`, `v5.0.0-11.4.1`, `v5.0.0-11.5.1`, `v5.0.0-11.1.2` · `A04:2025` · `CWE-327`, `CWE-338`

### SC-TLS-01 — Encrypted transport without downgrade
**Applies to:** every inbound and outbound connection · **Phase:** deployment, operation
**Requirement:** TLS on all connectivity, with currently recommended versions, no fallback to insecure protocols, and HSTS on external HTTP services.
**Agent action:** inventory the connections, including internal ones, monitoring, databases and external APIs. Check certificate validation on the client side.
**Verification:** TLS scan + inspection of each client's configuration.
**Evidence:** scan result and certificate-validation configuration.
**PASS:** TLS 1.2+ everywhere, no fallback, with certificate validation and HSTS where applicable. **FAIL:** a connection is unencrypted, falls back or skips certificate validation.
**Traceability:** `v5.0.0-12.1.1`, `v5.0.0-12.2.1`, `v5.0.0-12.3.1`, `v5.0.0-12.3.2`, `v5.0.0-3.4.1` · `A04:2025` · `CWE-319`, `CWE-295`

---

## Domain LOG — observability and errors

### SC-LOG-01 — Security events logged with enough context
**Applies to:** everything · **Phase:** implementation, operation
**Requirement:** authentication successes and failures, authorisation failures, attempts to bypass controls and unexpected errors are logged with when, where, who and what metadata, in UTC or with an explicit offset.
**Agent action:** check that the events exist in the real log, not just that there are logger calls in the code.
**Verification:** trigger an authentication failure and an authorisation failure and look for them in the log.
**Evidence:** the resulting log entries.
**PASS:** both appear with enough context for an investigation. **FAIL:** one is missing or lacks context.
**Traceability:** `v5.0.0-16.3.1`, `v5.0.0-16.3.2`, `v5.0.0-16.3.3`, `v5.0.0-16.3.4`, `v5.0.0-16.2.1`, `v5.0.0-16.2.2` · `A09:2025` · `CWE-778` · 800-53 `AU-2`

### SC-LOG-02 — Protection of logs and of what they contain
**Applies to:** everything · **Phase:** implementation, deployment, operation
**Requirement:** logs are encoded to prevent log injection, protected against modification and deletion, shipped to a logically separate system, and contain no credentials or payment data. Session tokens only hashed or masked.
**Agent action:** look for sensitive data in the real log. **With an LLM, include prompts, completions, retrieved chunks and reasoning traces**, which observability platforms log by default.
**Verification:** sample the log at its final destination, not at the emitter.
**Evidence:** the sample and the retention and access configuration.
**PASS:** no forbidden data, encoded, separated and access-restricted. **FAIL:** any of these fails.
**Traceability:** `v5.0.0-16.4.1`, `v5.0.0-16.4.2`, `v5.0.0-16.4.3`, `v5.0.0-16.2.5` · `A09:2025` · `CWE-117`, `CWE-532` · LLM02 (risk 7, tier 2 item 4)

### SC-ERR-01 — Fail closed and generic error
**Applies to:** everything · **Phase:** implementation, review
**Requirement:** on an exception or security error the system fails closed, rolls back transactions and returns a generic message to the consumer, without stack traces, queries, keys or tokens. A last-resort global handler exists.
**Agent action:** look for paths where an exception lets processing continue. It is the central pattern of `A10:2025`.
**Verification:** cause an error in a validation and observe whether the operation continues.
**Evidence:** the response to the consumer and the resulting system state.
**PASS:** it stops, rolls back and responds generically. **FAIL:** it continues, leaves partial state or leaks internal detail.
**Traceability:** `v5.0.0-16.5.1`, `v5.0.0-16.5.3`, `v5.0.0-16.5.4`, `v5.0.0-2.3.3` · `A10:2025` · `CWE-636`, `CWE-209`

---

## Domain CFG — configuration and environments

### SC-CFG-01 — Secure defaults and no information leakage
**Applies to:** everything · **Phase:** deployment, operation
**Requirement:** defaults are secure and documented; production has no debug modes, directory listings, reachable version-control metadata, TRACE method, internal documentation or unintentionally exposed monitoring endpoints.
**Agent action:** assess the **deployed configuration**, not the documented one.
**Verification:** direct inspection of the deployed environment.
**Evidence:** the effective configuration and the service's response to the leakage checks.
**PASS:** everything closed and defaults documented per setting. **FAIL:** anything exposed.
**Traceability:** `v5.0.0-13.4.1`, `v5.0.0-13.4.2`, `v5.0.0-13.4.3`, `v5.0.0-13.4.4`, `v5.0.0-13.4.5` · `A02:2025` · SSDF `PW.9.1`, `PW.9.2` · `CWE-489`, `CWE-548` · 800-53 `CM-6`, `CM-7`

### SC-ENV-01 — Separation and hardening of development environments
**Applies to:** organisation, CI/CD · **Phase:** build, deployment
**Requirement:** each environment (development, model training, build, test, distribution) is separated from the others and from production, with multi-factor authentication, network segmentation, minimised direct human access to toolchain systems, and continuous monitoring.
**Agent action:** check that production data does not flow into lower environments unsanitised and that production credentials are not reachable from development.
**Verification:** review of network and IAM configuration and of trust relationships between environments.
**Evidence:** the effective configuration and the privileged-access records.
**PASS:** effective separation verified. **FAIL:** an unjustified trust path exists.
**Traceability:** SSDF `PO.5.1`, `PO.5.2` · `800-218A PO.5.1` (R2, R3, R6), `800-218A PO.5.3` · SAMM Secure Deployment → Secret Management

---

## Domain RES / ISO — availability and isolation

### SC-RES-01 — Per-principal quotas on costly functionality
**Applies to:** APIs, public endpoints, workers, anything paid per use · **Phase:** design, implementation, operation
**Requirement:** functions that are expensive, enumerable or paid per call are protected by anti-automation and per-principal quotas, with limits set from documented availability decisions.
**Agent action:** list the costly operations (search, export, report generation, SMS/email, model calls) and check the limit applies per user or key, not only globally.
**Verification:** a bounded local burst from one test principal.
**Evidence:** the configured limits and the observed throttling.
**PASS:** the burst is throttled for that principal. **FAIL:** unlimited. **NOT APPLICABLE:** no costly or enumerable functionality.
**Traceability:** `v5.0.0-2.4.1`, `v5.0.0-15.2.2` · `API4:2023` · `CWE-770`
**Related:** SC-AI-08 for model consumption · **Audit companion:** `audit/upstream/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`

### SC-ISO-01 — Tenant isolation holds beyond the main data path
**Applies to:** multi-tenant systems · **Phase:** design, implementation, review
**Requirement:** cross-tenant controls hold in every secondary path — caches, search indexes, exports, reports, backups, queues and derived stores — not only in the main read/write API.
**Agent action:** for each secondary path, ask which tenant key it is keyed or filtered by, and who can read its output.
**Verification:** a two-tenant local fixture exercising each secondary path.
**Evidence:** the keys and filters in code and the fixture result.
**PASS:** no path returns another tenant's data. **FAIL:** any path does. **NOT APPLICABLE:** single-tenant.
**Traceability:** `v5.0.0-8.4.1`, `v5.0.0-14.2.2` · `A01:2025` · `CWE-668`
**Audit companion:** `audit/upstream/DATA-ISOLATION-AND-LIFECYCLE.md`

### SC-IPC-01 — Local IPC and helper endpoints authenticate their caller
**Applies to:** desktop and mobile apps, local daemons, helpers, browser extensions with native hosts · **Phase:** design, implementation, review
**Requirement:** local sockets, named pipes, localhost HTTP servers, deep links and exported components authenticate or restrict their callers and run with the least privilege needed.
**Agent action:** enumerate local entry points and check who can reach them (any local process, any web page through localhost, any app through an intent or URL scheme).
**Verification:** code and manifest review; a local call from an unprivileged process.
**Evidence:** the binding and access configuration and the call result.
**PASS:** unauthorised callers are refused. **FAIL:** any local caller is served. **NOT APPLICABLE:** no local IPC surface.
**Traceability:** `v5.0.0-13.2.2` · MASVS `MASVS-PLATFORM-1` · `CWE-306`
**Audit companion:** `audit/upstream/DESKTOP-MOBILE-AND-LOCAL-IPC.md`

---

## Domain SUP — supply chain

### SC-SUP-01 — Signed component inventory
**Applies to:** everything · **Phase:** build
**Requirement:** an up-to-date, signed inventory of all third-party components (SBOM) exists, extended to models, adapters and datasets with AI (AIBOM / ML-BOM), with licences tracked in the same inventory.
**Agent action:** check that the inventory is generated by the build, not by hand, and covers **transitive** dependencies.
**Verification:** generate the inventory and compare it with what is actually deployed (`scripts/audit_deps.py` writes a CycloneDX SBOM).
**Evidence:** the inventory and its signature.
**PASS:** complete, signed and current. **FAIL:** missing, stale or without transitives.
**Traceability:** `v5.0.0-15.1.2` · `A03:2025` · SSDF `PS.3.2`, `PW.4.1` · `800-218A PS.3.2` · LLM04 (mitigation 4)

### SC-SUP-02 — Artifacts by immutable reference with integrity verification
**Applies to:** CI/CD, deployment, models · **Phase:** build, deployment
**Requirement:** artifacts are resolved by immutable digest and their integrity and provenance are verified before acceptance into a trusted environment.
**Agent action:** look for mutable references (`latest`, branch tags, `Author/ModelName` without digest). For models this is the *namespace reuse* vector.
**Verification:** inspect pipeline definitions and deployment manifests; verify provenance attestations where the producer publishes them.
**Evidence:** the references used and the signature, hash or provenance verification result.
**PASS:** everything by digest with verification. **FAIL:** at least one mutable reference at a promotion boundary.
**Traceability:** SSDF `PS.2.1`, `PW.4.4` · `A08:2025` · `CWE-494` · SLSA `Build L2` / `Build L3` (provenance) · LLM04 (risks 4 and 5, mitigation 5) · `800-218A PS.2.1`
**Note:** signing proves **integrity and origin, not security**. Always combine with behavioural evaluation.

### SC-SUP-03 — Remediation time frames for vulnerable components
**Applies to:** everything · **Phase:** build, operation
**Requirement:** documentation sets risk-based remediation time frames for component versions with vulnerabilities, and the application only contains components that have not breached them.
**Agent action:** do not stop at "there is an SCA". Check that **the written time frame exists** and open findings respect it.
**Verification:** compare open SCA findings with the time-frame policy.
**Evidence:** the policy and the dated SCA report.
**PASS:** written policy and no breaches. **FAIL:** no policy, or components past their time frame.
**Traceability:** `v5.0.0-15.1.1`, `v5.0.0-15.2.1` · `A03:2025` · SSDF `PW.4.4` · `CWE-1395`, `CWE-1104` · 800-40r4 (maintenance plans)
**Note:** includes checking that **every dependency suggested by an AI assistant exists and is the intended package** before adopting it (*slopsquatting*).

### SC-SUP-04 — No known-malicious or unvetted packages in the resolved graph
**Applies to:** everything with third-party packages · **Phase:** build, operation
**Requirement:** the resolved dependency graph is checked against known-malicious-package and vulnerability advisories, and packages with install-time code, unusual sources or look-alike names are reviewed before adoption.
**Agent action:** run mode 3 (`audit/dependencies.md`); treat a known-malicious match as a confirmed critical finding and its install hosts as compromised.
**Verification:** `scripts/audit_deps.py` against the lockfiles, then manual review of the flagged packages.
**Evidence:** the advisory matches and the review notes.
**PASS:** no malicious match and every flagged package reviewed. **FAIL:** a malicious match, or flagged packages adopted without review.
**Traceability:** `v5.0.0-15.1.2`, `v5.0.0-15.2.4` · SSDF `PW.4.4` · `A03:2025` · `CWE-506`, `CWE-1357` · ATT&CK `T1195.001`, `T1195.002`

---

## Domain TM / VER — design and verification

### SC-TM-01 — Threat modelling with recorded decisions
**Applies to:** every system with architectural changes · **Phase:** architecture and design
**Requirement:** a risk model of the system exists, and the responses to each risk, the design decisions and approved exceptions are recorded retrievably.
**Agent action:** with AI, the model must explicitly include AI-specific threats: training-data poisoning, malicious content in inputs and outputs, denial of service through adversarial prompts, supply-chain attacks, unauthorised disclosure, weight theft and misconfigured data pipelines — use `standards/mitre-atlas.md`. For conventional adversaries use ATT&CK, for fraud paths F3, and name countermeasures with D3FEND.
**Verification:** review the threat-model artifact and its date against the last architectural change.
**Evidence:** the model, scoped and dated.
**PASS:** it exists, covers the current scope and decisions are recorded. **FAIL:** missing, stale or without responses.
**Traceability:** SSDF `PW.1.1`, `PW.1.2` · `A06:2025` · SAMM Threat Assessment → Threat Modeling · `800-218A PW.1.1`

### SC-VER-01 — Independent design review
**Applies to:** every architectural change · **Phase:** architecture and design
**Requirement:** the design is reviewed by a qualified person **who did not take part in it**, or by an automated process in the toolchain, to confirm it meets the security requirements and addresses the identified risk information.
**Agent action:** check the reviewer's independence. Self-review does not satisfy this control.
**Verification:** the review record with its author.
**Evidence:** the record and its conclusions.
**PASS:** independent review recorded with conclusions. **FAIL:** no review, or done by the designer.
**Traceability:** SSDF `PW.2.1` · `800-218A PW.2.1` · SAMM Architecture Assessment

### SC-VER-02 — Regression test for every fixed finding
**Applies to:** everything · **Phase:** review and testing
**Requirement:** every fixed security defect leaves behind a test that **fails without the fix**, and the same class of vulnerability is searched for in the rest of the software.
**Agent action:** when closing a finding, demand the test. When opening it, ask where else the same pattern can be.
**Verification:** run the test with the fix reverted.
**Evidence:** the test and its result in both states.
**PASS:** the test exists and fails without the fix. **FAIL:** no test, or it passes anyway.
**Traceability:** SSDF `RV.3.3`, `RV.3.4` · SAMM Requirements-driven Testing → Control Verification level 3

---

## Domain AI — models, LLMs, RAG and agents

### SC-AI-01 — Hidden context keeps no secrets and is no boundary
**Applies to:** every application with an LLM · **Phase:** design, implementation
**Requirement:** the system prompt and other hidden context contain no credentials, connection strings or tokens, and are **not used as the only boundary** for authorisation, privilege separation, policy enforcement or content filtering.
**Agent action:** assume hidden context is discoverable. Ask: *if this were published in full tomorrow, what would break?* What breaks is the finding.
**Verification:** inspect the assembled context + attempt extraction by conversational probing.
**Evidence:** the real context and the result of the extraction attempt.
**PASS:** no secrets and no control depends on its confidentiality. **FAIL:** secrets present, or a control depends on the prompt being secret.
**Traceability:** LLM08 (mitigations 1-3) · LLM02 (tier 1 item 4) · `v5.0.0-13.3.1` · `CWE-798`
**Related:** SC-SEC-01

### SC-AI-02 — Least privilege and complete mediation for tools
**Applies to:** agents, function calling, MCP · **Phase:** design, implementation, deployment
**Requirement:** each tool implements only the functions needed, with a strict parameter schema validated before use; connects downstream with minimum permissions and in the user's context; and every request to a target system is validated against policy at a decision point **outside the model**.
**Agent action:** the three questions, in this order: *which functions does this tool have in excess?* *with which identity does it connect downstream?* *who decides whether the action is allowed?* If the answer to the third is "the LLM", it is a finding.
**Verification:** inventory of tools with their functions and the effective permissions of their identity in the target system.
**Evidence:** the inventory and the real permissions, not the intended ones.
**PASS:** minimum functionality, minimum permissions enforced at the target, and deterministic mediation. **FAIL:** any of the three fails. **NOT APPLICABLE:** the model invokes no tools.
**Traceability:** LLM03 (mitigations 1-7) · `v5.0.0-8.3.1`, `v5.0.0-13.2.1`, `v5.0.0-13.2.2` · `800-218A PO.5.1.R3` · ASI `ASI02`, `ASI03`
**Note:** in delegated or multi-agent flows, **preserve the original authorisation context and scope through chained calls**.

### SC-AI-03 — Agent capability budget
**Applies to:** agents · **Phase:** design, deployment
**Requirement:** it is explicitly assessed whether the agent simultaneously has (A) untrusted input, (B) sensitive data and (C) state change or external communication. An [A,B,C] agent requires **per-action** human approval; [A,B] or [A,C] require a documented residual-risk assessment.
**Agent action:** classify the agent on the A/B/C axes **before** discussing mitigations. If one leg of the trifecta can be removed, that is the right mitigation and the rest is secondary.
**Verification:** inventory of the agent's input sources, accessible data and output capabilities.
**Evidence:** the A/B/C classification and the approval or residual-risk record.
**PASS:** classified and with the control its class requires. **FAIL:** [A,B,C] without per-action approval, or [A,B]/[A,C] without a documented assessment.
**Traceability:** LLM01 (mitigations 7 and 8; *lethal trifecta* and *Rule of Two*) · LLM03 · ASI `ASI01`
**Note:** the Rule of Two is **a floor**, and says nothing about autonomy depth. Do not treat it as sufficient.

### SC-AI-04 — Memory writes as a privileged operation
**Applies to:** systems with persistent agent memory · **Phase:** design, implementation
**Requirement:** the prompt causing each memory write is logged, writes are classified looking for instruction or role-modification content, and memories with instructions require approval before persisting across sessions.
**Agent action:** one contaminated entry reaches **every future session** that reads it. Treat memory as a corpus, not a cache.
**Verification:** review the write flow and the classification applied.
**Evidence:** the write log with its causing prompt.
**PASS:** logging, classification and approval for instructions. **FAIL:** free writes without logging or classification. **NOT APPLICABLE:** no persistent memory.
**Traceability:** LLM01 (mitigation 9) · LLM05 (risk 5, scenario 9) · ATLAS `AML.T0080.000`, `AML.TA0006` · ASI `ASI06`
**Note:** factual entries drift towards instructions and incremental writes evade per-write classification. Assume imperfect detection and add privilege limits.

### SC-AI-05 — Authorisation before retrieval
**Applies to:** RAG, vector-backed memory, semantic caches · **Phase:** design, implementation
**Requirement:** document- and chunk-level authorisation is enforced **inside the index query**, validated server-side, not as a filter after retrieval. At high sensitivity, separate indexes per tenant or trust zone.
**Agent action:** find where the tenant or permission filter is applied. If after the search, there is side-channel leakage (counts, scores, timing) even if no document is returned.
**Verification:** probe with queries from one tenant against another's content, observing counts, score distribution and timing.
**Evidence:** the real index query and the probe result.
**PASS:** scope enforced inside the query and validated server-side. **FAIL:** post-filtering, or client-supplied scope without validation. **NOT APPLICABLE:** no similarity retrieval.
**Traceability:** LLM09 (risk 1, mitigation 1) · LLM02 (risk 3, tier 1 item 3) · `v5.0.0-8.2.2`, `v5.0.0-8.4.1`

### SC-AI-06 — Vector store at the sensitivity of the source documents
**Applies to:** every system with embeddings · **Phase:** design, deployment, operation, retirement
**Requirement:** embeddings, vector database backups and exports are classified, encrypted, access-controlled and retained **at the same level as the original documents**. Embeddings are deleted within a bounded time when the source document is deleted, with a reconciliation audit.
**Agent action:** zero-shot inversion reconstructs the source text **without access to the original encoder** and survives differential-privacy noise added at storage. "Only embeddings" **is not a safe-harbour classification**.
**Verification:** inspect classification, encryption, ACLs and the deletion process; reconciliation audit after a test deletion.
**Evidence:** the classification applied and the reconciliation result.
**PASS:** same level as the source, with verified deletion. **FAIL:** classified lower or without verifiable deletion.
**Traceability:** LLM09 (risk 2, mitigation 5) · LLM02 (risk 3, scenario 6) · `v5.0.0-14.1.1`, `v5.0.0-14.2.7`
**Note:** embedding API keys are secrets: a leaked key grants query access to your exact encoder. When rotating the encoder, **re-index the whole corpus**.

### SC-AI-07 — Model output validated before an executable sink
**Applies to:** every application passing LLM output to another component · **Phase:** implementation, review
**Requirement:** model output is treated as untrusted input: structural validation in application code, context-aware encoding, parameterised queries, control characters stripped before a terminal, log or IDE, and client-side automatic rendering of Markdown images, link previews and iframes blocked by default.
**Agent action:** list **every** output sink: shell, `exec`/`eval`, SQL, file paths, mail templates, browser, terminal, log viewer, IDE panel. Each needs its own treatment.
**Verification:** a test payload per sink.
**Evidence:** each sink's behaviour with the payload.
**PASS:** every sink inert. **FAIL:** any interprets it. **NOT APPLICABLE:** output is only shown as plain text, with no rendering or automated consumption.
**Traceability:** LLM10 (mitigations 1-9) · `v5.0.0-1.1.2`, `v5.0.0-1.2.4`, `v5.0.0-5.3.2` · `800-218A PW.5.1.R2`, `PW.5.1.R3` · ASI `ASI05`
**Note:** never build and deploy LLM-generated code without human review and security testing.

### SC-AI-08 — Token- and cost-based consumption limits with circuit breakers
**Applies to:** every application with an LLM, especially agents · **Phase:** design, deployment, operation
**Requirement:** limits exist per tokens per minute and per day and per estimated cost per request, **non-overridable** spending caps that stop inference, and for agents limits on steps, recursion depth, time and per-run cost with loop detection.
**Agent action:** request-based rate limiting is not enough. Ask for **cost per session**, not per request: accumulated agentic context means no individual request trips the limits while the aggregate soars.
**Verification:** inspect the limit configuration and whether the cap **stops** or only **alerts**.
**Evidence:** the configuration and the behaviour observed when the threshold is exceeded.
**PASS:** token and cost limits, a cap that stops, and circuit breakers for agents. **FAIL:** only request limits, or caps that only alert.
**Traceability:** LLM06 (mitigations 1, 2, 9) · `v5.0.0-2.4.1`, `v5.0.0-15.1.3`, `v5.0.0-15.2.2` · `CWE-770` · ASI `ASI08`

### SC-AI-09 — Integrity and provenance of models and inference artifacts
**Applies to:** every system loading third-party models · **Phase:** build, deployment
**Requirement:** the integrity, provenance and security of acquired models and all their components — training, testing, fine-tuning and alignment datasets; reward models; adaptation layers; and configuration parameters — are verified before use. Chat templates, tokenizer configurations, LoRA/PEFT adapters and quantisation artifacts are treated **as security-relevant code**.
**Agent action:** static analysis does not establish behavioural safety. A backdoor can live in the computational graph of a "safe" format. Quantisation can change behaviour relative to full precision.
**Verification:** signature and hash verification, malware and backdoor scanning, diff of inference artifacts, and **behavioural evaluation** with trigger probing.
**Evidence:** the verification and behavioural-evaluation results.
**PASS:** provenance verified, inference artifacts signed and diffed, behavioural evaluation run. **FAIL:** loaded unverified, or verified by a scanner only.
**Traceability:** `800-218A PW.4.4` (R1, R2), `PS.2.1`, `PS.3.2` · LLM04 (risks 3-5) · LLM05 (mitigation 12) · ATLAS `AML.T0010` · ASI `ASI04`

### SC-AI-10 — Adaptive red teaming as a release gate
**Applies to:** every application with an LLM · **Phase:** review and testing, operation
**Requirement:** before release, red teaming runs with the **full specification of the deployed defence disclosed to the testers**, covering injection, the six disclosure surfaces and tool abuse, with quantitatively measured results tagged with their `AML.T****`.
**Agent action:** reject attack-success metrics obtained against attackers who do not know the defence. Static success can be near zero while adaptive success exceeds 90%.
**Verification:** red-teaming report with scope, disclosed specification, method and results.
**Evidence:** the report and the ATLAS tags of each finding.
**PASS:** adaptive red teaming run and its findings triaged. **FAIL:** none, or only static metrics.
**Traceability:** LLM01 (mitigation 11) · LLM02 (tier 3 item 3) · LLM05 (mitigation 10) · `800-218A PW.8.1`, `PW.8.2`, `RV.1.2` · AI RMF `MEASURE 2.7`

---

## Quick index

| ID | Name | Domain |
|---|---|---|
| SC-AUTH-01 | Authorisation in a trusted service layer | AUTH |
| SC-AUTH-02 | Object- and field-level authorisation | AUTH |
| SC-AUTH-03 | Session lifecycle | AUTH |
| SC-AUTH-04 | Authenticator strength matches the assurance level | AUTH |
| SC-IN-01 | Single, prior canonical decoding | IN |
| SC-IN-02 | Parameterised queries | IN |
| SC-IN-03 | Positive validation in a service layer | IN |
| SC-RPC-01 | Safe deserialisation of untrusted data | IN |
| SC-OUT-01 | Context-aware output encoding | OUT |
| SC-CLI-01 | Cross-window messages only from trusted origins | OUT |
| SC-SEC-01 | Secrets outside code and artifacts | SEC |
| SC-SEC-02 | Passwords with an adaptive KDF | SEC |
| SC-CRY-01 | Approved algorithms, modes and randomness | SEC |
| SC-TLS-01 | Encrypted transport without downgrade | SEC |
| SC-LOG-01 | Security events logged | LOG |
| SC-LOG-02 | Protection of logs and their content | LOG |
| SC-ERR-01 | Fail closed and generic error | LOG |
| SC-CFG-01 | Secure defaults | CFG |
| SC-ENV-01 | Separation and hardening of environments | CFG |
| SC-RES-01 | Per-principal quotas on costly functionality | RES |
| SC-ISO-01 | Tenant isolation beyond the main data path | ISO |
| SC-IPC-01 | Local IPC authenticates its caller | ISO |
| SC-SUP-01 | Signed component inventory | SUP |
| SC-SUP-02 | Artifacts by immutable reference | SUP |
| SC-SUP-03 | Remediation time frames for components | SUP |
| SC-SUP-04 | No known-malicious or unvetted packages | SUP |
| SC-TM-01 | Threat modelling with recorded decisions | TM |
| SC-VER-01 | Independent design review | VER |
| SC-VER-02 | Regression test per fixed finding | VER |
| SC-AI-01 | Hidden context without secrets or boundary role | AI |
| SC-AI-02 | Least privilege and complete mediation for tools | AI |
| SC-AI-03 | Agent capability budget | AI |
| SC-AI-04 | Memory writes as privileged operations | AI |
| SC-AI-05 | Authorisation before retrieval | AI |
| SC-AI-06 | Vector store at the source's sensitivity | AI |
| SC-AI-07 | Output validation before executable sinks | AI |
| SC-AI-08 | Consumption limits and circuit breakers | AI |
| SC-AI-09 | Integrity and provenance of models | AI |
| SC-AI-10 | Adaptive red teaming as a release gate | AI |
