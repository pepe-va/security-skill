# Cross-cutting view by security domain

Slices the problem by domain instead of by component. Useful when a change touches one capability (authentication, secrets, logging) across several components.

## Identity, authentication and session

**ASVS:** V6 (47 requirements) · V7 (19) · V9 (self-contained tokens) · V10 (OAuth/OIDC).

**NIST SP 800-63B-4:** authentication assurance levels (§2), authenticator and verifier requirements (§3), event management (§4), session management (§5). Example: single-factor passwords **SHALL** be at least 15 characters (§3.1.1.2). Mobile clients: MASVS-AUTH.

**Top 10:2025:** A07 Authentication Failures · **API Top 10:** API2 · **Adversary:** ATT&CK Credential Access (`TA0006`), e.g. `T1110` Brute Force, `T1539` Steal Web Session Cookie.

**Most often failed:**
- Forced periodic password rotation without evidence of compromise: **forbidden** by `V6.2.10`.
- Password composition rules (upper case, symbols): **forbidden** by `V6.2.5`.
- No new session token on authentication (`V7.2.4`).
- Sessions not terminated when an account is disabled or deleted (`V7.4.2`).
- JWT: audience, issuer and scopes not validated (`V9.2.2`, `V9.2.3`, `V9.1.2` — and never the `None` algorithm).

## Authorisation and access control

**ASVS:** V8 · `V3.5` (browser origin separation) · `V10.3` (resource server).

**Top 10:2025:** A01 Broken Access Control — category #1, present in 100% of the applications tested. **API Top 10:** API1 (object), API3 (property), API5 (function). **800-53:** AC-3, AC-6 (`standards/nist-800-53r5/ac.md`). **Zero trust:** 800-207 tenets 3 and 6.

**Hard rules:**
- Deny by default except for resources meant to be public.
- Enforce access control in **trusted server code or the API**, never only in the frontend (`V8.3.1`).
- Authorise at **object** level (`V8.2.2`, IDOR/BOLA) and **field** level (`V8.2.3`, BOPLA), not only at function level.
- Multi-tenant: cross-tenant controls (`V8.4.1`).

**With an agent:** the question is not what the agent can do but **with which identity the tool connects downstream**. See `ai-llm-agents.md`.

## Data, secrets and cryptography

**ASVS:** V11 (cryptography) · `V13.3` (secret management) · V14 (data protection) · V12 (communication).

**Top 10:2025:** A02, A04 · **CWE:** `CWE-798` hard-coded credentials, `CWE-327` broken or risky cryptographic algorithm · **800-53:** SC-12, SC-13, SC-28 · **Mobile:** MASVS-STORAGE, MASVS-CRYPTO.

**Hard rules:**
- Secrets live in a secret-management solution; **never in source code or build artifacts** (`V13.3.1`).
- Passwords stored with an adaptive, salted key-derivation function with a work factor: Argon2, yescrypt, scrypt or PBKDF2-HMAC-SHA-512 (`V11.4.2`, A04).
- No ECB and no PKCS#1 v1.5 padding (`V11.3.1`); authenticated encryption such as AES-GCM (`V11.3.2`).
- At least 128 bits of effective security (`V11.2.3`); a CSPRNG with ≥128 bits of entropy for unguessable values — **UUIDs do not qualify** (`V11.5.1`).
- TLS 1.2 or later and HSTS (`V12.1.1`, `V3.4.1`).

**With an LLM:** never put secrets in system prompts (LLM08, LLM02 tier 1). The system prompt **is not a secret store**; design assuming it is discoverable.

## Input, output and execution

**ASVS:** V1 (encoding and sanitisation, 30 requirements) · V2 (validation) · V5 (files) · `V15.3` (defensive coding).

**Top 10:2025:** A05 Injection · **CWE Top 25:** `CWE-79`, `CWE-89`, `CWE-78`, `CWE-94`, `CWE-22`, `CWE-502`, `CWE-918` (`standards/cwe/top25-2025.md`) · **API Top 10:** API7 SSRF, API10 unsafe consumption.

**Hard rules:**
- Decode to canonical form **once** and **before** processing, never after validating or sanitising (`V1.1.1`).
- Encode output as the **final step** before the target interpreter (`V1.1.2`).
- Parameterised queries or an ORM without concatenation (`V1.2.4`). Escaping does not replace parameterisation.
- Positive validation (allow list) in a trusted service layer (`V2.2.1`, `V2.2.2`).

**With an LLM:** inputs are LLM01 and outputs are LLM10. **They are not the same and are not mitigated the same way.** Validating model output before it reaches a shell, SQL, a browser or a terminal is LLM10; preventing input from subverting the model is LLM01, a problem with no complete solution.

## Configuration, errors and observability

**ASVS:** V13 (configuration) · V16 (logging and error handling).

**Top 10:2025:** A02, A09, A10 · **CSF 2.0:** DE.CM, DE.AE · **800-53:** AU family (`standards/nist-800-53r5/au.md`) · **Detection:** ATT&CK detection strategies per technique.

**Hard rules:**
- Log authentication successes and failures (`V16.3.1`) and authorisation failures (`V16.3.2`).
- Never log credentials or payment data; session tokens only hashed or masked (`V16.2.5`).
- Encode log data to prevent **log injection** (`V16.4.1`).
- Ship logs to a logically separate system (`V16.4.3`): if the application is compromised, the logs must not fall with it.
- Generic message to the user on an unexpected error; no stack traces or queries (`V16.5.1`).
- **Fail closed** (`V16.5.3`, A10): on an exception, do not process.

**With an LLM:** logging is both a control and a leakage surface. Reasoning traces and tool arguments are **outputs**, not debugging leftovers (LLM02).

## Dependencies and supply chain

**ASVS:** `V15.1` (remediation time frames, SBOM, risky components) · `V15.2` (architecture and dependencies).

**Top 10:2025:** A03 · **SSDF:** `PW.4.1`-`PW.4.4`, `PS.3.2` · **SLSA:** Build track, provenance verification · **CWE:** `CWE-1395`, `CWE-506`, `CWE-1357` · **ATT&CK:** `T1195.001`, `T1195.002`. Audit them with mode 3 (`audit/dependencies.md`).

**With AI models:** all of `standards/owasp-llm-top10-2026.md` LLM04 + `standards/nist-800-218a.md` `PW.4.4`, `PS.3.2`.

**New trap:** *slopsquatting*. Coding assistants hallucinate non-existent package names at scale and attackers pre-register them. **Check that every AI-suggested dependency exists and is the intended package before adopting it.**

## Resilience and abuse protection

**ASVS:** `V2.4` (anti-automation) · `V15.1.3`, `V15.2.2` (costly functionality) · `V13.1.2`, `V13.1.3` (connection limits, timeouts and retries) · `V16.5.2` (circuit breakers and graceful degradation).

**Top 10:2025:** A10 Mishandling of Exceptional Conditions · **API Top 10:** API4 · **CWE:** `CWE-770`, `CWE-400`.

**With an LLM:** LLM06 Unbounded Consumption. Request-based rate limiting **is no longer enough**: token- and cost-based limits, hard spending caps that cannot be overridden, and agent circuit breakers with step, recursion-depth, time and per-run cost limits.

## Fraud and business-logic abuse

**ASVS:** V2.3 (business logic security), V2.4 (anti-automation) · **API Top 10:** API6 Unrestricted Access to Sensitive Business Flows · **800-63B-4:** reauthentication and step-up (§2, §5).

**MITRE F3** (`standards/mitre-f3-1.2.md`): model how access turns into loss — Positioning (`FA0001`: add beneficiary `F1005.003`, account linking, SIM swap) and Monetization (`FA0002`: transfers, crypto conversion, refund abuse). Any change of payee, payout account or contact details is a fraud control point.

## Zero trust and network

**NIST SP 800-207:** the seven tenets (§2.1) and the policy engine / administrator / enforcement point model (§3). **CISA ZTMM 2.0:** maturity per pillar (Identity, Devices, Networks, Applications and Workloads, Data). **800-53:** SC-7 boundary protection, AC-17 remote access. Network findings: ASVS V12 and V13.2.

## Incident response and forensics

**NIST SP 800-61r3:** incident response as a CSF 2.0 Community Profile, with priority and R/C/N items per CSF element. **NIST SP 800-86:** evidence collection, examination, analysis and reporting. **CSF 2.0:** RESPOND and RECOVER. **ATT&CK** gives the language of what happened; **D3FEND** the countermeasure vocabulary (Evict, Restore). The incident-response, digital-forensics and threat-hunting playbooks hold the procedures (`playbooks/index-by-domain.md`).
