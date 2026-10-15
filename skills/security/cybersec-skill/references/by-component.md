# View by system and component

Which chapters and requirements each kind of component activates. Use it to **narrow down**: a chapter that does not appear for your component is a justified NOT APPLICABLE.

## Web applications (server + browser)

**ASVS:** V1 (encoding and sanitisation) · V2 (validation and business logic) · V3 (web frontend security) · V5 (file handling) · V6, V7 (authentication and session) · V8 (authorisation) · V12 (secure communication) · V13 (configuration) · V14 (data protection) · V16 (logging and errors).

**Top 10:2025:** A01, A02, A04, A05, A06, A07, A09, A10.

**Hot spots:** browser security headers (`V3.4`), origin separation (`V3.5`), cookie configuration (`V3.3`), unintended content interpretation (`V3.2`).

**Audit companions:** `audit/upstream/WEB-PROTOCOL-AND-AUTH.md`, `audit/upstream/CLIENT-SIDE.md`.

## Frontend (browser, client, local storage)

**ASVS:** all of V3 · `V14.3` (client-side data protection) · `V3.6` (external resource integrity, SRI) · `V15.3.6` (prototype pollution).

**Hard rules:**
- Client-side validation is **never** a security control (`V2.2.2`). It improves usability, nothing more.
- `localStorage`, `sessionStorage`, IndexedDB and cookies **must not hold sensitive data**, the only exception being session tokens (`V14.3.3`).
- If the application renders LLM output, **LLM10** applies too: disable by default automatic rendering of Markdown images, link previews and iframes, which are the exfiltration channel.

## Authentication and session (any component that logs users in)

**ASVS:** V6 (authentication), V7 (session), V9 (self-contained tokens), V10 (OAuth and OIDC).

**NIST SP 800-63B-4:** choose the AAL (§2), then the authenticator and verifier requirements (§3: passwords §3.1.1, OTP, out-of-band, cryptographic authenticators, passkeys/syncable authenticators in Appendix B), event management (§4) and session management (§5). Its **SHALL** statements are requirements; satisfy both ASVS and 800-63B when both apply.

**Top 10:2025:** A07. **API Top 10:** API2.

## Backend and services

**ASVS:** V1, V2, V8, V9 (self-contained tokens), V11 (cryptography), V13 (configuration and secrets), V15 (defensive coding and concurrency), V16.

**Top 10:2025:** A01, A05, A08, A10.

**Hot spots:** object- and field-level authorisation (`V8.2.2` IDOR/BOLA, `V8.2.3` BOPLA), mass assignment (`V15.3.3`), type juggling (`V15.3.5`), client IP through proxies (`V15.3.4`).

## APIs (REST, GraphQL, RPC/gRPC, WebSocket, webhooks)

**ASVS:** all of V4 · V8 (authorisation) · V9 (tokens) · V10 (OAuth and OIDC where used) · V13.2 (backend-to-backend communication).

**OWASP API Security Top 10 2023** (`standards/owasp-api-top10-2023.md`) names the API risk; ASVS gives the requirement:

| API risk | Usual ASVS requirements |
|---|---|
| API1 Broken Object Level Authorization | `V8.2.2` |
| API2 Broken Authentication | V6, V9 |
| API3 Broken Object Property Level Authorization | `V8.2.3`, `V15.3.3` |
| API4 Unrestricted Resource Consumption | `V2.4`, `V4.3.1`, `V15.2.2` |
| API5 Broken Function Level Authorization | `V8.2.1` |
| API6 Unrestricted Access to Sensitive Business Flows | `V2.4` (anti-automation), `V2.3` (business logic security) |
| API7 Server Side Request Forgery | `V1.3.6` |
| API8 Security Misconfiguration | V13, `V4.1` |
| API9 Improper Inventory Management | `V13.1` (documented communication needs), `V13.4` (debug and unintended exposure) |
| API10 Unsafe Consumption of APIs | `V1.2`, `V12.3` |

Check each ASVS identifier in `standards/owasp-asvs-5.0.0.md` before citing it; the table is editorial guidance.

**Hot spots by type:**
- **REST/HTTP:** `V4.1.1` correct Content-Type · `V4.1.3` headers set by intermediaries cannot be overridden by the user · `V4.2.1` request smuggling.
- **GraphQL:** `V4.3.1` depth/cost limits against DoS · `V4.3.2` introspection disabled in production.
- **WebSocket:** `V4.4.1` WSS · `V4.4.2` `Origin` validation in the handshake · `V4.4.3`, `V4.4.4` dedicated session tokens.
- **OAuth/OIDC:** all of V10. It is dense and specific: do not summarise it, read it.

**Audit companion:** `audit/upstream/PROTOCOLS-RPC-AND-MESSAGING.md`.

## Data and storage

**ASVS:** V11 (cryptography), `V13.3` (secret management), V14 (data protection), `V1.2.4` (parameterised queries), `V5.3` (file storage).

**Top 10:2025:** A02, A04.

**With a vector store:** all of `standards/owasp-llm-top10-2026.md` LLM09. A vector database backup is, for breach purposes, **equivalent to a backup of the source documents**.

**Audit companion:** `audit/upstream/DATA-ISOLATION-AND-LIFECYCLE.md` (tenancy, caches, exports, backups, deletion).

## Infrastructure and cloud (network, IAM, containers, orchestration, serverless)

**ASVS:** V13 (configuration), V12 (TLS and service-to-service communication), `V13.2` (backend components authenticate with individual accounts, short-lived tokens or certificates — **not** immutable credentials).

**SSDF:** `PO.5.1` (environment separation and protection), `PO.5.2` (hardening of development endpoints).

**Top 10:2025:** A02 (excessive cloud permissions, publicly shared storage).

**Containers and orchestration:** `standards/nist-800-190.md` — risks (§3: image, registry, orchestrator, container, host OS) and countermeasures (§4). Platform policies: Kubernetes Pod Security Standards (tier B).

**Zero trust:** `standards/nist-800-207.md` (tenets, logical components) and `standards/cisa-ztmm-2.0.md` (maturity per pillar).

**Controls and adversaries:** 800-53 AC, CM, SC families (`standards/nist-800-53r5/`); ATT&CK techniques for the Containers, IaaS and SaaS platforms; cloud-security and container-security playbooks.

**SAMM:** Environment Management (Configuration Hardening, Patching & Updating).

**Audit companion:** `audit/upstream/CLOUD-AND-DEPLOYMENT.md`.

## CI/CD and IaC

**SSDF:** `PO.3.1`-`PO.3.3` · `PO.5.1` · `PS.1.1` · `PW.6.1`-`PW.6.2`.

**SLSA:** Build track levels and build requirements (`standards/slsa.md`); provenance verification for consumers.

**Top 10:2025:** A03 (the pipeline protected less than the deployed system), A08 (artifacts consumed without verification).

**Hot spots:** secrets in the pipeline definition, CI cache poisoning, artifact registry credentials, unpinned third-party workflows.

**LLM04 note:** when the backdoored artifact is **built and signed by your own release infrastructure**, it passes downstream provenance checks and scanners that only flag external components. Pipeline integrity is not optional.

**Audit companion:** `audit/upstream/SUPPLY-CHAIN-AND-RELEASE.md`. Third-party packages: mode 3, `audit/dependencies.md`.

## Mobile apps (iOS, Android)

**MASVS** (`standards/owasp-masvs.md`) is the verifiable standard: STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY. The backend the app talks to is assessed with ASVS as usual. MASVS-RESILIENCE controls are defence in depth: their absence alone is a hardening note.

**Audit companion:** `audit/upstream/DESKTOP-MOBILE-AND-LOCAL-IPC.md`. Playbooks: mobile-security.

## Other components (desktop, CLI, SDK, libraries, messaging)

**ASVS:** the cross-cutting chapters apply (V1, V2, V6-V9, V11, V12, V14); V3 and V17 are explicitly excluded when there is no web frontend or WebRTC.

**Native code:** `audit/upstream/MEMORY-SAFETY-AND-BINARY.md`; CWE memory-safety entries (`CWE-787`, `CWE-125`, `CWE-416` are in the 2025 Top 25).

**On-device model:** LLM04 risk 6 — compromised manufacturing, OS or firmware vulnerabilities, and repackaged apps with tampered models. Encrypt the model at the edge, with integrity checks and vendor attestation.

## Systems that move money or value (payments, banking, wallets, marketplaces, loyalty)

**MITRE F3** (`standards/mitre-f3-1.2.md`): threat-model the fraud path — Positioning (`FA0001`: beneficiary changes, account linking, SIM swap) and Monetization (`FA0002`: transfers, cash-out, refund abuse). Controls: ASVS V2 business logic and anti-automation, `800-63B-4` step-up and reauthentication, API6:2023. Playbooks: the fraud-relevant ones in `playbooks/index-ai-and-fraud.md`.

## OT / ICS

**ATT&CK for ICS** (`standards/mitre-attack/ics.md`) for adversary behaviour. NIST SP 800-82, ISA/IEC 62443 and NERC CIP are tier B (`standards/tier-b-cards.md`): candidate controls only. Playbooks: ot-ics-security.

## WebRTC

**ASVS:** all of V17 (TURN, media, signalling). **Only** if the system uses WebRTC. In any other case it is NOT APPLICABLE and must be said.
