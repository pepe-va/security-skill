# Classification: IDOR / BOLA on `GET /api/v1/orders/{id}`

## Result

| | |
|---|---|
| **CWE** | **CWE-639** Authorization Bypass Through User-Controlled Key (CWE 4.20 · Base · mapping usage *Allowed*) |
| **CVSS 4.0 vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CVSS 4.0 score** | **CVSS-B 7.1 (High)**. Computed with `tools/cvss4.py`, MacroVector `101200` |
| **Severity** | **High**: object-level authorisation is fully bypassed, and any customer can read every other customer's personal data |
| **Main requirement broken** | OWASP ASVS 5.0.0 **`v5.0.0-8.2.2`** (data-specific access / IDOR / BOLA, level L1) |
| **Also broken** | ASVS 5.0.0 `v5.0.0-8.3.1` · NIST SP 800-53 Rev. 5 `AC-3` (if 800-53 is your control set) |
| **Risk categories** | OWASP API Security Top 10 2023 `API1:2023` · OWASP Top 10:2025 `A01:2025` |

## Assumptions

You asked me not to ask questions, so I assumed the following. Each one affects the result, and the sensitivity table further down shows what changes if one is wrong.

1. **Order IDs can be guessed or enumerated**, for example sequential integers. I read "changes the id" this way, so an attacker can walk the whole order table.
2. **The attacker only needs an ordinary customer account**: no staff, support or admin role.
3. **The API faces the internet**, because it serves customers.
4. **Single-tenant B2C platform**: customers are users, not tenants.
5. **The data exposed is name, postal address and items**: that is personal data, but there are no payment card numbers, credentials or tokens. You stated that the response contains nothing else, and that the endpoint cannot modify orders.
6. **No AI, LLM or agent** sits on this path.
7. **Your compliance framework is unknown**, so I list NIST 800-53 and the tier-B mappings in case either applies to you.

## Context (`references/context-model.md`)

```text
System type:      API (REST, customer-facing)
Component:        GET /api/v1/orders/{id}
Phase:            review and testing (penetration test result)
Exposure:         external · single-tenant (assumed) · boundary crossed: customer A → customer B's records
Data:             PII (name, postal address, purchase history) · regime: privacy law likely (tier B, e.g. GDPR)
Identity:         authenticated customer session · authorisation: function-level only, no record ownership check
Integrations:     not relevant to this finding
AI context:       no
Business domain:  e-commerce orders; read-only, no money moved by this flaw
ASVS level:       L2 (internet-facing, holds personal data of all customers). The failed requirements are L1, so they fail at every level
Out of scope:     LLM Top 10, ASI, ATLAS, 800-218A, AI RMF (no AI) · MASVS (server-side flaw) · 800-63B (authentication works)
```

## 1. CWE: why CWE-639

CWE 4.20 defines CWE-639 as follows: *"The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data."* The pentest result matches this definition word for word: a logged-in user changed the key (`{id}`) and got another user's record.

Here is why I rejected the neighbouring entries (all are in `references/standards/cwe/weaknesses.md`):

| CWE | Why not the primary |
|---|---|
| CWE-566 (Variant, child of 639): *SQL primary key* | It would be more precise, but only if code review shows that `{id}` goes straight into a SQL primary-key lookup. A black-box test cannot show that. Switch to CWE-566 if the code confirms it. |
| CWE-863 / CWE-862 (Class, *Allowed-with-Review*) | Parent classes. CWE's mapping rules say to prefer a Base or Variant entry when one fits, and one does here. |
| CWE-359 (Base): *Exposure of Private Personal Information* | It describes the **consequence**, not the root cause. Add it as a secondary tag only if your tracker wants a data-exposure label. |

CWE-639 maps to `A01:2025` in the CWE → Top 10:2025 index (`references/standards/cwe/README.md`). It is also #24 in the 2025 CWE Top 25 (`references/standards/cwe/top25-2025.md`).

## 2. CVSS 4.0

Metric definitions come from FIRST CVSS v4.0 (`references/standards/cvss-4.0.md`). The vector describes only what was demonstrated.

| Metric | Value | Why |
|---|---|---|
| AV | **N** | It is a REST API reachable over the internet: "the set of possible attackers extends … up to and including the entire Internet". |
| AC | **L** | There is no security mechanism to evade: changing the ID works every time, so "an attacker can expect repeatable success". |
| AT | **N** | There is no race to win, no on-path position and no special deployment condition. |
| PR | **L** | A normal customer account is enough: "basic capabilities that are typically limited to settings and resources owned by a single low-privileged user". |
| UI | **N** | The victim does nothing. |
| VC | **H** | The attacker **chooses** which order to read and, with enumerable IDs, can read **all** of them: every customer's name, address and purchase history. This matches High: "access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact". Low does not fit, because Low is when "the attacker does not have control over what information is obtained, or the amount or kind of loss is limited". |
| VI | **N** | The test showed that orders cannot be modified this way. |
| VA | **N** | There is no availability impact. |
| SC / SI / SA | **N** | No other system is affected, because the data lives in the vulnerable system itself. |

```text
$ python3 tools/cvss4.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
score 7.1 · severity High · nomenclature CVSS-B · macro_vector 101200
```

This is a **CVSS-B** score: Threat and Environmental metrics are not set, so CVSS v4.0 treats them as worst case. Your team can add Exploit Maturity (E) and Confidentiality Requirement (CR) to get its own CVSS-BTE.

**Sensitivity.** If an assumption above is wrong, the score changes as follows (each row was computed with `tools/cvss4.py`):

| If… | Change | Score | Severity |
|---|---|---|---|
| IDs are random, unpredictable and do not leak anywhere, so the attacker cannot pick or enumerate victims | VC:H → VC:L | CVSS-B 5.3 (Medium) | Medium (narrow blast radius) |
| You count open self-service sign-up as part of the attack (the PR guidance on self-provisioned accounts) | PR:L → PR:N | CVSS-B 8.7 (High) | Still High: an authenticated, read-only leak of one record type does not meet the critical anchor |

## 3. Severity: High

The severity anchors are in `references/audit/README.md` → *Severity*.

- **High** fits: "an actor fully defeats an explicit security control with real consequences". Object-level authorisation is fully bypassed rather than just weakened. The consequence is concrete: any customer can read the personal data of all other customers.
- **Not critical**: the attacker must be logged in, gets read access to one record type only (not the whole data store), and cannot write or take over accounts.
- **Not medium**: the blast radius is every customer, the only precondition is an ordinary account, and the damage is real. This holds under assumption 1. If the IDs cannot be enumerated, medium becomes defensible, as the sensitivity table shows.

The CVSS score (7.1, High) and the anchor agree.

## 4. Requirements it breaks (FAIL)

```text
[SC-AUTH-02] Object-level authorisation (IDOR/BOLA)
State:     FAIL
Context:   Customer REST API · GET /api/v1/orders/{id} · review and testing (pentest)
Evidence:  A logged-in customer who replaces {id} with another customer's order id receives that order
           (name, address, items). The server checks that the caller is logged in, not that the caller owns the record.
Sources:   OWASP ASVS 5.0.0 — v5.0.0-8.2.2 (references/standards/owasp-asvs-5.0.0.md)
             "Verify that the application ensures that data-specific access is restricted to consumers with
              explicit permissions to specific data items to mitigate insecure direct object reference (IDOR)
              and broken object level authorization (BOLA)." · level L1
           MITRE CWE 4.20 — CWE-639 (references/standards/cwe/weaknesses.md)
           OWASP API Security Top 10 2023 — API1:2023 Broken Object Level Authorization (references/standards/owasp-api-top10-2023.md)
           OWASP Top 10 2025 — A01:2025 Broken Access Control (references/standards/owasp-top10-2025.md)
             "Permitting viewing or editing someone else's account by providing its unique identifier (insecure direct object references)"
           FIRST CVSS 4.0 — base metrics (references/standards/cvss-4.0.md)
Severity:  High · CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N · CVSS-B 7.1
Action:    Enforce record ownership on the server for every request: scope the lookup to the caller
           (e.g. WHERE id = :id AND customer_id = :session_customer), deny by default, and return 404 for a foreign id.
           SC-AUTH-02 also covers field level (v5.0.0-8.2.3); that half is not affected by this finding.
```

```text
[SC-AUTH-01] Authorisation enforced in a trusted service layer
State:     FAIL
Context:   Same endpoint
Evidence:  The only thing that keeps a customer to their own orders is which id the client sends, and the
           consumer controls that value. Calling the endpoint directly with another id is served (the SC-AUTH-01 FAIL criterion).
Sources:   OWASP ASVS 5.0.0 — v5.0.0-8.3.1 (references/standards/owasp-asvs-5.0.0.md)
             "Verify that the application enforces authorization rules at a trusted service layer and doesn't rely
              on controls that an untrusted consumer could manipulate, such as client-side JavaScript." · level L1
           MITRE CWE 4.20 — CWE-639 (references/standards/cwe/weaknesses.md)
Severity:  Same finding as above. Do not count it twice.
Action:    Put the ownership check in the service or data-access layer, not in the client or UI flow.
```

```text
[AC-3] Access Enforcement — applies if NIST SP 800-53 is your control baseline (federal / FedRAMP, or adopted internally)
State:     FAIL
Context:   Same endpoint
Evidence:  The application does not enforce approved authorisations for access to order records.
Sources:   NIST SP 800-53 Rev. 5.2.0 — AC-3 (references/standards/nist-800-53r5/ac.md)
             "Enforce approved authorizations for logical access to information and system resources in accordance
              with applicable access control policies."
Action:    Same fix. Whether AC-3 is in your baseline depends on SP 800-53B, which this skill does not hold.
```

**Affected organisational outcome (not a pass/fail on its own):** NIST CSF 2.0 `PR.AA-05`: *"Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed…"* (`references/standards/nist-csf-2.0.md`). This finding is evidence against "enforced", but a single finding does not decide an organisation-level outcome.

## 5. Related requirements this finding does not settle (NOT VERIFIED)

| Requirement | Why it matters | How to verify |
|---|---|---|
| ASVS 5.0.0 `v5.0.0-8.1.1` (L1): authorisation documentation defines data-specific access rules | If the rule "a customer sees only their own orders" was never written down, it was never tested | Check the API's authorisation documentation for this rule |
| ASVS 5.0.0 `v5.0.0-16.3.2` (L2): failed authorisation attempts are logged; at L3, every authorisation decision and every access to sensitive data | The bug **succeeds**, so no "failure" was ever logged. Only access logs show whether anyone has already exploited it | Review the access logs for `/api/v1/orders/{id}` where the order's owner differs from the caller, and for sequential-ID walks |
| SC-VER-02: regression test for every fixed finding (SSDF `RV.3.3`, `RV.3.4`) | Prevents the bug from coming back | A test where customer A requests customer B's order and expects a 404; it must fail if the fix is reverted |

## 6. Checked and not broken by this evidence

| Requirement / category | State | Reason |
|---|---|---|
| ASVS `v5.0.0-8.2.3`, `v5.0.0-15.3.1` · `API3:2023` (property-level, over-exposed fields) | NOT VERIFIED (not implicated) | The response holds the fields the order's owner is entitled to see, and you report nothing else is exposed. A field-by-field check against the documented rules would confirm it |
| ASVS `v5.0.0-8.2.1` · `API5:2023` (function-level) | Not implicated | Customers are meant to call this endpoint. The OWASP API1:2023 text says: "it's by design that the user will have access to the vulnerable API endpoint/function. The violation happens at the object level" |
| ASVS `v5.0.0-8.4.1` (cross-tenant controls) | NOT APPLICABLE | Assumed single-tenant B2C. If the platform is multi-tenant and this crosses tenants, this becomes a FAIL and the severity anchor names "cross-tenant read" explicitly |
| NIST SP 800-63B-4 | NOT APPLICABLE | Authentication works. The failure is authorisation |
| OWASP LLM Top 10, ASI, ATLAS, 800-218A, AI RMF | NOT APPLICABLE | No AI component on this path |
| OWASP MASVS | NOT APPLICABLE | The flaw is on the server. A mobile client would not change it |
| `API6:2023`, MITRE F3 | NOT APPLICABLE | Read-only: no money, value or business flow is abused |
| MITRE ATT&CK | Not added | T1190 *Exploit Public-Facing Application* belongs to the Initial Access tactic (network foothold). Here a legitimate user reads data inside the application, so no technique adds meaning |

## 7. Tier-B standards (text not held by this skill: best result is NOT VERIFIED)

These are candidate controls only (`references/standards/tier-b-cards.md`). The control names come from the unreviewed ASI crosswalk (`references/crosswalk/ASI06.md`, `ASI03.md`). None of this is legal advice.

| Standard | Candidate control | State |
|---|---|---|
| ISO/IEC 27001:2022 | Annex A `A.8.3` Information access restriction | NOT VERIFIED, likely affected. Covered in tier A by 800-53 AC-3 |
| AICPA SOC 2 (2017, rev. 2022) | `CC6.1` Logical and physical access controls | NOT VERIFIED, likely affected |
| GDPR (2016/679) | Security of processing, and personal-data-breach assessment and notification | NOT VERIFIED. Name, address and purchase history are personal data. If logs show actual unauthorised access, have your DPO or counsel decide whether it is a notifiable breach |
| PCI DSS 4.0.1 | — | Not in scope: no cardholder data is exposed (assumption 5) |

## 8. What to do

1. **Fix**: on every request, check on the server that the caller owns the order (or holds an explicit grant to it). Scope the query to the session's customer, deny by default, and return 404 rather than 403 so the response does not reveal which IDs exist (ASVS `v5.0.0-8.2.2`, `v5.0.0-8.3.1`).
2. **Look for the same pattern elsewhere**: check every endpoint that takes an object ID (`/orders/{id}/…`, invoices, addresses, returns, shipments). One BOLA usually means the authorisation design lacks an object-level check altogether (SC-VER-02).
3. **Regression test**: customer A requests customer B's order and gets a 404. The test must fail when the fix is reverted (SC-VER-02).
4. **Check for prior exploitation** in the access logs (see `v5.0.0-16.3.2` above), and give the result to your privacy/legal owner.
5. **Defence in depth only**: random, unpredictable IDs (an `API1:2023` *How To Prevent* item) and rate limiting (`A01:2025`) make enumeration harder, but **neither fixes the finding**. Even with UUIDs, the ownership check is still required.
