# Finding: IDOR / BOLA on `GET /api/v1/orders/{id}`

**Where:** REST API endpoint `GET /api/v1/orders/{id}`, path parameter `id`.
**What happens:** any logged-in customer who changes `id` gets another customer's order back, with name, postal address and items. It is read-only and nothing else is exposed.

## Summary

| Item | Value |
|---|---|
| CWE | **CWE-639**, Authorization Bypass Through User-Controlled Key (CWE List v4.20) |
| CVSS 4.0 vector | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| CVSS 4.0 score | **7.1** (CVSS-B, base metrics only) |
| Severity | **High** (the CVSS 4.0 High band is 7.0–8.9) |
| OWASP category | API1:2023 Broken Object Level Authorization; A01:2021 and A01:2025 Broken Access Control |
| Main requirement broken | OWASP ASVS 5.0.0 **V8.2.2** (Level 1, so the API fails every ASVS level) |

---

## 1. CWE

**Primary: CWE-639, Authorization Bypass Through User-Controlled Key.** Abstraction: Base. Mapping usage: ALLOWED (CWE v4.20).

MITRE's definition: *"The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data."* Your finding matches it exactly. The user-controlled key is the `{id}` path segment. The endpoint checks that the caller is logged in but never checks that the order belongs to them. CWE-639 lists "Insecure Direct Object Reference / IDOR", "Broken Object Level Authorization / BOLA" and "Horizontal Authorization" as alternate terms.

Why not the nearby CWEs (all v4.20):

| CWE | Status | Use it? |
|---|---|---|
| CWE-863 Incorrect Authorization | Class, parent of 639, *Allowed-with-Review* | Only if your tracker accepts Class-level IDs and nothing more specific. 639 is more precise. |
| CWE-862 Missing Authorization | Class, *Allowed-with-Review* | No. There is an authorization layer (authentication is required). The per-object check is what's missing, and CWE-639 is the more specific entry for that. |
| CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key | Variant, *Allowed* | Only if code review shows `id` goes straight into a SQL primary-key lookup with no owner condition. A black-box test can't prove that. |
| CWE-359 Exposure of Private Personal Information to an Unauthorized Actor | Base, *Allowed* | Fine as a **secondary/impact** tag for privacy tracking. It isn't the root cause. |
| CWE-285 / CWE-284 / CWE-200 | *Discouraged* for mapping | No. |

## 2. CVSS 4.0

**`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` = 7.1, High**

I calculated the score with the official FIRST v4.0 MacroVector algorithm (Python `cvss` 3.6 library), not by estimating.

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | **N** | The REST API is reachable over the network. |
| Attack Complexity | **L** | There is no security control to get around. The attacker just changes the id, which I assume is predictable (see assumptions). |
| Attack Requirements | **N** | No race condition or deployment-specific precondition. |
| Privileges Required | **L** | An ordinary customer session is needed. The spec defines Low as privileges "typically limited to settings and resources owned by a single low-privileged user". |
| User Interaction | **N** | The victim doesn't have to do anything. |
| VC (Confidentiality, vulnerable system) | **H** | The attacker chooses which order to read and can loop over ids to collect every customer's name, address and purchases. VC:L would need the attacker to "not have control over what information is obtained" or the loss to be limited, and neither applies. |
| VI (Integrity) | **N** | Orders can't be modified this way. |
| VA (Availability) | **N** | No impact on availability. |
| SC / SI / SA (Subsequent systems) | **N** | No other system is affected. |

Threat metric `E` is left at `X`, which CVSS treats as Attacked, the worst case. That is the normal choice for a pentest finding, and exploitation here takes one edited number in the URL.

**What changes the score** (all computed with the same algorithm):

| Scenario | Change | Score |
|---|---|---|
| Base case (as described) | none | **7.1 High** |
| You read the spec's line *"self-service provisioned accounts do not constitute a privilege requirement"* as applying to open customer sign-up | PR:N | 8.7 High |
| Order ids are random and unguessable (e.g. UUIDv4) and never leaked elsewhere, so they become a "target-specific secret" | AC:H | 6.0 Medium |
| Only a few records, not chosen by the attacker, could be read | VC:L | 5.3 Medium |
| CVSS 3.1 equivalent, for older trackers | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 Medium |

With predictable ids and every order readable, the finding is **High** whichever way you read PR. Unguessable ids lower the score but don't fix the flaw.

## 3. Severity

**High.** The CVSS v4.0 qualitative scale puts 7.0–8.9 in High. In business terms, any customer account can pull PII for the whole customer base in bulk. Under GDPR, if it has been exploited, that can be a notifiable personal data breach (see 4.3).

## 4. Requirements broken, by standard

### 4.1 Broken: the test result alone shows non-compliance

| Standard (version) | ID | Requirement (quoted or abridged) | Why it fails |
|---|---|---|---|
| **OWASP ASVS 5.0.0** | **V8.2.2** (L1) | "Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA)." | Any customer can read any order. |
| OWASP ASVS 5.0.0 | V8.3.1 (L1) | "Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate…" | The only thing deciding which order comes back is the client-supplied `id`. |
| OWASP ASVS 4.0.3 (if you still assess against 4.x) | V4.2.1 (L1, CWE-639) | "Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting … reading … of records, such as … viewing everyone's records…" | The read path is vulnerable. |
| OWASP ASVS 4.0.3 | V4.1.2 (L1, CWE-639) | "Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized." | The `id` the user can change effectively acts as the access key. |
| **OWASP API Security Top 10 2023** | **API1:2023** Broken Object Level Authorization | API endpoints that take an object ID from the client and don't check the caller may access that object. | Textbook case: the object id is in the path and there is no per-object check. |
| OWASP Top 10 2021 | A01:2021 Broken Access Control | Lists "Permitting viewing or editing someone else's account, by providing its unique identifier (insecure direct object references)". CWE-639 is among its mapped CWEs. | Same flaw. |
| OWASP Top 10 2025 | A01:2025 Broken Access Control | Same IDOR wording. CWE-639 is mapped (CWE category 1436). | Same flaw. |
| **NIST SP 800-53 Rev. 5** (release 5.2.0) | **AC-3** Access Enforcement | "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies." | Authorization on order records isn't enforced. |
| NIST SP 800-53 Rev. 5 | AC-6 Least Privilege | "Employ the principle of least privilege, allowing only authorized accesses for users…" | Customers can access records they aren't authorized for. |
| **ISO/IEC 27001:2022**, Annex A | **A.8.3** Information access restriction | Access to information must be restricted in line with the access-control policy (paraphrased; the text is paywalled). | No owner restriction on order data. |
| ISO/IEC 27001:2022, Annex A | A.5.15 Access control | Access-control rules must be established *and implemented* (paraphrased). | The rule exists in the business logic but isn't implemented in this endpoint. |
| **GDPR** (Regulation (EU) 2016/679) | **Art. 32(1)(b)** | Ability to ensure the ongoing confidentiality of processing systems and services. | Personal data (name, address, purchase history) goes to unauthorized people. |
| GDPR | Art. 25(2) | By default, personal data must not be "made accessible without the individual's intervention to an indefinite number of natural persons". | Every logged-in customer, an open-ended group, can see other customers' data. |
| GDPR | Art. 5(1)(f) | Integrity and confidentiality principle: protection against unauthorised processing. | Same cause. |

**Test references for the report** (these are test cases, not requirements): OWASP WSTG v4.2 **WSTG-ATHZ-04** Testing for Insecure Direct Object References, and in the current unreleased WSTG master branch, **WSTG-APIT-02** API Broken Object Level Authorization.

### 4.2 Probably broken: confirm in a code or process review

| Standard | ID | When it fails |
|---|---|---|
| OWASP ASVS 5.0.0 | V8.1.1 (L1) | If no authorization document says "a customer may only read their own orders" (data-specific access rules). |
| OWASP ASVS 5.0.0 | V16.3.2 (L2) | Not proven by this finding, because the requests *succeeded*. Check whether denied object access is logged and whether you could detect someone enumerating ids. |
| ISO/IEC 27001:2022 | A.8.26 Application security requirements; A.8.28 Secure coding; A.8.29 Security testing in development and acceptance | A process gap if object-level authorization isn't a stated requirement and isn't tested before release. |
| ISO/IEC 27001:2022 | A.5.34 Privacy and protection of PII | Your PII obligations aren't being met for order data. |

### 4.3 Conditional: GDPR breach handling

The vulnerability alone isn't a "personal data breach" under Art. 4(12). Check the access logs for one session reading many order ids that belong to other customers, leaving out the authorized pentest traffic. If you find real unauthorized access:

- **Art. 33(1):** notify the supervisory authority within 72 hours, unless the breach is unlikely to result in a risk to people.
- **Art. 34:** tell the affected customers if the risk is high.
- **Art. 33(5):** document the breach in either case.

### 4.4 Not broken or not applicable

- **OWASP API3:2023 BOPLA:** no extra properties are exposed and nothing can be written (you confirmed nothing else leaks).
- **OWASP API5:2023 BFLA:** customers are allowed to call this function. The flaw is at object level, not function level.
- **PCI DSS v4.0.1:** no account data (PAN) is exposed. If the API is inside your CDE scope anyway, the only relevant requirement is **6.2.4**: bespoke software must prevent "attacks on access control mechanisms". Requirements 7 and 8 don't cover consumer accounts.

## 5. Assumptions

1. Order ids are predictable or enumerable, for example sequential integers. That's how "changing the id" works. If they are random UUIDs that never leak, see the AC:H row in section 2.
2. The attacker needs only a normal customer account, and anyone can create one.
3. The response holds customer PII (name, postal address, items) but no payment data, credentials or tokens, and nothing can be changed.
4. You process data of people in the EU, so GDPR applies. If not, use your local privacy law in its place.
5. The score uses base metrics only (CVSS-B), with no threat or environmental adjustment.
6. The API isn't in PCI DSS CDE scope.

## 6. Remediation (short)

- **Check ownership on the server for every object access.** Load the order with `WHERE id = :id AND customer_id = :caller_id`, taking `:caller_id` from the authenticated session or token and never from the request. A central, deny-by-default policy check works too.
- Return **404** for orders the caller doesn't own, so the response doesn't confirm that the order exists.
- Apply the same check to every order sub-resource, to other API versions (`/v2`…), and to every other endpoint that takes an object id (addresses, invoices, returns).
- Add automated two-user BOLA regression tests: user A's token on user B's order must return 404.
- Defense in depth: non-sequential ids (UUIDv4/ULID), rate limiting, and alerts on id enumeration and authorization denials (ASVS 5.0.0 V16.3.2). None of these is a fix on its own.

## Sources

| Source | Version | What was used |
|---|---|---|
| MITRE CWE, `cwe.mitre.org/data/definitions/{639,863,862,566,359,285,284,200}.html` | CWE List v4.20 | Definition, abstraction, mapping usage, alternate terms, OWASP Top 10 memberships |
| FIRST CVSS v4.0 Specification Document, `first.org/cvss/v4.0/specification-document` | v4.0 | PR, AC, VC metric definitions; qualitative severity scale |
| Python `cvss` library (FIRST v4.0 MacroVector implementation) | 3.6 | Score calculation |
| OWASP ASVS, `5.0/en/0x17-V8-Authorization.md`, `5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md` | 5.0.0 | V8.1.1, V8.2.2, V8.3.1, V16.3.2 |
| OWASP ASVS, `4.0/en/0x12-V4-Access-Control.md` | 4.0.3 | V4.1.2, V4.2.1 |
| OWASP API Security Top 10, `editions/2023/en/0xa1-broken-object-level-authorization.md` | 2023 | API1:2023 |
| OWASP Top 10, `2021/docs/en/A01_2021-Broken_Access_Control.md`, `2025/docs/en/A01_2025-Broken_Access_Control.md` | 2021, 2025 | A01 IDOR wording and mapped CWE-639 |
| OWASP WSTG, `05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md`; `12-API_Testing/02-API_Broken_Object_Level_Authorization.md` | v4.2; master (unreleased) | WSTG-ATHZ-04; WSTG-APIT-02 |
| NIST SP 800-53 Rev. 5, OSCAL catalog | Release 5.2.0 | AC-3, AC-6 statements |
| ISO/IEC 27001:2022 Annex A | 2022 | A.5.15, A.5.34, A.8.3, A.8.26, A.8.28, A.8.29 (paraphrased, text is paywalled) |
| GDPR, Regulation (EU) 2016/679 | OJ L 119, 4.5.2016 | Arts. 4(12), 5(1)(f), 25(2), 32(1)(b), 33, 34 |
| PCI DSS | v4.0.1 | Req. 6.2.4 (conditional only) |
