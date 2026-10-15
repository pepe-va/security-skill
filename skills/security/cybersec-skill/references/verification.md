# Security verification and testing

Which proof allows you to say a control is satisfied, and which method obtains it. For a full source audit, the method is mode 2 (`audit/README.md`); this file covers the evidence rules that apply everywhere.

## Evidence hierarchy

Strongest first. **Always use the strongest available and say which one you used.**

1. **Direct observation of the artifact in its real state** — the deployed code, the effective configuration, the real permissions on the target system.
2. **Output of an executed test** — a test that fails without the control and passes with it, a scanner result with the concrete finding.
3. **Process artifact** — signed SBOM, provenance attestation, approval record, audit log, tracker entry.
4. **Documentation** — policy, written requirement, recorded design decision. Enough **only** for requirements that explicitly ask for documentation to exist.
5. **Unverified third-party statement** — not evidence. If it is all there is, the state is NOT VERIFIED.

**Rule:** *documented* configuration does not prove *deployed* configuration. *Intended* permissions do not prove *effective* permissions.

**Audit mode adds:** a `confirmed` finding needs a source trace plus a bounded local result (`audit/upstream/SECURITY-AUDIT.md` → *Core principles*); a lead blocked by a fact outside the source is `needs_validation`, never a low-confidence vulnerability.

## Manual review

**What for:** business logic, architecture decisions, correctness of authorisation, backdoors and malicious content. What a tool does not see.

**Standards:** SSDF `PW.7.1`, `PW.7.2` · SAMM Security Testing → Deep Understanding · NIST SP 800-115 review techniques (`standards/nist-800-115.md` §3).

**Rules:**
- `PW.2.1`: design review is done by **someone who did not take part in the design**, or by an automated process in the toolchain.
- Prioritise by risk: authentication modules, access-control enforcement points, session management, external interfaces, validators and parsers.
- The developer's self-review **complements**, it does not replace (`PW.5.1` example 9).

## Automated tools

| Type | What it finds | Standard |
|---|---|---|
| SAST | Vulnerabilities in readable code | SSDF `PW.7.2` · SAMM Security Testing |
| DAST | Runtime behaviour | SSDF `PW.8.2` |
| IAST | Hybrid with instrumentation | SAMM Security Testing |
| SCA | Vulnerable dependencies | SSDF `PW.4.4` · ASVS `V15.2.1` · mode 3 (`scripts/audit_deps.py`) |
| Secret scanning | Secrets in code and history | ASVS `V13.3.1` · SSDF `PO.5.1` |
| IaC / container scanning | Insecure configuration | ASVS V13 · SSDF `PO.5.1` · `standards/nist-800-190.md` §4.1 |
| Model scanning | Malware, backdoors, unsafe deserialisation | `800-218A PW.7.2.R1` |

**Rules:**
- Tune the tool to the stack: disabling support for technologies you do not use reduces false positives and speeds things up (SAMM Scalable Baseline level 2).
- Minimising false negatives with your own rules matters as much as minimising false positives.
- **For AI models, static analysis alone does not establish behavioural safety** (LLM04 risk 3). Scanning is not evaluating.
- A scanner hit is a candidate, not a finding: it still needs the boundary-and-result test of audit mode.

## Dynamic testing

**Fuzzing** (SAMM Misuse/Abuse Testing level 1): covers at least the main input parameters; record and inspect every crash for security impact.

**Abuse cases** (level 2): built on personas with defined motivations and capabilities. Important business functionality must have its abuse case. For money flows, derive them from MITRE F3.

**Stress and denial-of-service tests** (level 3): in acceptance environments, aimed at specific application resources. Prioritise what an **unauthenticated** user can do.

**Penetration testing** (SSDF `PW.8.2` example 6; `standards/nist-800-115.md`): for high-risk scenarios, simulating how an attacker would try to compromise the software. Only against systems you are authorised to test; this skill's audit mode never probes deployed or shared systems.

## Testing AI and agents

**Reference benchmarks:** AgentDojo and JailbreakBench as an injection baseline.

**Requirements specific to this domain:**
- **Attacker-aware.** The tester must have the full specification of the deployed defence. A metric obtained against an attacker who does not know the defence **is not valid**.
- **Six disclosure surfaces** to cover separately: training-data extraction, membership inference, embedding inversion, internal-state inversion, side channels and LoRA extractability.
- **Trigger probing after every alignment cycle** (LLM05 mitigation 10).
- **Re-evaluate after retraining** or adding sources (`800-218A PW.8.2.R2`).
- **ATLAS tag** on every finding with its `AML.T****`.
- Automate inside the pipeline as regression tests where possible (`800-218A PW.8.1.C1`).

## Scoring a finding

Severity follows the anchors in `audit/README.md` (demonstrated impact, likelihood, blast radius). Add a CVSS v4.0 vector when the result can be expressed as one, and **compute** it with `python scripts/cvss4.py "<vector>"` — never estimate it. Prioritise known vulnerabilities in dependencies with CISA KEV and EPSS, which are priorities, not severities.

## Revalidation

**When it is mandatory:**
- After fixing a finding: write a **regression test** that fails without the fix (SAMM Control Verification level 3).
- After a context change: new exposure, new data type, new tool in an agent, model or embedding-encoder change.
- After every alignment cycle of a model.
- Periodically for controls whose validity depends on time: certificates, secret rotation (`V13.3.4`), dependency currency (`V15.2.1`).

**Rule:** a finding closed without a regression test comes back. `RV.3.3` also asks to look for **similar vulnerabilities** to eradicate the whole class, not just the reported instance.
