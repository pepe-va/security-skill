# View by lifecycle phase

Which controls come into play in each phase. For every phase: **what to look at**, **which standards to open** and **what evidence to ask for**.

## Requirements and planning

**Look at:** whether written security requirements exist for this software, whether they are specific and measurable, and whether someone has reviewed them.

**Standards:** SSDF `PO.1.1`, `PO.1.2`, `PO.1.3` · ASVS documentation requirements (`V2.1`, `V5.1`, `V6.1`, `V7.1`, `V8.1`, `V11.1`, `V13.1`, `V14.1`, `V15.1`, `V16.1`) · SAMM Security Requirements · with AI: `800-218A PO.1.1-PO.1.2` · authentication: choose the AAL with `standards/nist-800-63b-4.md` §2 · mobile: pick the MASVS groups in scope (`standards/owasp-masvs.md`).

**Evidence:** the versioned security requirements document. ASVS explicitly requires *documentation to exist*: when it is missing, several requirements are FAIL by definition, not NOT VERIFIED.

**Common trap:** generic requirements such as "the application must be protected against the OWASP Top 10". They are not measurable and do not satisfy `PO.1.2`.

## Architecture and design

**Look at:** trust boundaries, the threat model, recorded design decisions, use of shared security services instead of home-grown ones.

**Standards:** SSDF `PW.1.1` (threat modelling), `PW.1.2` (decision records), `PW.1.3` (standardised security features), `PW.2.1` (design review by someone who did not design it) · SAMM Threat Assessment and Security Architecture · Top 10:2025 `A06` Insecure Design · with AI: `800-218A PW.1.1` + `standards/mitre-atlas.md` · adversary behaviour: `standards/mitre-attack/` (and `standards/mitre-f3-1.2.md` when money or value moves) · countermeasures: `standards/mitre-d3fend.md` · zero trust: `standards/nist-800-207.md` (tenets) and `standards/cisa-ztmm-2.0.md` (maturity).

**Evidence:** the threat model, dated and scoped. Design decisions and approved exceptions with their justification.

**Common trap:** confusing insecure design with a faulty implementation. `A06` is explicit: *a perfect implementation cannot fix a security control that was never designed*.

## Implementation

**Look at:** secure coding practices actually applied in the code in front of you.

**Standards:** SSDF `PW.5.1` · ASVS V1 (encoding and sanitisation), V2 (validation and business logic), V15.3 (defensive coding) · APIs: `standards/owasp-api-top10-2023.md` · with AI: `800-218A PW.5.1` (input and output handling, encoding to prevent unauthorised execution) · name every weakness with its CWE (`standards/cwe/`).

**Evidence:** the code itself. Evidence here is direct; NOT VERIFIED is rarely justified.

## Review and testing

**Look at:** whether review or analysis happens, against which criteria, and what is done with the findings.

**Standards:** SSDF `PW.7.1`, `PW.7.2`, `PW.8.1`, `PW.8.2` · SAMM Requirements-driven Testing and Security Testing · testing methodology: `standards/nist-800-115.md` · see `verification.md`. A full source audit follows `audit/README.md` (mode 2).

**Evidence:** SAST/DAST/SCA results, peer reviews, the tracker with triaged findings.

## Build and supply chain

**Look at:** build reproducibility, integrity and provenance of artifacts and dependencies, security of the pipeline itself.

**Standards:** SSDF `PO.3.1-PO.3.3` (toolchains), `PO.5.1` (environment separation), `PS.1.1`-`PS.3.2` (protection and archiving), `PW.4.1`-`PW.4.4` (verified reuse), `PW.6.1`-`PW.6.2` (compiler and build) · ASVS `V15.1`, `V15.2` · Top 10:2025 `A03`, `A08` · SAMM Secure Build · SLSA Build track (`standards/slsa.md`) · container images: `standards/nist-800-190.md` §3.1 and §4.1 · with models: `standards/owasp-llm-top10-2026.md` LLM04 and `800-218A PS.1-PS.3, PW.4.4`. Dependencies are audited with mode 3 (`audit/dependencies.md`).

**Evidence:** SBOM (and AIBOM/ML-BOM with models), signatures and hashes, pipeline configuration as code, provenance attestations, patching policy.

**Common traps:**
- **Mutable** references (`latest`) instead of immutable digests: the *model namespace reuse* vector of LLM04.
- Assuming that signing proves security. Signing proves **integrity and origin**, not the absence of a backdoor.
- Trusting model scanners and safe-loading flags as a guarantee: they are defence in depth and have had bypasses with CVEs.

## Deployment

**Look at:** secure defaults, secret management, least privilege, hardening.

**Standards:** SSDF `PW.9.1`, `PW.9.2` · ASVS V13 (configuration), V12 (secure communication), `V13.3` (secret management), `V13.4` (unintended information leakage) · Top 10:2025 `A02` · SAMM Secure Deployment · containers and orchestrators: `standards/nist-800-190.md` §3.3-3.5 and §4.3-4.5 · configuration controls: `standards/nist-800-53r5/cm.md` (CM-6, CM-7) · with AI: `800-218A PO.5.1-PO.5.3`.

**Evidence:** the deployed configuration, not the documented one. Effective permissions, not intended ones.

## Operation

**Look at:** logging and alerting, detection, vulnerability management, incident response, resource consumption.

**Standards:** ASVS V16 (logging and error handling) · Top 10:2025 `A09`, `A10` · SSDF `RV.1.1`-`RV.3.4` · SAMM Incident Management and Environment Management · CSF 2.0 DETECT, RESPOND, RECOVER (`standards/nist-csf-2.0.md`) · incident response: `standards/nist-800-61r3.md` · forensics: `standards/nist-800-86.md` · patching: `standards/nist-800-40r4.md` · detection engineering: ATT&CK detection strategies (`standards/mitre-attack/enterprise-techniques.md`) and the SOC, threat-hunting and incident-response playbooks (`playbooks/index-by-domain.md`) · with AI: `800-218A PO.5.3, RV.1.1-RV.1.3` · with LLMs: LLM02 (observability as a leakage surface), LLM06 (unbounded consumption).

**Evidence:** the real logs and their retention, the configured alerts, the incident register.

**Common trap with AI:** observability platforms log prompts, completions, chunks and reasoning traces **by default**. That turns logging, a control, into a disclosure surface (LLM02). Look at both sides.

## Maintenance and retirement

**Look at:** change management, end of life, revocation, secure deletion.

**Standards:** SSDF `PO.1.2` (policies covering the whole lifecycle, including end-of-support notice), `RV.3.4` · ASVS `V14.2.7` (retention), `V15.2.1` (remediation time frames) · patch and maintenance plans: `standards/nist-800-40r4.md` · SAMM Operational Management → Legacy Management · with AI: verifiable deletion in raw data, embeddings, checkpoints and adapters (LLM02 tier 3), and deletion of embeddings when the source document is deleted (LLM09).

**Common trap:** deleting the source and assuming the data is gone. Once data has influenced weights, embeddings or adapters it **remains extractable**. That strains GDPR art. 17 and requires post-unlearning verification.
