# Governance, exceptions and maintenance

How the skill's standards were obtained, how to regenerate them, what was transformed, which source wins on conflict, and what is still missing.

## Contents

- [Sources incorporated and pinned versions](#sources-incorporated-and-pinned-versions)
- [Regeneration](#regeneration)
- [Transformations applied to the sources](#transformations-applied-to-the-sources)
- [Conflicts between sources](#conflicts-between-sources)
- [Known divergences](#known-divergences)
- [Exceptions and non-applicability](#exceptions-and-non-applicability)
- [Mandatory re-evaluation](#mandatory-re-evaluation)
- [Pending work](#pending-work)

## Sources incorporated and pinned versions

Tier A only: standards whose text this skill holds and against which PASS / FAIL can be issued. Every tier-B and tier-C standard cited by the three origin repositories, with its date and current status, is in `standards/INVENTORY.md`; the reference cards for tier B are in `standards/tier-b-cards.md`.

Every input file is recorded in `sources/manifest.json` with URL, size, SHA-256 and date. Each generated file names its source URL in its header.

### Application security

| Standard | Version (date) | How obtained | File |
|---|---|---|---|
| OWASP Top 10 | 2025 | Generated from the ten official English pages | `standards/owasp-top10-2025.md` |
| OWASP ASVS | 5.0.0 | Generated from the official CSV (345 requirements) | `standards/owasp-asvs-5.0.0.md` |
| OWASP API Security Top 10 | 2023 | Generated from the official markdown, verbatim | `standards/owasp-api-top10-2023.md` |
| OWASP MASVS | 2.1.0 | Generated from the release YAML (24 controls) | `standards/owasp-masvs.md` |
| NIST SP 800-63B-4 | Rev. 4 (Jul 2025) | Generated from the official web version (337 `SHALL`) | `standards/nist-800-63b-4.md` |
| MITRE CWE | 4.20 (2026-04-30) + 2025 Top 25 | Generated from the official XML | `standards/cwe/` |
| CVSS | 4.0 | Specification text generated from FIRST's page; scoring ported from FIRST's calculator | `standards/cvss-4.0.md`, `scripts/cvss4.py` |

### Process, maturity and supply chain

| Standard | Version (date) | How obtained | File |
|---|---|---|---|
| NIST SP 800-218 (SSDF) | 1.1 (Feb 2022) | Generated from the NIST CPRT export (42 tasks + 5 moved rows) | `standards/nist-ssdf-800-218.md` |
| NIST SP 800-218A | Jul 2024 | Hand transcription of Table 1, verified against the PDF by `gen_218a.py` (48 tasks) | `standards/nist-800-218a.md` |
| OWASP SAMM | V2.0 (2020 PDF) | Generated from the official 303-page PDF (90 cards) | `standards/owasp-samm-2.0.md` |
| SLSA | 1.2 | Generated from the specification markdown at tag v1.2 | `standards/slsa.md` |
| NIST SP 800-190 | Sep 2017 | Generated from the PDF: outline + explicit recommendations | `standards/nist-800-190.md` |

### AI, LLM and agents

| Standard | Version (date) | How obtained | File |
|---|---|---|---|
| OWASP Top 10 for LLM Applications | 2026 | Generated from the official English markdown, verbatim | `standards/owasp-llm-top10-2026.md`, `-mappings.md` |
| OWASP Top 10 for Agentic Applications (ASI) | 2026 v1.0 | Generated from the English source of the final release; titles checked against the 57-page PDF | `standards/owasp-asi-top10-2026.md`, `-incidents.md` |
| OWASP Agentic AI — Threats and Mitigations | 1.1 (Dec 2025) | Generated from the 53-page PDF; multi-column tables by coordinates | `standards/owasp-agentic-threats-mitigations-1.1.md` |
| MITRE ATLAS | 2026.09, format 6.0.0 | Generated from the official YAML | `standards/mitre-atlas.md`, `-case-studies.md` |
| NIST AI RMF | 1.0 (Jan 2023) | Statements from AI 100-1; suggested actions from the AI RMF Playbook | `standards/nist-ai-rmf-1.0.md` |
| NIST AI 600-1 | Jul 2024 | Generated from the official PDF (12 risks, 211 actions) | `standards/nist-ai-600-1.md` |
| ASI crosswalk (not a standard) | 4.0.0, entries 2026-Q3 | Generated from `data/entries/ASI01..10.json` | `crosswalk/` |

### Threat-informed defence

| Standard | Version (date) | How obtained | File |
|---|---|---|---|
| MITRE ATT&CK (Enterprise, Mobile, ICS) | 20.0 (2026-10-13) | Generated from the official STIX 2.1 bundles | `standards/mitre-attack/` |
| MITRE D3FEND | 1.6.0 (2026-08-31) | Generated from the official JSON-LD ontology | `standards/mitre-d3fend.md` |
| MITRE F3 (Fight Fraud Framework) | 1.2 (2026-09-29) | Generated from the official STIX bundle | `standards/mitre-f3-1.2.md` |

### Governance, controls and operations

| Standard | Version (date) | How obtained | File |
|---|---|---|---|
| NIST CSF | 2.0 (Feb 2024) | Generated from the NIST CPRT export | `standards/nist-csf-2.0.md` |
| NIST SP 800-53 | Rev. 5, OSCAL 5.2.0 | Generated from the OSCAL catalogue | `standards/nist-800-53r5/` |
| NIST SP 800-207 | Aug 2020 | Generated from the PDF: outline, tenets, recommendations | `standards/nist-800-207.md` |
| CISA Zero Trust Maturity Model | 2.0 (Apr 2023) | Tables rebuilt from the PDF layout (40 functions) | `standards/cisa-ztmm-2.0.md` |
| NIST SP 800-61 | Rev. 3 (Apr 2025) | Generated from the PDF: CSF 2.0 Community Profile (134 elements) | `standards/nist-800-61r3.md` |
| NIST SP 800-86 | Aug 2006 | Generated from the PDF: outline + explicit recommendations | `standards/nist-800-86.md` |
| NIST SP 800-115 | Sep 2008 | Generated from the PDF: outline + explicit recommendations | `standards/nist-800-115.md` |
| NIST SP 800-40 | Rev. 4 (Apr 2022) | Generated from the PDF: outline + explicit recommendations | `standards/nist-800-40r4.md` |

### Methodology and procedures (not standards)

| Material | Version | Licence | File |
|---|---|---|---|
| security-audit methodology (Cloudflare) | https://github.com/cloudflare/security-audit-skill, revision `c1c8a8c` | MIT | `audit/upstream/`; original validators in `sources/security-audit/`, ported as `scripts/validate_*.py` |
| Anthropic-Cybersecurity-Skills playbooks | https://github.com/mukul975/Anthropic-Cybersecurity-Skills, revision `54a798831d22` | Apache-2.0 | `playbooks/` |
| systema-cure (this skill's Spanish predecessor) | local, no repository | — | translated and regenerated into this skill; its source inputs are in `sources/` (`"adopted": true` in the manifest) |

### Origin repositories

The three repositories this skill was built from were removed from the project folder on 2026-10-15. Nothing at runtime needs them. Regeneration does not either: `gen_inventory.py` and `gen_playbooks.py` rebuild from snapshots of their last scan (`sources/inventory-scan.json`, `sources/playbooks-catalogue.json`). A fresh scan is needed only to change the inventory's detection patterns or to refresh the playbook copies: clone the two public repositories at the revisions above into the repository root. systema-cure cannot be re-cloned; everything it contained lives on, in English, in this skill.

## Regeneration

Everything generated can be rebuilt from the recorded sources. The build lives in the **source repository**, around the installed skill: `scripts/` (generators and `build_all.py`), `sources/` (official inputs, `manifest.json`, snapshots), `tests/`. Commands run from the repository root:

```bash
python scripts/build_all.py            # fetch what is missing, regenerate everything, verify IDs, run tests
python scripts/build_all.py --offline  # same, without network: use only the cached sources
python scripts/build_all.py --list     # show the steps in order
```

The order matters and `build_all.py` enforces it:

1. `fetch_sources.py` — downloads missing inputs; adopts existing ones (hash only).
2. `gen_inventory.py` — `INVENTORY.md` and `tier-b-cards.md` from the three origin repositories, or from the snapshot of their last scan.
3. One generator per standard (`gen_<standard>.py`).
4. `gen_asi.py` and `gen_crosswalk.py` **last among the standards**: they route to views and SC controls and verify crosswalk IDs against the files of step 3.
5. `gen_playbooks.py` — indexes and copies (copies only when the repository is present); verifies playbook IDs against ATT&CK, D3FEND, CSF, ATLAS and F3.
6. `verify_ids.py` (the skill's own `scripts/`) — every identifier cited in `SKILL.md`, the views, the SC catalogue and the audit docs must exist in a standard file.
7. The unit tests under `tests/` (the CVSS and report tests that need QuickJS are skipped without `pip install quickjs`).

**Build dependencies:** `pypdf`, `pyyaml`, `beautifulsoup4`, `lxml`, `markdownify`. They belong to the skill's build, not to any project: use a separate virtual environment. Runtime tools (`cvss4.py`, validators, `render_report.py`, `audit_deps.py`, `verify_ids.py`) are stdlib only.

**Upgrading a standard:** replace the input in `sources/` (or change its URL in `fetch_sources.py`), update the version constant in the generator, run `build_all.py`, and record the change here.

**Generated files are never edited by hand.** They carry a notice in their header. A manual fix is lost at the next regeneration and breaks traceability to the source.

**Inputs over 5 MB** (ATT&CK bundles, the 800-53 catalogue) are download caches listed in `sources/.gitignore`; the manifest keeps their hash so a rebuild can prove it used the same input.

## Transformations applied to the sources

Declared so nobody mistakes them for the original:

1. **SSDF 1.1** — the per-task informative references (BSAFSS, BSIMM, EO14028, …, SP800181) are omitted: they are cross-framework mappings, not compliance criteria. Practice, task and example texts are complete; the CPRT export in `sources/ssdf/` keeps the references.
2. **SP 800-218A** — the only standard still from a hand transcription. `gen_218a.py` verifies it against the PDF: 48/48 task identifiers, and every quoted text at ≥85% word 5-gram coverage or ≥97% of words in order where the table layout splits a cell.
3. **LLM Top 10 2026** — entries, preface and appendices verbatim; figures replaced by their captions. *Mappings by risk* regroups the rows of Appendix A without changing them. Sections marked *editorial* are this skill's additions.
4. **OWASP Top 10:2025** — the per-category score tables are omitted.
5. **Threats and Mitigations 1.1** — the *Detailed Threat Model* and *Playbook and Threat Mapping Overview* tables are rebuilt from PDF coordinates because they are multi-column.
6. **ATT&CK** — descriptions trimmed and citation markers removed; revoked and deprecated objects listed separately. **D3FEND** — the "related ATT&CK" lists are derived through shared digital artifacts and labelled as derived; they are not MITRE's own technique-to-technique mapping.
7. **AI RMF 1.0** — subcategory statements come from AI 100-1, the normative text. The Playbook words 22 of the 72 subcategories differently; only its suggested actions are reproduced. One category statement (GOVERN 4) split by the PDF layout was completed and verified in word order.
8. **AI 600-1** — footnote markers stripped per page; shortened risk tags resolved to the twelve risk names; the source's non-standard tag "Civil Rights violations" is kept as printed.
9. **NIST prose guides** (800-190, 800-207, 800-86, 800-115, 800-40r4) — they are not requirement catalogues. Only their explicit recommendations, countermeasures or tenets are extracted as numbered items; **PASS / FAIL is issued only against those items**, and the rest of the text is context. Headings are validated against each PDF's table of contents. **800-61r3** is reproduced as its CSF 2.0 Community Profile (priority and R/C/N items per CSF element).
10. **CISA ZTMM 2.0** — tables rebuilt from the page layout; cells verbatim, footnote markers removed.
11. **SP 800-63B-4** — section numbers rebuilt from the web version to match the official numbering.
12. **SP 800-53 Rev. 5** — withdrawn controls and enhancements are kept, marked, for traceability.
13. **CVSS 4.0** — specification text verbatim; the score is never typed by hand but computed by `scripts/cvss4.py`, which reads FIRST's lookup tables (BSD-2-Clause) at runtime.
14. **Playbooks** — copied as `<name>/playbook.md` with a provenance comment and without `scripts/`. The 37 offensive playbooks (red teaming, offensive security) are indexed but not copied: this skill is defensive.
15. **security-audit** — methodology files copied verbatim with an origin header. The Node validators are ported to Python and extended with the mandatory `sources` checks; the schema is extended with `sources`, `cvss`, `category` and `package`.

## Conflicts between sources

**Precedence:**

1. The **verifiable requirement** beats the awareness category. If the Top 10 and ASVS seem to disagree, ASVS gives the compliance criterion. The same goes for the API Top 10 against ASVS, and for CSF outcomes against 800-53 controls.
2. The **specialised profile** beats the general one **within its scope**. For AI model development 800-218A extends SSDF 1.1; for incident response 800-61r3 refines CSF 2.0. They are read together and the extension does not repeal the base.
3. The **most recent version** wins, with the divergence declared. Never mix versions silently.
4. An unresolved conflict is **reported as such**, with both identifiers, instead of tacitly picking one.
5. The **crosswalk never wins**. It is an unreviewed navigation hint; if it contradicts the standard, the standard wins.
6. **Playbooks never win.** They are procedures; the standard judges.

## Known divergences

- **LLM Top 10 numbering.** Appendix A of ASI cites the **2025** list; this skill uses the renumbered **2026** list. The equivalence table is in `standards/owasp-asi-top10-2026.md`. The crosswalk uses 2026 and its `crossrefs.llm_top10` disagree with Appendix A for 8 of the 10 risks; this skill takes Appendix A as the normative reading and marks the rest as editorial.
- **T taxonomy names.** ASI Appendix A shortens some and in ASI06 uses labels absent from the guide (*T4 Memory Overload*, *T6 Broken Goals*, *T12 Shared Memory Poisoning*). The T identifiers are right; the canonical names are those of the Threats and Mitigations file.
- **ATLAS release.** The LLM Top 10 cites ATLAS 2026.06; this skill uses 2026.09. Known rename: `AML.TA0001` is *AI Attack Staging* in 2026.06 and *AI Attack Adaptation* in 2026.09.
- **Crosswalk identifiers.** `AML.T0045` (Disinformation), mapped to ASI09, does not exist in ATLAS 2026.09; `CWE-730` is a CWE category, which MITRE prohibits for vulnerability mapping. Neither may be cited as a finding source.
- **SAMM.** The 2020 V2.0 PDF is older than the official core model data release v2.2.0 (2026-07-06). The differences have not been checked.
- **CVSS 4.0 examples page.** For `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` FIRST's examples page shows 8.2, while FIRST's own reference calculator gives 9.2. `cvss4.py` follows the calculator and records the case in `KNOWN_DISCREPANCIES`. `tests/test_cvss4.py` runs that JavaScript calculator in QuickJS and checks that the port matches it on every official example and on 1,500 random vectors, including threat and environmental metrics.
- **Anthropic-Cybersecurity-Skills metadata.** Its OWASP mapping labels 2021 category names as 2025, and its ATT&CK Navigator layer is ATT&CK v14. Neither is imported; playbook IDs are verified against the current standard files instead. Two ICS IDs cited by playbooks, `T0807` and `T0853`, are deprecated in ATT&CK for ICS 20.0.
- **AI RMF wording.** AI 100-1 and the AI RMF Playbook word 22 subcategories differently; this skill cites AI 100-1.

## Exceptions and non-applicability

**NOT APPLICABLE** requires the requirement's identifier, the concrete reason (absent component, platform or functionality) and who determined it. A requirement marked NOT APPLICABLE without a reason is a process finding.

**Approved exception** requires the requirement's identifier, justification, compensating controls, owner and review date. SSDF `PO.1.2` asks for processes to handle exception requests **with periodic reviews of all approved exceptions**; an exception without a review date fails that requirement.

**NOT VERIFIED** requires what is missing to verify it and how it would be obtained. It never turns into PASS with the passage of time.

**Tier-B standards** (PCI DSS, ISO/IEC 27001, SOC 2, CIS Controls, IEC 62443, laws such as GDPR or HIPAA) cap the result at NOT VERIFIED with the candidate control named: this skill does not hold their text, and is not legal advice.

## Mandatory re-evaluation

- Exposure changes (internal becomes external) or tenancy changes.
- A new class of data is processed.
- A new tool, MCP server or capability in an agent.
- A model, adapter or embedding-encoder change; every alignment cycle of a model.
- A new version of any incorporated standard (`gen_inventory.py --refresh-status` flags newer releases and withdrawals).
- A security incident relevant to the scope.

## Pending work

- **The SC catalogue is a seed of 40 controls**, not a complete catalogue. Whole domains (files and uploads, WebRTC, OAuth/OIDC in detail, mobile beyond IPC, cloud control planes) still mean going straight to the standard file.
- **Three ASI companion guides are still out:** *Securing Agentic Applications Guide 1.0*, *Agentic AI MAS Threat Modelling Guide 1.0* and *Agent Name Service (ANS) 1.0* (available in `GenAI-Security-Project/GenAI-Security-Advisor`, `corpus/agentic-top10/companions/`).
- **OWASP AISVS**, cited by LLM10 and the crosswalk, could become the verifiable counterpart of ASVS for AI.
- **SAMM:** compare the 2020 PDF with core model data v2.2.0 and regenerate from the newer source if it differs.
- **SAMM PDF provenance:** it reached systema-cure without a recorded download URL; the manifest holds its hash (`"adopted": true`) but `fetch_sources.py` cannot re-download it. Regenerating SAMM from the official core model data (v2.2.0, see above) would fix both this and the version gap.
- **The crosswalk is unreviewed at source.** Its 993 mappings carry `confidence: unreviewed`. Identifiers are verified for the eight frameworks this skill holds (ASVS 44/44, 800-218A 40/40, SAMM 51/51 by practice name, ATLAS 29/30, CSF 40/40, AI RMF 40/40, CWE 49/50, FedRAMP via 800-53 40/40); the other frameworks are reproduced without verification.
- **The SC control → ASI risk link is editorial.** The crosswalk does not know SC controls; the chain is documented in `sc-controls-catalog.md`.
- **Editorial status values** in `INVENTORY.md` (marked ≈) were not verified online; refresh them when an official status page exists.
- **No CVSS v3.1 calculator.** Advisories that publish only a v3.1 vector are shown as published; this skill does not rescore them.
