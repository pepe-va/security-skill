# Third-party notices

This skill's own code and text are under the MIT licence (`LICENSE` at the root of the source repository). The material below keeps its own licence. **Files generated from a source keep that source's licence**: for example `references/standards/owasp-asvs-5.0.0.md` is an adaptation of OWASP ASVS and is distributed under CC BY-SA 4.0, not MIT.

Licences were read from each source on 2026-10-15 (the repository's licence file, or the publisher's terms where the content states its own).

| Material | Files in this skill | Licence or terms | Source |
|---|---|---|---|
| OWASP Top 10:2025 | `references/standards/owasp-top10-2025.md` | CC BY-SA 4.0 | https://github.com/OWASP/Top10 |
| OWASP ASVS 5.0.0 | `references/standards/owasp-asvs-5.0.0.md` | CC BY-SA 4.0 | https://github.com/OWASP/ASVS |
| OWASP SAMM 2.0 | `references/standards/owasp-samm-2.0.md` | CC BY-SA 4.0 | https://github.com/owaspsamm/core |
| OWASP API Security Top 10 2023 | `references/standards/owasp-api-top10-2023.md` | CC BY-SA 4.0 | https://github.com/OWASP/API-Security |
| OWASP MASVS 2.1.0 | `references/standards/owasp-masvs.md` | CC BY-SA 4.0 | https://github.com/OWASP/masvs |
| OWASP Top 10 for LLM Applications 2026, Top 10 for Agentic Applications 2026, Agentic AI Threats and Mitigations 1.1 | `references/standards/owasp-llm-top10-2026*.md`, `owasp-asi-top10-2026*.md`, `owasp-agentic-threats-mitigations-1.1.md` | CC BY-SA 4.0 (as stated in each document) | https://genai.owasp.org |
| OWASP GenAI crosswalk 4.0.0 | `references/crosswalk/` | CC BY-SA 4.0, © 2026 OWASP GenAI Data Security Initiative | https://github.com/GenAI-Security-Project/crosswalk |
| MITRE ATT&CK 20.0 | `references/standards/mitre-attack/`, ATT&CK identifiers across the skill | ATT&CK licence, reproduced below | https://github.com/mitre-attack/attack-stix-data |
| MITRE ATLAS 2026.09 | `references/standards/mitre-atlas*.md` | Apache-2.0, © 2021-2026 MITRE (licence text: `references/playbooks/LICENSE`) | https://github.com/mitre-atlas/atlas-data |
| MITRE D3FEND 1.6.0 | `references/standards/mitre-d3fend.md` | MIT | https://github.com/d3fend/d3fend-ontology |
| MITRE Fight Fraud Framework (F3) 1.2 | `references/standards/mitre-f3-1.2.md` | Apache-2.0 (licence text: `references/playbooks/LICENSE`) | https://github.com/center-for-threat-informed-defense/fight-fraud-framework |
| MITRE CWE 4.20 | `references/standards/cwe/` | CWE Terms of Use, reproduced below | https://cwe.mitre.org/about/termsofuse.html |
| CVSS v4.0 specification | `references/standards/cvss-4.0.md` | © FIRST.Org, Inc. CVSS is owned by FIRST and used by permission; FIRST licenses it freely subject to attribution | https://www.first.org/cvss/ |
| FIRST CVSS v4.0 calculator tables | `assets/cvss-calculator/*.js` (read by `scripts/cvss4.py`) | BSD-2-Clause, © FIRST, Red Hat, and contributors | https://github.com/FIRSTdotorg/cvss-v4-calculator |
| SLSA 1.2 | `references/standards/slsa.md` | Community Specification License 1.0 | https://github.com/slsa-framework/slsa |
| NIST publications: SP 800-218, 800-218A, 800-53 Rev. 5, 800-63B-4, 800-190, 800-207, 800-61r3, 800-86, 800-115, 800-40r4, CSF 2.0, AI 100-1 (AI RMF), AI 600-1, AI RMF Playbook | `references/standards/nist-*.md`, `nist-800-53r5/` | Works of the United States government: public domain in the US; the OSCAL catalogue also carries a CC0 1.0 waiver | https://csrc.nist.gov, https://github.com/usnistgov/oscal-content |
| CISA Zero Trust Maturity Model 2.0 | `references/standards/cisa-ztmm-2.0.md` | Work of the United States government: public domain in the US | https://www.cisa.gov/zero-trust-maturity-model |
| security-audit (Cloudflare), revision `c1c8a8c` | `references/audit/upstream/`; the validators in `scripts/` are ports of its `.cjs` validators; `schemas/report-schema.json` extends its schema | MIT, see `references/audit/upstream/LICENSE` | https://github.com/cloudflare/security-audit-skill |
| Anthropic-Cybersecurity-Skills playbooks, revision `54a798831d22` | `references/playbooks/` | Apache-2.0, see `references/playbooks/LICENSE` | https://github.com/mukul975/Anthropic-Cybersecurity-Skills |

Standards this skill only names (PCI DSS, ISO/IEC, SOC 2, CIS, IEC 62443 and others in `references/standards/tier-b-cards.md`) are not reproduced: their licences do not allow it.

## MITRE ATT&CK licence

```text
License
-------
The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research,
development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce
MITRE's copyright designation and this license in any such copy.

"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

Disclaimers
-----------
MITRE does not claim ATT&CK enumerates all possibilities for the types of actions and behaviors documented as part
of its adversary model and framework of techniques. Using the information contained within ATT&CK to address or cover
full categories of techniques will not guarantee full defensive coverage as there may be undisclosed techniques or
variations on existing techniques not documented by ATT&CK.

ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE
ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS,
AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT
THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR
FITNESS FOR A PARTICULAR PURPOSE.
```

## MITRE CWE Terms of Use

> CWE™ is free to use by any organization or individual for any research, development, and/or commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE's copyright designation and this license in any such copy. CWE is a trademark of The MITRE Corporation.

Copyright © The MITRE Corporation. Full terms: https://cwe.mitre.org/about/termsofuse.html

## Creative Commons Attribution-ShareAlike 4.0

Full licence: https://creativecommons.org/licenses/by-sa/4.0/legalcode. Adaptations in this skill (regenerated files, regrouped mappings, condensed tables) are marked as generated in their headers, name their source, and are shared under the same licence.
