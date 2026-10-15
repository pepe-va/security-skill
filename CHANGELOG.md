# cybersec-skill

## 1.0.0 (2026-10-15)

First release, built from three sources: the systema-cure skill (nine standards, Spanish), the methodology of Cloudflare's security-audit skill, and the standards and playbooks of Anthropic-Cybersecurity-Skills.

- Three modes in one skill: consultation, code audit, dependency audit (see [ADR 0001](./.agents/adr/0001-one-skill-three-modes.md)).
- 29 tier-A standards generated from their official sources, each verified against it: OWASP Top 10:2025, ASVS 5.0.0, API Security Top 10 2023, MASVS 2.1.0, SAMM 2.0, LLM Top 10 2026, Agentic Top 10 2026, Agentic Threats and Mitigations 1.1; NIST SSDF 1.1, SP 800-218A, 800-53 Rev. 5, 800-63B-4, CSF 2.0, AI RMF 1.0, AI 600-1, 800-190, 800-207, 800-61r3, 800-86, 800-115, 800-40r4; CISA ZTMM 2.0; SLSA 1.2; MITRE ATT&CK 20.0, ATLAS 2026.09, D3FEND 1.6.0, F3 1.2; CWE 4.20; CVSS 4.0.
- Inventory of 241 standards cited by the sources, with tier, publication date and status checked online, and a section for withdrawn revisions and never-finalised drafts.
- 39 SC controls, 7 of them new (authenticator strength, postMessage origin, safe deserialisation, per-principal quotas, tenant isolation, local IPC, malicious packages).
- Every finding cites standard, version, identifier and file; the validators enforce it, and `verify_ids.py` checks 1,161 identifiers cited by the skill's own text.
- CVSS 4.0 scores computed by a port of FIRST's calculator, checked against FIRST's JavaScript on 1,500 random vectors and every official example.
- Dependency audit: CycloneDX SBOM, OSV (including OpenSSF malicious packages), CISA KEV, EPSS, malware signals, typosquats, dependency confusion and lockfile hardening notes.
- HTML report in English or Spanish, self-contained with a strict CSP, with a mitigation prompt panel.
- GitHub Actions workflow running the tests and the ID verifier on every push.
- Repository laid out as a skills repository: `skills/<bucket>/<skill>/`, plugin manifests, docs pages, build scripts and sources outside the installed skill (see [ADR 0002](./.agents/adr/0002-build-outside-the-installed-skill.md)).
