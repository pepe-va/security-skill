# Skill Benchmark: cybersec-skill

**Date**: 2026-10-15T13:21:09Z · 4 evals, 1 run per configuration

| Metric | With Skill | Without Skill | Delta |
|---|---|---|---|
| Pass rate | 100% | 78% | +0.22 |
| Time (s) | 1376 ± 432 | 741 ± 336 | +634.4 |
| Tokens | 188694 ± 47802 | 82397 ± 18638 | +106297 |

## Per eval

| Eval | With skill | Without skill |
|---|---|---|
| mcp-agent-controls | 7/7 · 1325s · 213024 tok | 6/7 · 415s · 67124 tok |
| invoice-app-code-audit-es | 8/8 · 1916s · 212588 tok | 5/8 · 506s · 71272 tok |
| idor-finding-classification | 8/8 · 863s · 116993 tok | 7/8 · 924s · 82622 tok |
| shop-frontend-dependency-audit | 8/8 · 1399s · 212171 tok | 6/8 · 1121s · 108571 tok |

## Notes

- With the skill 31/31 assertions (100%); without 24/30 (80% pooled, 78% as the mean of the per-eval rates). One run per configuration, so there is no variance estimate: treat the deltas as indicative.
- Non-discriminating: finding the IDOR and the SQL injection, the lethal-trifecta analysis, lodash advisories, colour-utilz and expresss all pass in both configurations. A capable model finds these bugs without the skill.
- What the skill adds: a validated findings.json, sources for every finding, the mitigation prompt panel, a CycloneDX SBOM, the 'cannot prove clean' limit, and only current editions (the baseline cited LLM Top 10 2025 numbering and A01:2021).
- Cost: with the skill about 2.3x the tokens (mean 189k vs 82k) and 1.9x the time (mean 23 min vs 12 min). The audit modes pay for validators, the coverage ledger and sandboxed evidence; the consultation cited and checked 149 identifiers.
- Eval 2 with the skill demonstrated both bugs in a bwrap sandbox (no network, read-only source); the baseline did a static review only.
- Defects these runs exposed, now fixed: finding text stayed English inside the Spanish report (SKILL.md and audit/README.md now say to write finding text in the conversation's language); with no critical finding the prompt panel started empty (the most severe level present is now preselected); audit_deps.py took a fixed version from lodash-es, put guessed CVEs in titles and emitted no lockfile hardening notes.
- The eval 3 baseline downloaded reference pages and installed a Python CVSS library into the session scratchpad; the skill's bundled cvss4.py avoids that.
