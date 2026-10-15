# security-audit, vendored

**Source:** https://github.com/cloudflare/security-audit-skill, revision `c1c8a8c` (2026-09-14), directory `skills/security-audit/`. **Licence:** MIT, see `LICENSE`.

Every file here is a byte-for-byte copy, with one rename: `SECURITY-AUDIT.md` is the upstream `SKILL.md`, renamed so no loader mistakes it for a second skill. Its frontmatter is kept as published.

The upstream validators (`validate-findings.cjs`, `validate-coverage-ledger.cjs`), their tests and `report-schema.json` are in `sources/security-audit/`, as the reference for the Python ports.

Where this methodology and the rest of the skill disagree, `../README.md` decides.
