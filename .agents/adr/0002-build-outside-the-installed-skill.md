# Keep the build outside the installed skill

The standards in the skill are generated from official sources: PDFs, STIX bundles, OSCAL and CPRT exports, CSV and YAML releases. Those inputs weigh 116 MB, the generators need third-party Python packages (pypdf, pyyaml, beautifulsoup4, lxml, markdownify), and none of it is read when the skill runs. Before this decision they lived in the skill's `tools/` folder, so the installed skill weighed 144 MB.

## Decision

- The skill directory ships only what runs: `SKILL.md`, `references/`, `assets/` (report template, FIRST's CVSS lookup tables), `schemas/`, `scripts/` (stdlib-only runtime tools) and `THIRD-PARTY-NOTICES.md`. It weighs 28 MB.
- The build lives at the repository root: `scripts/` (generators, `fetch_sources.py`, `build_all.py`), `sources/` (inputs, `manifest.json` with URL, SHA-256 and date, status cache, scan snapshots), `tests/`, `evals/`.
- Generators write into `skills/security/cybersec-skill/`. `gen_cvss.py` also copies FIRST's lookup tables into the skill's `assets/`, because `cvss4.py` reads them at runtime.
- `verify_ids.py` resolves paths in the repository when it is there; in an installed copy it skips paths that only exist in the repository instead of reporting them as broken.

## Consequences

- An installed skill cannot regenerate itself; a maintainer works from the repository.
- A plugin install copies the whole repository, sources included. The symlink route (`scripts/link-skills.sh`) installs only the skill directory.
- The origin repositories were deleted from the project on 2026-10-15. `gen_inventory.py` and `gen_playbooks.py` rebuild from the snapshots `sources/inventory-scan.json` and `sources/playbooks-catalogue.json`; rescanning needs a clone of the public repositories at the recorded revisions, in the repository root.
