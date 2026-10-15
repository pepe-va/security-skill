# cybersec-skill

A security skill for coding agents that answers with the standard, not with an opinion. It turns 29 official standards (OWASP, NIST, MITRE, CWE, CVSS 4.0, SLSA, CISA) into checkable controls, and every result it gives cites the standard, version, identifier and file that support it.

It works in three modes: a **consultation** while you design, code or review; a **code audit** of a repository; and a **dependency audit** for vulnerable or malicious packages. The audits end in a validated `findings.json` and a self-contained HTML report with a copyable mitigation prompt, criticals preselected.

## Installation

### Claude Code (plugin)

Inside a Claude Code session:

```text
/plugin marketplace add pepe-va/security-skill
/plugin install cybersec-skill@cybersec
```

The repository is its own marketplace (`.claude-plugin/marketplace.json`). A plugin install copies the whole repository, sources included; for a lean install clone it and use the symlink route below.

### Any agent that reads `~/.claude/skills` or `~/.agents/skills`

```bash
scripts/link-skills.sh
```

It symlinks each skill directory into those folders, so a `git pull` keeps the installed skill current.

## Skills

### Model-invoked

Model- or user-reachable: the agent reaches for it when a task fits.

- **[cybersec-skill](./skills/security/cybersec-skill/SKILL.md)**: Security consultant and scanner. Consultation by default; code audit and dependency audit only on explicit request. Gives PASS / FAIL / NOT APPLICABLE / NOT VERIFIED with cited sources, computes CVSS 4.0, and renders the audit report in English or Spanish.

## What is inside

| Mode | You ask | You get |
|---|---|---|
| Consultation | "Which controls apply to this API?", "is this secure?", "classify this finding" | Controls with a state, the evidence behind it and the sources. No files. |
| Code audit | "Audit this repository", "full security review" | Confirmed findings, leads needing validation and coverage, as `findings.json`, Markdown reports and `security-report.html`. Starts with an exposure sweep: environment-variable files under any name, keys, secrets in any language, secrets left in git history, `.gitignore` gaps, ports and services published by compose, Kubernetes, Terraform or service configs |
| Dependency audit | "Audit our dependencies", "anything malicious in our packages?" | CycloneDX SBOM, known vulnerabilities (OSV, CISA KEV, EPSS), known-malicious packages, malware signals and typosquats, in the same report |

For a quick look without an audit, `python skills/security/cybersec-skill/scripts/find_exposures.py <path>` prints the exposure sweep and writes nothing. Secret values are always masked.

The standards held in full, with their versions and how each was generated, are listed in the skill's [`references/governance.md`](./skills/security/cybersec-skill/references/governance.md). Every other standard cited by the source material, with its date and status, is in [`references/standards/INVENTORY.md`](./skills/security/cybersec-skill/references/standards/INVENTORY.md).

## Repository layout

```text
skills/security/cybersec-skill/   the installed skill: SKILL.md, references, runtime scripts, assets
docs/security/                    human-facing page for each skill
scripts/                          build: fetch_sources.py, gen_*.py, build_all.py; link-skills.sh, list-skills.sh
sources/                          official inputs with manifest.json (URL, SHA-256, date) and scan snapshots
tests/                            unit tests for the runtime scripts and the ID verifier
evals/                            skill-creator evals: prompts, fixtures, graded iterations
.claude-plugin/                   plugin manifest and marketplace
.agents/adr/                      architecture decisions
```

## Building

Everything under `references/standards/`, `references/crosswalk/` and `references/playbooks/` is generated from the official sources and never edited by hand.

```bash
python3 -m venv .venv && .venv/bin/pip install pypdf pyyaml beautifulsoup4 lxml markdownify quickjs
.venv/bin/python scripts/build_all.py             # fetch missing sources, refresh publication status, regenerate, verify, test
.venv/bin/python scripts/build_all.py --offline   # the same from what is already in sources/, no network
```

Download caches over 5 MB (the ATT&CK bundles, the SP 800-53 catalogue) and the OWASP Top 10 page cache are not committed, so a fresh clone needs one build with network before `--offline` works; `sources/manifest.json` keeps their URL and SHA-256.

The runtime scripts inside the skill need only the Python 3.9+ standard library.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). Report vulnerabilities in the skill privately, not in a public issue.

## Disclaimer

Not affiliated with or endorsed by OWASP, NIST, MITRE, FIRST, CISA or the OpenSSF. ATT&CK® and CWE™ are trademarks of The MITRE Corporation; CVSS is owned by FIRST and used by permission. This skill is not legal advice: laws and licensed standards are named, never interpreted.

## Licence

MIT for this repository's own code and text: see [`LICENSE`](./LICENSE). Material from the standards and the projects this skill builds on keeps its own licence (CC BY-SA 4.0 for OWASP content, the ATT&CK and CWE terms of use, Apache-2.0, BSD-2-Clause, public domain for US government works): see [`THIRD-PARTY-NOTICES.md`](./skills/security/cybersec-skill/THIRD-PARTY-NOTICES.md), which travels with the installed skill.
