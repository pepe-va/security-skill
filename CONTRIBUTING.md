# Contributing

Thanks for helping. This is a defensive security skill whose value is that every answer is traceable to a standard, so contributions are judged on two things: that they rest on an official source or an observed failure, and that they keep every identifier traceable. [`SCOPE.md`](./SCOPE.md) states the bar; [`AGENTS.md`](./AGENTS.md) holds the conventions an agent (or a person) follows when changing the repository.

## Reporting a vulnerability in the skill

Do not open a public issue. Use GitHub's private reporting (**Security → Report a vulnerability**) on this repository. Examples: a script that executes target code, follows a symlink out of the target, writes an unmasked secret, or a report page that can run attacker-controlled script.

## Reporting a problem

Open an issue with:

- **What you ran**: the mode (consultation, code audit, dependency audit) and the prompt, or the script and its arguments.
- **What happened** and **what you expected**: a wrong or unsupported answer, a missing or invented identifier, a false positive or a false negative of a script.
- **The smallest input that shows it.** For scanner problems, a few synthetic lines are enough. **Never paste a real secret**, even a revoked one: build a fake value with the same shape.

"It would be better if…" without an observed failure is a discussion, not an issue.

## Setting up

```bash
git clone https://github.com/pepe-va/security-skill.git && cd security-skill
python3 -m venv .venv && .venv/bin/pip install pypdf pyyaml beautifulsoup4 lxml markdownify quickjs
.venv/bin/python scripts/build_all.py            # first build needs network: download caches are not committed
.venv/bin/python -m unittest discover -s tests   # quick loop while you work
```

The runtime scripts in `skills/security/cybersec-skill/scripts/` need only the Python 3.9+ standard library; the build dependencies are for `scripts/` at the root.

## Rules for every change

- **English everywhere**: code, docs, file names, commit messages. Only the audit HTML report renders in Spanish.
- **Generated files are never edited by hand.** Everything under `references/standards/`, `references/crosswalk/` and `references/playbooks/` comes from a generator in `scripts/`: change the generator or its input, then run `scripts/build_all.py --offline`.
- **Every identifier you cite must exist** in a standard file of the skill. `verify_ids.py` checks the skill's own text; the validators check findings. Never cite a superseded revision as a requirement (`references/standards/INVENTORY.md` → *Not current*).
- **Never weaken a requirement.** Explanations and automation stay at least as demanding as the source.
- **Runtime scripts stay safe on hostile input**: stdlib only, read-only on the target, never execute target code, never contact the target's hosts, never follow symlinks out of the target, and never write a secret value unmasked.
- **Tests come with the change.** A script change adds a case that fails without it; a new detection pattern in `find_exposures.py` adds both a positive and a negative case to `tests/test_find_exposures.py`. Test secrets are synthetic; mark literals that only look like secrets with `# exposures: ignore`.
- **Behaviour changes update the docs**: `SKILL.md` and the reference it points to, the page in `docs/`, and `CHANGELOG.md`.
- **Structural decisions get an ADR** in `.agents/adr/NNNN-short-title.md`: context, options, decision, consequences.

## Adding or upgrading a standard

1. Check its licence. Text you may not redistribute (PCI DSS, ISO/IEC, SOC 2, CIS, IEC 62443) stays tier B: a card in `scripts/gen_inventory.py`, never its text.
2. Add its official input to `scripts/fetch_sources.py`; the manifest records URL, SHA-256 and date.
3. Write or update its `scripts/gen_<standard>.py`, verifying the result against the source (counts, identifiers, or text matching for transcriptions), and place it in `scripts/build_all.py`'s order.
4. Record it in `references/governance.md` (version, how obtained, transformations, divergences), in the tier-A catalogue of `scripts/gen_inventory.py`, and in `THIRD-PARTY-NOTICES.md`.
5. Route to it: a query map in `SKILL.md`, a view, or an SC control's traceability line.

## Evals

Changes to how the skill behaves are measured, not assumed. Prompts, expectations and fixtures live in `evals/`; run each prompt with and without the skill into `evals/iteration-<N>/`, then `python evals/grade.py iteration-<N>` and `python evals/aggregate.py iteration-<N>`. The fixtures are intentionally vulnerable: keep them read-only, never deploy them.

## Pull requests

- [ ] `python scripts/build_all.py --offline` ends with `build complete`
- [ ] Tests added or updated for the change
- [ ] `CHANGELOG.md` entry, and `version` bumped in `.claude-plugin/plugin.json` for a release
- [ ] Docs updated if behaviour changed
- [ ] No real secrets, no personal paths, no generated file edited by hand

Contributions are accepted under the repository's MIT licence. Third-party material you add keeps its own licence and must be listed in `THIRD-PARTY-NOTICES.md`.
