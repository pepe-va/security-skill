# One skill with three modes, not one skill per mode

The skill consults (which controls apply, is this secure, classify this finding), audits a codebase, and audits dependencies. These could be three skills, or two (a model-invoked consultation skill holding the standards, and a user-invoked audit skill that loads it through the Skill tool). We keep **one model-invoked skill with three modes**.

## Considered options

- **Two skills** (`cybersec` model-invoked, `cybersec-audit` user-invoked). The audit could not start unless the user typed it, which enforces "loading the skill does not authorise an audit" by construction, and the consultation `SKILL.md` would be smaller. Cost: the audit skill needs the standards held by the other skill, and its validators need the other skill's directory to resolve each source's `file`.
- **Three skills** (consultation, code audit, dependency audit). The schema, the validators and the report template would be duplicated in both audit skills, and a full audit would need two launches.
- **One skill** (chosen by the user on 2026-10-15). Everything shares one directory: findings cite `references/...` paths the validator resolves directly, and a full audit is one run.

## Consequences

- The model can reach the audit modes. `SKILL.md` keeps the guard in prose: modes 2 and 3 run only on an explicit request, and an ambiguous request gets one question before any file is created.
- Every consultation loads the whole `SKILL.md`, audit sections included. The iteration-1 evals measured about 2.3 times the tokens of a run without the skill; trimming `SKILL.md` is the first lever if that cost matters.
- Revisit if an eval shows the model starting an audit nobody asked for, or if the token cost of consultations becomes the main complaint. The two-skill split above is the ready alternative.
