# Scope

This repository holds a defensive security skill. A change is judged against the bar below.

## The bar

A change stays only if it clears **both** parts:

1. **Grounded.** It rests on an official, versioned source or on an observed failure: a session where the skill gave a wrong, unsupported or missing answer, or an eval that shows it. "It would be better if..." does not clear this part.
2. **Traceable.** Every requirement, identifier and mapping it adds exists in a standard file of the skill, and the build ends with `build complete` (generators, `verify_ids.py`, tests).

## What belongs

- **Tier-A standards**: only with an official, machine-readable or reproducible source, a generator that rebuilds the file from it, and a check against the source (counts, identifiers, or text matching for transcriptions). A licence that forbids reproduction makes a standard tier B.
- **SC controls**: only when they bind requirements that already exist in tier-A files, and never weaker than those requirements.
- **Audit methodology changes**: only when they keep the boundary-and-result rule, the verdicts and the execution safety rules.

## Out of scope

- Offensive tooling: exploit development, weaponised payloads, red-team playbooks (they are indexed, never copied), probing of deployed or shared systems.
- The text of licensed standards (PCI DSS, ISO/IEC, SOC 2, CIS, IEC 62443) and legal advice on laws (GDPR, HIPAA, DORA, NIS2, EU AI Act).
- Proving that a dependency or a system is clean: the audits find known problems and indicators only.
- Hand edits to generated files.
