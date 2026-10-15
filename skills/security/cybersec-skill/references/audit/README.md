# Audit modes — code audit (mode 2) and dependency audit (mode 3)

This folder turns the skill from a consultant into a scanner. The method is Cloudflare's **security-audit** skill (https://github.com/cloudflare/security-audit-skill, revision `c1c8a8c`), vendored verbatim in `upstream/` (MIT, see `upstream/LICENSE` and `upstream/README.md`), with the integration rules below. Read this file first: where it disagrees with an upstream file, this file wins.

## When these modes run

Only on an explicit request to audit, scan or pen-test a codebase or its dependencies, a request for a full / comprehensive / end-to-end review, or a request for the report. Loading the skill does not authorise creating files. If the request could be a quick question instead, ask one focused question before creating anything (upstream rule, `upstream/SECURITY-AUDIT.md` → *Operating modes*).

| Mode | Scope | Procedure |
|---|---|---|
| 2 — code audit | The repository's own source | `upstream/SECURITY-AUDIT.md` → phases 1-6 in `upstream/RECONNAISSANCE.md`, `upstream/HUNTING.md`, `upstream/VALIDATION-AND-REPORTING.md`, attack classes in `upstream/ATTACK-CLASSES.md` and the domain companions; exposure sweep in phase 1 (`exposures.md`) |
| 3 — dependency audit | Third-party packages, lockfiles, vendored code | `dependencies.md` (uses `scripts/audit_deps.py`) |
| 2 + 3 — full audit | Both | Run both; one `findings.json`, one ledger, one report |

Profiles (`quick`, `standard`, `deep`), scoped runs and budgets are options inside a mode (`upstream/SECURITY-AUDIT.md` → *Run profiles and scope*).

## Overrides of the upstream text

| Upstream says | In this skill |
|---|---|
| `report-schema.json` | `schemas/report-schema.json` — same contract plus `sources` (required), `cvss`, `category`, `package` |
| `node <skill-dir>/validate-findings.cjs <file>` | `python scripts/validate_findings.py <file>` |
| `node <skill-dir>/validate-coverage-ledger.cjs <file>` | `python scripts/validate_ledger.py <file>` |
| `SKILL.md` of security-audit | `upstream/SECURITY-AUDIT.md` |
| Default output `~/security-audit-skill/<repo>/run-<N>` | `<parent of the target>/<repo>-security-audit/run-<N>` — outside the target. If it is not writable, ask the user for a path; never fall back to `/tmp` or the home directory |
| Phase 6 writes `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md` | The same three files **plus** `security-report.html` from `scripts/render_report.py` (below) |
| Parallel sub-agents for hunters and verifiers | Use them when the platform has them. Without them, see *No sub-agents* below |

Everything else in `upstream/` applies as written: the boundary-and-result rule, bounded local evidence, source visibility, the candidate gate, write isolation, the execution sandbox, coverage ledger and critic waves, and the anti-patterns.

## Exposure sweep (phase 1)

Run `python scripts/find_exposures.py <target> --out <output-dir>` during reconnaissance. It covers deterministically what the *Obvious things* hunter checks by hand (`upstream/ATTACK-CLASSES.md`): environment-variable files under any name, keys and credential stores, secrets in any programming language, secrets left in git history, `.gitignore` gaps, and services published by compose, Kubernetes, Terraform or service configs. Its `exposures-findings.json` holds leads with sources; triage them into `findings.json` as `exposures.md` describes. The hunter still reads the code: the sweep finds known patterns, not every exposure.

## Unified states

A finding and a control are different things; the audit links them.

| Axis | Values | Comes from |
|---|---|---|
| Finding verdict | `confirmed` · `needs_validation` · `rejected` | security-audit |
| Control state | PASS · FAIL · NOT APPLICABLE · NOT VERIFIED | `../../SKILL.md` §3 |
| Severity (confirmed only) | critical · high · medium · low · informational, plus a computed CVSS v4.0 | security-audit + `../standards/cvss-4.0.md` |

- `confirmed` → the control it demonstrates broken is **FAIL**.
- `needs_validation` → that control is **NOT VERIFIED**, with the exact missing fact. No severity, no CVSS.
- `rejected` → no change to any control. Kept so later runs do not repeat the claim.

### Severity

Use the upstream anchors (`upstream/SECURITY-AUDIT.md` → *Separate priority from certainty*):

- **critical** — an unauthenticated actor gains code execution, full data-store access, or takeover of arbitrary accounts.
- **high** — an actor fully defeats an explicit security control with real consequences (authentication bypass, cross-tenant read or write, stored script execution affecting others, authenticated code execution, unauthenticated remote stop of a shared service).
- **medium** — a real boundary violation with limited blast radius, uncommon preconditions, or a narrow resource set.
- **low** — disclosure of non-secret internals, or an effect needing sustained effort for minimal gain.
- **informational** — confirmed but minimal impact.

Overall severity never exceeds demonstrated impact (the validator enforces it). Add a `cvss` block when the result can be expressed as a vector: write the vector for **what was demonstrated**, compute it with `python scripts/cvss4.py "<vector>"` and copy the output — the validator recomputes it and rejects any difference. If CVSS and the anchor disagree, say why in the description; the anchor decides the finding's severity.

## Sources: every finding is justified by its standards

`sources` is mandatory for `confirmed` and `needs_validation` records. Each source is an object:

```json
{"standard": "OWASP ASVS", "version": "5.0.0", "id": "v5.0.0-8.2.2",
 "file": "references/standards/owasp-asvs-5.0.0.md", "relation": "violated-requirement", "tier": "A"}
```

| `relation` | What it is | Typical standard |
|---|---|---|
| `violated-requirement` | The verifiable requirement the finding shows broken — **required (tier A) for `confirmed`** | ASVS, 800-63B, MASVS, SSDF, 800-218A, 800-53, SLSA, API Top 10 is *not* one (awareness list) |
| `weakness` | The root-cause CWE — **required for `confirmed`** | CWE |
| `risk-category` | Awareness category the finding belongs to | OWASP Top 10:2025, API Top 10, LLM Top 10, ASI |
| `attack-technique` | Adversary technique the exploitation matches | ATT&CK, ATLAS, F3 |
| `countermeasure` | Defence that addresses it | D3FEND, ATT&CK mitigation |
| `threat` | Threat-model entry | Agentic T1-T17, AI 600-1 risk |
| `governance-outcome` | Organisational outcome affected | CSF 2.0, AI RMF, 800-61r3 |
| `maturity-practice` | Practice gap behind it | SAMM, ZTMM |
| `severity-basis` | What grounds the severity | CVSS 4.0 spec |
| `candidate-control` | A control in a standard whose text this skill lacks — **the only allowed relation for tier B** | PCI DSS, ISO 27001, SOC 2… (`../standards/tier-b-cards.md`) |

Rules the validator enforces: every tier-A `file` exists under `references/` and contains the `id`; tier-B sources point at `references/standards/tier-b-cards.md` and are only candidates. Use `quote` to paste the requirement's exact words when it helps the reader.

**How to find the sources fast:** name the root cause's CWE (`../standards/cwe/`), read its row in the CWE → Top 10:2025 index (`../standards/cwe/README.md`), then the ASVS chapter or component view for the verifiable requirement (`../by-component.md`, `../domains.md`). For AI components start from `../ai-llm-agents.md`; for dependencies, `dependencies.md` lists the usual set.

## No sub-agents

security-audit assumes isolated sub-agents so that the agent that finds a candidate never validates it. When the platform cannot spawn them:

1. Run the phases in order yourself, but keep the roles apart: finish all hunting and write the candidate list before starting validation; validate each candidate by trying to **disprove** it from the source, using the verifier prompt in `upstream/VALIDATION-AND-REPORTING.md` as a checklist.
2. Record `"independent_verification": false` and the reason in `run-metadata.json`.
3. The report states, in its first section, that verification was not independent. Never present such a run as independently verified.

## Phase 6 — the HTML report

After both validators pass:

```bash
python scripts/render_report.py <output-dir> --lang <es|en>
```

It reads `findings.json`, `run-metadata.json` and `coverage-ledger.json` from the output directory and writes `<output-dir>/security-report.html`: a single self-contained file (no network) with the summary, context, confirmed findings with their sources, the leads that need validation, coverage, and a **mitigation prompt panel** — one checkbox per confirmed finding, criticals preselected, and a *Copy* button. Pick `--lang` from the language of the conversation (Spanish conversation → `es`); default `en`. The finding text in `findings.json` (titles, descriptions, remediation, hardening notes) is what the report shows, so write it in that same language; identifiers and field names never change.

`run-metadata.json` may carry an optional `context` object (the output of `../context-model.md`: system type, component, exposure, data, identity, integrations, AI context, ASVS level, out-of-scope standards) and `hardening_notes` (list of strings); the report shows them when present.

## Execution safety (summary of upstream)

Source inspection is read-only. Target-controlled code runs only inside an OS-enforced sandbox with no external network, an allowlisted empty environment, a read-only target and explicit resource limits; otherwise it does not run and the lead stays `needs_validation`. No installs, no dependency fetches by the build, no probing of deployed or shared systems, dummy principals and secrets only, minimum effect. Full text: `upstream/SECURITY-AUDIT.md` → *Universal execution safety*.

## Files in `upstream/`

| File | Use |
|---|---|
| `SECURITY-AUDIT.md` | Modes, setup, write isolation, planning, profiles, budget, core principles, workflow, anti-patterns |
| `RECONNAISSANCE.md` | Phase 1 and the coverage ledger |
| `HUNTING.md` | Phase 2: hunter prompt, candidate gate, structured results, critic waves |
| `ATTACK-CLASSES.md` | Core, wildcard and obvious-things attack classes |
| `VALIDATION-AND-REPORTING.md` | Phases 3-6 |
| `AI-AND-LLM.md`, `WEB-PROTOCOL-AND-AUTH.md`, `CLIENT-SIDE.md`, `SUPPLY-CHAIN-AND-RELEASE.md`, `CLOUD-AND-DEPLOYMENT.md`, `PROTOCOLS-RPC-AND-MESSAGING.md`, `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`, `DATA-ISOLATION-AND-LIFECYCLE.md`, `DESKTOP-MOBILE-AND-LOCAL-IPC.md`, `MEMORY-SAFETY-AND-BINARY.md` | Domain companions selected in phase 1 |
