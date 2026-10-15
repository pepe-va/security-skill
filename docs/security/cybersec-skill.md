## What it does

`cybersec-skill` answers security questions with the standard instead of an opinion, and audits code and dependencies on request. Every result names the standard, its version, the requirement's identifier and the file in the skill that holds it, so you can check the claim yourself.

Its defining constraint is that **a result without a source is not a result**. When the evidence is missing it says NOT VERIFIED and how to verify, instead of guessing PASS or FAIL; when a standard's text is not in the skill (PCI DSS, ISO 27001), the best it can say is NOT VERIFIED with the candidate control named.

## When to reach for it

Type `/cybersec-skill`, or the agent reaches for it automatically when a task fits: designing or reviewing an API, a web or mobile app, cloud or CI/CD, an LLM, RAG or MCP integration; asking "is this secure" or "which controls apply"; classifying a finding.

| Your situation | Mode |
|---|---|
| A design, a diff or a snippet, and the question "what applies / is this right?" | Consultation (default, no files) |
| A pentest or scanner finding to classify | Consultation: CWE, CVSS 4.0 computed, severity, requirements broken |
| "Audit this repository", "full security review" | Code audit (starts with the exposure sweep) |
| "Is there an exposed .env, a secret or an open port in this repo?" | Exposure sweep on its own: a summary, no files |
| "Audit our dependencies", "anything malicious in our packages?", "SBOM" | Dependency audit |
| Both of the last two | Full audit: one run, one report |

The audits never start from a vague request: the skill asks one question first.

## Prerequisites

Python 3.9 or later for its scripts (standard library only). The dependency audit queries OSV, CISA KEV and EPSS when the network allows it; without network those checks come back NOT VERIFIED. An audit writes its files outside the audited repository, by default in `<parent>/<repo>-security-audit/run-<N>`.

## Four states and a source for each

Every control ends in one of four states: **PASS**, **FAIL**, **NOT APPLICABLE** (with the reason) and **NOT VERIFIED** (with how to verify). Audit findings add a verdict: **confirmed** needs a source trace and bounded local evidence, **needs_validation** names the missing fact, **rejected** is kept so the next run does not repeat it.

The sources come from 29 standards held in full: OWASP (Top 10:2025, ASVS 5.0.0, API Top 10, MASVS, SAMM, LLM and Agentic Top 10), NIST (SSDF, 800-218A, 800-53, 800-63B-4, CSF 2.0, AI RMF, AI 600-1 and the 800-series guides), MITRE (ATT&CK, ATLAS, D3FEND, F3, CWE), CVSS 4.0, SLSA and CISA's Zero Trust Maturity Model. A validator rejects any confirmed finding that does not cite a requirement and a CWE that exist in those files.

## The report

An audit ends in `security-report.html`: one self-contained file, in the language of the conversation, with the findings and their sources, the leads that still need validation, the coverage, and a **mitigation prompt**. Tick the findings to fix (criticals come ticked, or the most severe ones when there is no critical) and copy the prompt into your coding agent.

## Common questions

**It found the same bugs I would have found without it. What does it add?**

In the evals, the model without the skill found the same IDOR and SQL injection. What it lacked was the rest: a `findings.json` that passes a validator, a source for every finding, the mitigation prompt, a CycloneDX SBOM, and current editions (without the skill it cited the 2021 OWASP Top 10 and the 2025 LLM Top 10).

**Why is it slower and more expensive than asking directly?**

It reads the standards it cites, computes CVSS with FIRST's algorithm and, in audits, validates every finding and records coverage. The evals measured about 2.3 times the tokens and twice the time. For a quick opinion, ask without it; for something you will act on or show to someone, use it.

**Why does a design review come back mostly NOT VERIFIED?**

Because a description is not evidence. It marks FAIL only what your description already proves (for example an agent that reads untrusted tickets, holds private code and acts on its own) and lists, for everything else, the evidence that would settle it.

**Does it find exposed `.env` files and open ports?**

In the repository, yes, and in any language. The exposure sweep finds environment-variable files whatever their name (by name, or because the content is `KEY=VALUE` lines), keys and credential files, secrets written in code or config (including key names such as `contraseña` or `Passwort`), secrets left in git history, `.gitignore` gaps, and services published by docker-compose, Kubernetes, Terraform or a service's own config. Secret values are always masked. It does not scan a running server: a published port in the config is a lead until the deployment's network rules show who can reach it.

**Does a clean dependency audit mean my packages are safe?**

No. It finds known vulnerabilities, known-malicious packages and signs of malice; static analysis cannot prove that a package is clean, and the report says so.

**Can it test my live site?**

No. Audits read source code and run target code only inside an isolated sandbox with no network. They never probe deployed or shared systems.

## It's working if

- Every control or finding it gives you carries a standard, a version, an identifier and a file you can open.
- It says NOT VERIFIED, and how to verify, where you expected a confident answer from a description alone.
- It asks before starting an audit you did not clearly request.
- The audit report's prompt panel opens with the most severe findings already ticked.

## Where it fits

A **reach-for-it-anytime standalone**: consult it while you design and code, run the code and dependency audits before a release or after a big change, and use the report's prompt to hand the fixes to a coding agent. Its governance file (`references/governance.md` in the skill) lists every standard, how it was generated and what is still missing.
