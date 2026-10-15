# Security controls for the Jira-to-GitHub bug-fixing agent

**Short answer:** as you describe it, the agent combines all three conditions for a high-impact compromise. It reads **untrusted input** (Jira ticket text). It reaches **private data** (your source code, ticket contents and the bot token). And it can **change state and communicate**: it pushes branches, opens PRs, triggers CI and writes PR text that GitHub renders for other people. OWASP's minimum for that combination is human approval on each action, or removing one of the three conditions. "Fixes simple bugs on its own" does not meet it.

Prompt injection cannot be reliably prevented (OWASP LLM01:2026), so the controls that matter are architectural:

- what the bot identity can do on GitHub,
- where the code the agent writes is allowed to run,
- what the agent can write into PRs,
- that a human who did not ask for the change approves every merge.

## Must do before rollout

1. **Gate the agent** (item 1). Only tickets approved by a trusted engineer can enter. Every irreversible or privileged action waits for a human. Write down the residual risk of what stays automatic.
2. **Narrow the bot identity** (items 2, 3). Use a dedicated GitHub App with short-lived tokens, scoped to one repo per run. It gets write access to contents and PRs only: no admin rights, no access to workflow files or secrets, and no bypass of branch protection. Each run may reach only what the person who asked for it can reach.
3. **Put a policy check outside the model** (item 4). Code, not the model, decides which repo, which branch and which paths the agent may change.
4. **Require independent human review** (item 5). Every merge needs code-owner approval. Approvals are dismissed when new commits arrive. The person who requested the ticket cannot be the only approver.
5. **Keep agent code out of privileged CI** (item 6). Bot PRs run with no secrets, a read-only token and no deployment rights. The bot cannot edit workflow files.
6. **Sandbox the agent** (item 7). Each ticket gets a fresh container with an outbound allowlist. The GitHub token stays outside the container, held by a broker service.
7. **Make the Jira tools read-only and treat the MCP server as supply chain** (items 8, 9). Pin it, review its tool descriptions and watch them for changes.
8. **Clean up what the agent writes** (item 10). Remove external images and links from PR text. Turn on secret scanning with push protection.
9. **Operate it safely** (items 11-15). Keep secrets in a vault, label bot PRs, set hard limits, keep tamper-evident logs, rehearse a kill switch, and red-team before go-live.

## Context and assumptions

```text
System type:      AI agent (LLM with tools) acting as a development tool
Component:        agent runtime, its Jira MCP server, its GitHub identity, and the repos and CI it writes to
Phase:            architecture and design, before deployment (pre-rollout)
Exposure:         internal · single organisation, many users (every engineer) ·
                  boundaries: Jira text -> model -> GitHub -> CI; model provider is a third party
Data:             proprietary source code · ticket contents (may hold customer data or pasted credentials) · bot credentials
Identity:         one bot token with write access to repositories; effective privilege = whatever that token grants
Integrations:     Jira MCP server · GitHub API · CI (e.g. GitHub Actions) · hosted model API · package registries
AI context:       agent + tools via MCP · autonomy: picks tickets and opens PRs unattended · runs builds and tests
Business domain:  none (no payments, OT or federal workload)
ASVS level:       L2. The system is internal, but it holds a write credential to source code and handles business-sensitive data.
                  L3 items (for example V13.3.4 rotation) are recommended but not assessed here.
Out of scope:     see "Not applicable" at the end
```

I made these assumptions because they were not stated. Each one changes which controls apply.

- **A1.** There is a single agent: no sub-agents, no memory kept between tickets, and no vector index.
- **A2.** The model is a hosted provider API. No model weights are loaded locally.
- **A3.** Any employee can write Jira tickets and comments. If you run a service desk or email-to-ticket, outsiders can too.
- **A4.** The agent builds the code and runs tests to check its fix, so it executes repository code and installs dependencies.
- **A5.** Humans are meant to merge. "On its own" means the agent picks up tickets and opens PRs without asking anyone.
- **A6.** The token type (personal access token or GitHub App) and its permissions are unknown.
- **A7.** The agent is triggered by polling or a Jira label, not by an inbound webhook. If you add a webhook, re-assess it as an API (`references/by-component.md` → APIs).

You haven't shown me a running system. Results are therefore **NOT VERIFIED**, each with the evidence that would settle it. The one exception is item 1, which can be judged from your description alone.

---

## Gate decision

### 1. Classify the agent before choosing mitigations

```text
[SC-AI-03] Agent capability budget (lethal trifecta / Rule of Two)
State:     FAIL (the design as described; no severity, because nothing was demonstrated against a running system)
Context:   the whole agent, pre-rollout design
Evidence:  Your description, read against the three conditions:
           (A) untrusted input: ticket title, description, comments and attachments, writable by any employee (A3);
           (B) sensitive data: private repositories, ticket contents, the bot token;
           (C) state change and external communication: branch pushes, PRs, the CI runs they trigger,
               and PR/commit text that GitHub renders for others.
           "On its own" means none of these actions waits for a human. If merging already needs a review,
           the push, the CI run and the PR text still happen before anyone approves.
Sources:   OWASP Top 10 for LLM Applications 2026, LLM01:2026, mitigations 7 and 8 (lethal trifecta, Rule of Two)
             (references/standards/owasp-llm-top10-2026.md)
           SC-AI-03 (references/sc-controls-catalog.md)
           OWASP Top 10 for Agentic Applications 2026, ASI01, mitigations 2 and 4 (references/standards/owasp-asi-top10-2026.md)
           OWASP LLM03:2026, mitigation 7, graduated enforcement (references/standards/owasp-llm-top10-2026.md)
           MITRE ATLAS 2026.09, AML.T0051.001 LLM Prompt Injection: Indirect; mitigation AML.M0030
             Restrict AI Agent Tool Invocation on Untrusted Data (references/standards/mitre-atlas.md)
           CWE 4.20, CWE-1427 Improper Neutralization of Input Used for LLM Prompting (references/standards/cwe/weaknesses.md)
Action:    Narrow condition A. The agent only takes tickets that an engineer from an allowlisted group has approved
           (by label or transition). It processes exactly the snapshot that was approved. Any later edit or new
           comment voids the approval. Attachments and linked URLs are ignored.
           Put a human approval in front of every irreversible or privileged action: merges (always), CI jobs that
           can see secrets, and any write outside the agent's own branch namespace.
           Let only reversible, contained actions run automatically: pushing to agent/* branches and opening draft
           PRs in the one repo mapped to the ticket. That follows LLM03's graduated policy. It does not satisfy the
           Rule of Two by itself, so write the residual-risk assessment and record it in the threat model
           (SC-TM-01, SSDF PW.1.1) with an independent design review (SC-VER-01, SSDF PW.2.1).
           The Rule of Two is a floor and says nothing about how deep autonomy goes. Apply items 2-15 as well.
```

## Identity and permissions

### 2. A narrow, short-lived identity on GitHub

```text
[SC-AI-02 / ASI03] Least-privilege, short-lived bot identity
State:     NOT VERIFIED (token type and permissions not provided, A6)
Context:   the GitHub credential the agent's tools use
Evidence:  None yet. A long-lived personal access token with broad repo scope on a shared account
           would FAIL v5.0.0-13.2.1 and v5.0.0-13.2.2.
Sources:   OWASP ASVS 5.0.0, v5.0.0-13.2.1 (individual service accounts and short-term tokens, not unchanging
             credentials or API keys), v5.0.0-13.2.2 (least privilege) (references/standards/owasp-asvs-5.0.0.md)
           OWASP LLM03:2026, mitigations 1-4 (minimise tools, functionality and permissions)
           OWASP ASI02, mitigations 1 and 6 · ASI03, mitigation 1 (task-scoped, time-bound permissions)
           MITRE ATLAS AML.M0028 AI Agent Tools Permissions Configuration
           CWE-250 Execution with Unnecessary Privileges
Action:    Use a dedicated GitHub App (or an equivalent machine identity), not a person's or a shared user's
           personal access token. Install it only on the pilot repositories.
           Grant only: contents read/write (to push branches), pull requests read/write, metadata read.
           Do not grant administration, workflow-file write, secrets, environments, Actions administration or any org scope.
           Keep it off every branch-protection and ruleset bypass list. It must not be able to merge, approve,
           force-push or delete branches other than its own.
           Verify against GitHub's effective permissions (what GitHub actually allows, not what was intended). From
           staging, try to push to main, edit .github/workflows, approve a PR and merge one, and confirm that GitHub
           rejects every attempt. Instructions in the prompt are not a control.
```

### 3. Rolling out to everyone must not hand everyone the bot's access

```text
[ASI03] Each run reaches only what the person who asked can reach
State:     NOT VERIFIED
Context:   org-wide rollout: any employee can steer the agent by writing a ticket
Evidence:  None yet. With one bot identity for everyone, whoever writes a ticket borrows the bot's access.
           A ticket in project X could steer the agent to read repo Y and copy it into a PR seen by a different
           audience. ASI03 calls this "Identity Sharing" (Example Attack Scenario 7). In CWE terms it is a confused deputy.
Sources:   OWASP ASI03, Example Attack Scenario 7 and mitigations 1 and 7 (references/standards/owasp-asi-top10-2026.md)
           OWASP LLM03:2026, mitigation 5 (execute tools in the user's context, keep the original scope through chained calls)
           MITRE ATLAS AML.M0027 Single-User AI Agent Permissions Configuration (an agent is never granted
             permissions the user would not have)
           OWASP ASVS 5.0.0, v5.0.0-8.3.1 (authorisation enforced at a trusted service layer)
           CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')
Action:    Code binds each run to one requester and one target repository: a fixed map from Jira project or component
           to repo. Refuse the run if the requester, or the engineer who approved the ticket, lacks write access to
           that repo. The stronger option is to act through the requester's own least-scope OAuth delegation, so
           GitHub itself enforces this.
           Issue each run's token for that single repository only.
           The agent clones only the target repo. Give it no org-wide code search tool.
```

### 4. Code outside the model decides every write

```text
[SC-AI-02] Complete mediation by a policy check outside the model
State:     NOT VERIFIED
Context:   the tool layer between the model and GitHub/Jira
Evidence:  None yet. If the system prompt is the only thing keeping the agent away from CI files or other repos,
           this is a FAIL. Hidden context is not a security boundary.
Sources:   OWASP LLM03:2026, mitigation 7 (complete mediation)
           OWASP ASI02, mitigation 4 (policy enforcement before execution, the "Intent Gate")
           OWASP LLM01:2026, mitigation 4 (keep credentials and the ability to change state in application code, not in the model)
           SC-AI-02, SC-AI-01 (references/sc-controls-catalog.md)
           OWASP ASVS 5.0.0, v5.0.0-8.3.1
Action:    Give the model narrow tools with strict schemas, such as "commit these files to agent/<ticket>" and
           "open a draft PR", instead of a general GitHub, git or shell tool.
           Before anything executes, deterministic code checks:
           - the repo is the one mapped to the ticket;
           - the branch name matches agent/<ticket-id>;
           - there is no force-push;
           - no changed path is on the denylist: .github/, CODEOWNERS, infrastructure as code, auth or crypto code,
             dependency manifests and lockfiles (changes there go to a human instead);
           - the diff is under a size cap.
           Log every denial.
```

## Code path into your repositories

### 5. A human who did not ask for the change approves every merge

```text
[A03:2025 / SSDF PS.1.1 / SLSA Source L4] Independent human review of agent-written code
State:     NOT VERIFIED
Context:   protected branches of every repository the agent can push to
Evidence:  None yet.
Sources:   OWASP Top 10:2025, A03:2025 ("No single person should be able to write code and promote it all the way to
             production without oversight from another human being"; protect branches) (references/standards/owasp-top10-2025.md)
           NIST SP 800-218 SSDF 1.1, PS.1.1 (example 4: the code owner reviews and approves all changes made by others),
             PW.7.2 (references/standards/nist-ssdf-800-218.md)
           SLSA v1.2, Source L4 two-party review; Source Roles, where a "trusted robot" is one whose "identity and
             codebase cannot be unilaterally influenced" (references/standards/slsa.md)
           SC-AI-07 note (never deploy LLM-generated code without human review and security testing) · OWASP ASI05, mitigation 2
           MITRE ATLAS AML.M0029 Human In-the-Loop for AI Agent Actions
Action:    On default and release branches, use branch protection or rulesets:
           - a PR is required;
           - at least 1 approval from CODEOWNERS;
           - stale approvals are dismissed when new commits are pushed (SLSA: the final revision is what must be approved);
           - required status checks pass;
           - no bypass for the bot.
           Separation of duties: the person who filed or approved the ticket cannot be the only approver of the
           resulting PR. Otherwise one person writes code through the agent and approves it themselves. GitHub does
           not enforce this natively, so add a required check that compares the PR's approvers with the ticket's requester.
           Do not give the agent the "trusted robot" exception that SLSA allows for bots such as Dependabot. Anyone
           who writes a ticket influences this bot, so it does not meet the definition. If you are aiming for
           Source L4, the bot is the uploader, not a trusted person, so you need two trusted human reviewers.
```

### 6. Agent-written code never runs in a privileged pipeline

```text
[SSDF PO.5.1 / SC-ENV-01] Bot PRs are untrusted contributions in CI
State:     NOT VERIFIED
Context:   CI workflows triggered by the bot's pushes and PRs
Evidence:  None yet. This is where an injected ticket becomes secret theft: the agent adds a test or build step,
           and CI runs it with whatever secrets that event exposes.
Sources:   OWASP Top 10:2025, A03:2025 (CI/CD weaker than what it builds; build server and CI/CD with separation of
             duties and environment-scoped secrets)
           NIST SSDF 1.1, PO.5.1 (separate and protect each environment; keep non-production use of production
             services to a minimum)
           SC-ENV-01 (references/sc-controls-catalog.md) · OWASP ASI05, mitigations 2 and 4
           Audit companion: "Untrusted code in a privileged workflow" (references/audit/upstream/SUPPLY-CHAIN-AND-RELEASE.md)
Action:    Treat bot PRs like PRs from an outside contributor:
           - no repository or org secrets;
           - a read-only workflow token;
           - no deployment environments;
           - no self-hosted runners on the internal network.
           Require a human to approve workflow runs on bot PRs, or run only an unprivileged test job until merge.
           The bot cannot change workflow files (no workflow permission, plus CODEOWNERS on .github/), so it cannot
           widen its own CI access.
           Branch names, PR titles and commit messages carry attacker-influenced text. Never interpolate them into
           shell steps.
```

### 7. The agent's own runtime is sandboxed and holds no credentials

```text
[ASI05] Sandboxed, ephemeral execution with an outbound allowlist
State:     NOT VERIFIED
Context:   the environment where the agent clones, edits, builds and tests (A4)
Evidence:  None yet. Fixing bugs means running repository code, test suites and dependency installs. Unexpected
           code execution is part of the job description.
Sources:   OWASP ASI05, mitigations 4 and 5 (never run as root; sandboxed containers with network limits; per-session
             isolation; keep code generation separate from execution)
           OWASP ASI02, mitigation 3 (execution sandboxes and outbound allowlists)
           OWASP ASVS 5.0.0, v5.0.0-13.2.4 (an allowlist of external systems the application may talk to)
           MITRE ATLAS AML.M0032 Segmentation of AI Agent Components (clean image per run, no state carried over)
           OWASP ASI10, mitigation 6 (keys are never directly available to agents; an orchestrator signs or acts on their behalf)
Action:    Run one ephemeral container or VM per ticket, as non-root, from a clean image, and destroy it after the run.
           Block outbound traffic by default. Allow only the model API, the Jira MCP endpoint and your internal
           package mirror.
           Keep the GitHub token out of the sandbox. A broker service holds it and pushes the diff after the item 4
           checks pass. Then a test that dumps environment variables cannot steal it.
           Put no cloud, database or production credentials in the sandbox.
```

### 8. Jira text is untrusted, and the Jira tools are read-only

```text
[LLM01:2026 / LLM03:2026] Read-only Jira access; ticket text treated as untrusted
State:     NOT VERIFIED
Context:   the Jira MCP server and the ticket text it returns to the model
Evidence:  None yet. LLM01:2026 describes this exact pattern: text planted in an issue tracker makes an agent act
           with its own elevated credentials (Common Example 3). In Scenario #9, a poisoned GitHub issue
           exfiltrated private repositories through an MCP-connected agent.
Sources:   OWASP LLM01:2026, Common Example 3, mitigations 5 and 6, Scenario #9
           OWASP ASI01, mitigations 1 and 6
           OWASP LLM03:2026, mitigations 1-3 (minimise tools and functionality; avoid open-ended tools)
           MITRE ATLAS AML.T0051.001 (indirect injection) · AML.T0099 AI Agent Tool Data Poisoning ·
             AML.T0093 Prompt Infiltration via Public-Facing Application (if a customer portal or email feeds Jira)
           CWE-1427
Action:    Enable only the Jira read tools the agent needs: get a ticket, or search within allowlisted projects.
           Disable create, comment, transition and delete. If you want a status comment, the broker posts a fixed template.
           Give the MCP server's Jira credential read-only access to the pilot projects only.
           Strip invisible characters (tag-block, variation-selector, zero-width) from ticket text, and pass the text
           to the model as labelled data, not as instructions. Both defences are partial: an attacker who knows the
           labels can imitate them. Items 2-7 are what actually limit the damage.
           Give the model no tool to fetch URLs, browse the web or run shell commands. Those tools are open-ended.
```

### 9. The Jira MCP server is a supply-chain component

```text
[ASI04] Agentic supply chain: MCP server, tool descriptions, model provider
State:     NOT VERIFIED
Context:   which Jira MCP server you run (vendor-hosted or a community package) and how it is updated
Evidence:  None yet.
Sources:   OWASP ASI04, mitigations 1, 2, 7 and 8 (provenance; allowlist and pin; pin by content hash; kill switch)
           OWASP LLM01:2026, mitigation 10 · LLM04:2026 (including risk 7, the provider's terms and data policy)
           MITRE ATLAS AML.T0010.005 AI Supply Chain Compromise: AI Agent Tool · AML.T0110.000 AI Agent Tool Poisoning:
             Definition and Instructions · AML.T0109 AI Supply Chain Rug Pull
           NIST SSDF 1.1, PO.3.2 (assess the security of each tool; regularly verify its integrity and provenance)
           SC-SUP-01, SC-SUP-02, SC-SUP-04 (references/sc-controls-catalog.md)
Action:    Prefer the vendor's MCP server or one you build yourself. For a community package, review the code and run
           a dependency audit on it before adoption.
           Pin it by version and content hash, and deploy updates only after review. Never auto-update.
           Snapshot the tool names, descriptions and schemas the server sends to the model, and alert when they change.
           Pinning does not catch poisoned descriptions shipped without a version change.
           Do the same check on the model provider. The agent sends it proprietary code and ticket contents, so
           confirm the provider's data-use and retention terms (LLM04 risk 7).
```

### 10. What the agent writes into GitHub cannot carry data out

```text
[SC-AI-07 / LLM10:2026] PR text sanitised, commits scanned for secrets
State:     NOT VERIFIED
Context:   PR titles and bodies, commit messages, branch names, code comments
Evidence:  None yet. Blocking the sandbox's network is not enough. An injected agent can put a Markdown image into
           the PR body whose URL carries data, and the data leaves when the PR is viewed and the image is fetched.
Sources:   OWASP LLM10:2026, mitigation 9 (model output must not trigger automatic fetches of Markdown images or link
             previews; use an allowlist, or a proxy that strips data-bearing query parameters)
           SC-AI-07 (references/sc-controls-catalog.md)
           MITRE ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation
           OWASP LLM02:2026 (sensitive information disclosure)
           SC-SEC-01 · OWASP ASVS 5.0.0, v5.0.0-13.3.1 (no secrets in source code)
Action:    In the broker, strip or allowlist URLs and images in PR text and commit messages, and strip control and
           invisible characters. Branch names come from a template, never from model text.
           Turn on secret scanning with push protection for bot pushes. Tickets often contain pasted logs with
           credentials or personal data, and once committed they stay in git history. A secret that reaches history
           must be rotated, not just deleted (SC-SEC-01).
```

## Operation

### 11. Credentials live in a vault, never in the prompt

```text
[SC-SEC-01 / SC-AI-01] Secret management for the bot key and the model API key
State:     NOT VERIFIED
Context:   the GitHub App private key, the model API key and the Jira service credential
Evidence:  None yet.
Sources:   OWASP ASVS 5.0.0, v5.0.0-13.3.1, v5.0.0-13.3.2 · SC-SEC-01, SC-AI-01 (references/sc-controls-catalog.md)
           OWASP LLM02:2026, Tier 1 item 4 (never put secrets in system prompts) · CWE-798 Use of Hard-coded Credentials
Action:    Keep these keys in a secrets manager, readable only by the broker. Never put them in code, images,
           config repositories or the system prompt, and assume the system prompt will leak.
           Document a rotation schedule. Alert when a credential is used from an unexpected host.
```

### 12. Reviewers judge the diff, not the agent's own explanation

```text
[ASI09] Protect human review from automation bias and approval fatigue
State:     NOT VERIFIED
Context:   the engineers who approve bot PRs
Evidence:  None yet. The agent writes its own PR description, and a hijacked agent writes a convincing one.
           Approval fatigue grows with PR volume.
Sources:   OWASP ASI09, mitigations 4, 5 and 6 (a risk summary that is not generated by the model; trust calibration; provenance)
           OWASP Agentic AI Threats and Mitigations 1.1, T10 Overwhelming Human in the Loop; Playbook 5
             (references/standards/owasp-agentic-threats-mitigations-1.1.md)
           OWASP LLM01:2026, mitigation 7 (show the exact action; approval fatigue)
           NIST SSDF 1.1, PW.7.2 (example 4: static analysis with human triage)
           SC-SUP-03 note (check that AI-suggested dependencies exist and are the intended package) · ASI05, Scenario 8
Action:    Label bot PRs. The broker, not the model, adds a factual header: ticket link, requester, files changed,
           policy checks run, and flags for changes to dependencies, CI or auth.
           Require SAST and tests as status checks on bot PRs.
           Any new or changed dependency needs an explicit check that the package exists and is the intended one
           (the agent may invent a look-alike name). Never regenerate lockfiles from unpinned specs.
           Cap the number of bot PRs per repo per day.
```

### 13. Hard limits that stop the run

```text
[SC-AI-08] Consumption limits and circuit breakers
State:     NOT VERIFIED
Context:   the agent loop and the queue of tickets
Evidence:  None yet.
Sources:   SC-AI-08 (references/sc-controls-catalog.md) · OWASP LLM06:2026 · ASI02, mitigation 5 ·
           LLM03:2026, mitigation 9 · CWE-770
Action:    Per run, set limits on steps, time, recursion depth and cost, and detect loops.
           Overall, limit concurrent runs and PRs per hour. A limit must stop the run, not just raise an alert.
```

### 14. Every action can be traced to a person and cannot be altered

```text
[SC-LOG-01 / SC-LOG-02] Audit logging of the agent
State:     NOT VERIFIED
Context:   the broker, the MCP server, the GitHub audit log
Evidence:  None yet.
Sources:   OWASP ASVS 5.0.0, v5.0.0-16.2.1, v5.0.0-16.3.2, v5.0.0-16.3.3, v5.0.0-16.4.2, v5.0.0-16.4.3, v5.0.0-16.2.5
           OWASP ASI02, mitigation 8 · ASI08, mitigation 10 · T8 Repudiation and Untraceability
           SC-LOG-01, SC-LOG-02 (references/sc-controls-catalog.md) · CWE-778, CWE-532
Action:    For each run, log in UTC:
           - run ID;
           - ticket ID and the hash of the approved snapshot;
           - requester and approver;
           - model and prompt version;
           - every tool call with its arguments;
           - every policy decision, allowed or denied;
           - the resulting commit SHA and PR.
           Send the logs to a separate store the agent cannot write to.
           Prompts and completions contain ticket text, so mask secrets and personal data before they reach your log
           platform.
           Alert on policy denials and unusual sequences, for example a ticket read followed by writes to an
           unexpected repo, or a burst of PRs.
```

### 15. A kill switch, and red-teaming before go-live

```text
[ASI10 / ASI04] Containment
State:     NOT VERIFIED
Context:   incident response for the agent
Sources:   OWASP ASI10, mitigation 4 (kill switches, credential revocation) · ASI04, mitigation 8 (supply-chain kill switch)
Action:    Write down one procedure and rehearse it before rollout: suspend the GitHub App, revoke the MCP
           credential, drain the queue, close open bot PRs.

[SC-AI-10] Adaptive red teaming as the release gate
State:     NOT VERIFIED
Context:   staging Jira and GitHub, before the org-wide rollout
Sources:   SC-AI-10 (references/sc-controls-catalog.md) · OWASP LLM01:2026, mitigation 11 · ASI01, mitigation 8 ·
           MITRE ATLAS AML.T0051.001, AML.T0053, AML.T0086
Action:    Give the testers the full design. Have them write tickets that try to:
           (a) put environment variables or another repo's code into a PR;
           (b) edit workflow files;
           (c) touch a repo outside scope;
           (d) add a look-alike dependency;
           (e) exfiltrate data through a Markdown image;
           (f) hide instructions in invisible Unicode.
           Record the results, tagged with ATLAS IDs.
           Go-live criterion: every attempt is stopped by an enforced control (permissions, the policy check, the
           sandbox, the review), not by the model declining.
```

---

## Not applicable (with the reason, and when that changes)

- **ASI06 Memory & Context Poisoning, SC-AI-04.** The agent keeps no memory between tickets (A1). These apply as soon as it stores notes or "learned fixes".
- **ASI07 Insecure Inter-Agent Communication.** There is a single agent with no sub-agents or agent-to-agent traffic (A1). Traffic between the MCP client and server is covered by items 8-9. Add ASI07 if you introduce sub-agents.
- **SC-AI-05 and SC-AI-06** (authorisation before retrieval; vector stores). There is no index of code or tickets for retrieval (A1). These apply if you add one.
- **SC-AI-09 and the model-development tasks of NIST SP 800-218A.** You call a hosted model and load no weights (A2). These apply if you self-host open-weight models.
- **MITRE F3 and API6:2023** (no money movement), **ATT&CK for ICS** (no OT), **SP 800-53** (no federal workload stated), **ASVS V3 and MASVS** (no web or mobile front end).
- **ISO/IEC 27001, ISO/IEC 42001, SOC 2 and the EU AI Act** were not assessed. This skill doesn't hold their text, so the best possible result is NOT VERIFIED with a candidate control named. Ask if you need that mapping.

## What turns these NOT VERIFIED results into PASS

Each result settles on the following evidence:

- GitHub's effective permissions for the bot and the export of your rulesets (items 2, 5, 6).
- The broker's policy code and the log of its denials (items 3, 4, 10).
- The sandbox image and its network policy (item 7).
- The list of enabled MCP tools and the snapshot of their descriptions (items 8, 9).
- The red-team report (item 15).

Send me those, or the agent's code, and I can reassess each item against them. For the code, I can also run a full source-code audit.
