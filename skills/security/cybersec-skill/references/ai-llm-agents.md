# View of AI, LLMs, RAG, tools, MCP and agents

The densest view of the skill. Enter through the capability you are adding.

## Boundary rule

This skill covers the model **as a component of an application**. As soon as the model becomes an **actor** — tools it can call, memory it carries across sessions, consequences it triggers downstream — the risk also belongs to the **OWASP Top 10 for Agentic Applications (ASI)**.

**If you are building an agent, start with `standards/owasp-asi-top10-2026.md`**: identify which of the ten ASI risks is in front of you and follow its routing to the LLM risks, views and SC controls that cover it in full.

Two more files branch from there:

- `standards/owasp-agentic-threats-mitigations-1.1.md` — the **T1-T17** taxonomy ASI refers to, with the *Agentic Threat Decision Path* (six questions that narrow which threats apply), the six mitigation playbooks split into proactive / reactive / detective, and four example threat models.
- `crosswalk/ASI0n.md` — the official crosswalk for the risk: candidate controls in 25 frameworks. Unreviewed at the source; use it to find the requirement, not to judge compliance.

**ASI and Threats & Mitigations 1.1 are incorporated in full**, so results can be issued against `ASI**` and `T*` identifiers. Still out: the companion guides *Securing Agentic Applications Guide*, *MAS Threat Modelling Guide* and *Agent Name Service (ANS)*.

**Auditing an AI system's code:** mode 2 with the companion `audit/upstream/AI-AND-LLM.md` (context and retrieval, tool and action, MCP and sub-agent trust, output and disclosure attack classes).

## Models and providers

**Look at:** where the model comes from, who signs it, the provider's terms, and whether your data ends up training it.

**Standards:** LLM04 (supply chain) · `800-218A PW.4.1`, `PW.4.4`, `PS.2.1`, `PS.3.2` · ATLAS `AML.T0010` AI Supply Chain Compromise · AI 600-1 risk *Value Chain and Component Integration*.

**Checks:**
- Resolve models by **immutable digest**, never by a mutable tag or by `Author/ModelName` alone (*namespace reuse* vector).
- Signature ≠ security. A model validly signed by a compromised provider can still carry a backdoor.
- Model scanners and safe-loading flags are **defence in depth, not a guarantee**: they have had bypasses with assigned CVEs.
- A backdoor can live in the **computational graph** of a "safe" format such as ONNX, with no executable code to flag.
- Quantisation is a transformation: guarantees at full precision **do not transfer** to the deployed quantised artifact.
- Review the operator's terms and privacy policy: `PO.1.3`, LLM04 risk 7.

## Prompts and context

**Standards:** LLM08 Hidden Context Exposure · LLM02 · ATLAS `AML.TA0008` Discovery.

**Hard rules:**
- **Design assuming hidden context is discoverable.** Nothing in it may be treated as secret.
- Never credentials, connection strings or tokens in the system prompt.
- Hidden context **is not a security boundary**: authorisation, privilege separation, policy enforcement and content filtering happen outside the model, deterministically and auditably.
- Specialised fine-tuning lowers disclosure risk but **gives no consistent guarantee**.

## Prompt injection and jailbreak

**Standards:** all of LLM01 · ATLAS `AML.TA0004`, `AML.TA0005`, `AML.TA0006`, `AML.TA0007`, `AML.TA0010`.

**Posture:** no reliable prevention mechanism exists. **Defence is architectural, not interceptive.** Design assuming the instruction boundary will eventually be bypassed and limit what the model can do and how far its outputs reach.

**Threat modelling — decompose along LLM01's three axes before choosing mitigations:**

| Axis | Values |
|---|---|
| Delivery surface | direct input · retrieved content · tool output · tool connection channel · persistent memory |
| Propagation | single-shot · multi-step kill chain · cross-session (memory or RAG) · self-replicating across agents |
| Encoding | plain text · base64 or obfuscation · invisible Unicode · multimodal or steganographic · low-resource language |

**Pre-deployment check — the *lethal trifecta*:** an agent that simultaneously (A) accesses private data, (B) ingests untrusted content and (C) can communicate externally has the conditions for high-impact exploitation. **Removing any one leg removes them.**

**Rule of Two as a floor:** any [A,B,C] agent needs **per-action** human approval; [A,B] or [A,C] configurations need an explicit, documented residual-risk assessment.

**Evaluation trap:** reject static-only attack-success metrics. Static success can be near zero while adaptive success exceeds 90%. Red-team **with the full defence specification disclosed to the testers**.

## RAG and document sources

**Standards:** LLM09 (embedding geometry) · LLM05 (durable poisoning) · LLM01 (injection through retrieved content) · LLM02 (authorisation at retrieval) · ATLAS `AML.T0070` RAG Poisoning.

**Separate the three problems, which are constantly confused:**

| Problem | Entry | Dominant mitigation |
|---|---|---|
| The retrieved passage carries instructions | LLM01 | Separate channel and provenance labelling; least privilege |
| Poisoned content persists in the corpus | LLM05 | Ingestion validation, provenance, versioning, rollback |
| The attacker manipulates **what is retrieved** without malicious instructions | LLM09 | Anomaly detection at ingestion and retrieval, segregation by trust level |

**Hard rules:**
- **Authorise before retrieving**, inside the index query. Post-filtering cannot undo a chunk already handed to the model. Cosine similarity does not respect ACLs.
- Access control **at chunk level**: a mostly public document can contain a confidential paragraph.
- Multi-tenant: physically separate indexes at high sensitivity. A tenant filter applied after the search **leaks through side channels** (counts, scores, timing).
- Do not return raw similarity scores to the client: they turn the index into a **membership oracle**.
- When rotating the embedding model, **re-index the whole corpus**. Mixing vectors from different encoders creates exploitable gaps.
- Treat vector database backups **at the same sensitivity as the source documents**: zero-shot inversion reconstructs the text without access to the original encoder.

## Memory

**Standards:** LLM01 (mitigation 9) · LLM05 · LLM09 (vector-backed memory) · ATLAS `AML.T0080.000` Memory, `AML.TA0006` Persistence.

**Hard rules:**
- **Memory writes are privileged operations.** Log the causing prompt, classify writes looking for instruction or role-modification content, and require approval before memory with instructions persists across sessions.
- One contaminated entry reaches **every future session** that reads it.
- Factual entries drift towards instructions, and incremental writes evade per-write classification. Assume imperfect detection.

## Tools, function calling and MCP

**Standards:** LLM03 (Excessive Agency) · LLM01 (mitigation 10) · LLM06 (loops and fan-out) · LLM10 (outputs) · `800-218A PO.5.1`.

**LLM03's three root causes, by frequency:**

1. **Excessive functionality** — the third-party tool you picked to read can also delete and send. Single-purpose tools, strict parameter schemas, validation before use.
2. **Excessive permissions** — the identity the tool uses downstream has more than it needs, or is a generic high-privilege identity. Enforced **in the target system**, not in the agent's logic.
3. **Excessive autonomy** — no independent verification of high-impact actions.

**Hard rules:**
- **Complete mediation:** authorisation is implemented in logic, never by delegating to the LLM the decision of whether an action is allowed. A policy decision point before execution, or the target system itself.
- **Execute in the user's context**, with least-scope OAuth. In delegated or multi-agent flows, **preserve the original authorisation context and scope through chained calls**: do not rely on the calling agent's permissions or on a service identity.
- **Graduated policy** (audit, warn, block, escalate): auto-approve what is reversible, escalate to a human what is irreversible.
- **Treat MCP servers and tool packages as supply chain**: pin, sign, verify, and audit tool descriptions for hidden instructions. Pinning stops neither a payload in the pinned version nor description poisoning without a version change. Dependency audit (mode 3) covers the packages.
- Tool schemas exposed in context are **concrete targets** for later injection (LLM08 risk 1).

## Agents and autonomy

**Standards:** LLM03 · LLM06 (circuit breakers) · LLM07 (cross-agent propagation) · LLM01 (self-replication) · ATLAS.

**Mandatory circuit breakers in every agent run:** step limit, recursion-depth limit, time limit, **per-run cost ceiling**, and state hashing to detect loops.

**Trust between agents:** wrong state or evidence produced by one agent and trusted by another propagates as a compound failure (LLM07). A downstream agent **must not treat an upstream agent's output as verified evidence**.

**Cost:** accumulated agentic context means every turn reprocesses everything before it. No single request trips rate limits and the aggregate reaches hundreds of dollars (LLM06 scenario 8). Measure **cost per session**, not per request.

## Execution and resource access

**Standards:** LLM10 · LLM03 · ATLAS `AML.TA0005` Execution.

**Hard rules:**
- Model output into a shell, `exec`/`eval`, SQL, file paths or mail templates: **context-specific validation and encoding are mandatory**. Treat the model like any other user, zero trust.
- **Strip control characters** (ANSI, BEL, OSC, backspace, carriage return) before writing to a terminal, log or IDE panel. OSC 52 allows clipboard hijacking.
- In client renderers, **disable by default automatic rendering** of Markdown images, link previews and iframes: they are the exfiltration channel through hostname or query string.
- Never build and deploy LLM-generated code without human review and security testing.

## Evaluation and red teaming

**Standards:** LLM01 (mitigation 11) · LLM02 (tier 3, red teaming as a release gate) · LLM05 (mitigation 10) · `800-218A PW.8.1`, `PW.8.2`, `RV.1.2` · ATLAS as the tagging taxonomy · AI RMF MEASURE 2.7 (security and resilience evaluated) · AI 600-1 suggested actions under MEASURE.

**Hard rules:**
- **Tag every offensive finding with its `AML.T****`.** Without a common taxonomy findings are not comparable across campaigns.
- Baseline with AgentDojo and JailbreakBench; then adaptive red teaming.
- **Dedicated trigger probing after every alignment cycle.** Standard safety alignment **does not remove** embedded backdoors.
- Re-evaluate models when they are retrained or data sources are added (`800-218A PW.8.2.R2`).
- Disclosure red teaming covers six distinct surfaces: extraction, membership inference, embedding inversion, internal-state inversion, side channels and LoRA extractability.

## Governance of AI systems

**NIST AI RMF 1.0** (`standards/nist-ai-rmf-1.0.md`): GOVERN (policies, accountability, third-party risk), MAP (context, categorisation, impacts), MEASURE (methods, trustworthiness evaluation, tracking), MANAGE (prioritisation, response, third-party, communication). Use it when the question is organisational: who decides, on what context, with what evidence.

**NIST AI 600-1** (`standards/nist-ai-600-1.md`): the 12 generative-AI risks (CBRN, confabulation, dangerous content, data privacy, environmental impacts, harmful bias, human-AI configuration, information integrity, information security, intellectual property, obscene content, value chain) and 211 suggested actions keyed to AI RMF subcategories (`GV-1.1-001` …).

Both are voluntary frameworks: PASS / FAIL needs organisational evidence, otherwise NOT VERIFIED. The EU AI Act is tier B (`standards/tier-b-cards.md`) and this skill is not legal advice.
