# Context model and applicability

Without context there is no applicability. This file is the first step of every consultation and every audit: it decides **which controls come into play and which are a justified NOT APPLICABLE**.

## The nine questions

Answer them before opening any standard. If you do not know an answer, that is already a finding: record it as an explicit assumption.

### 1. System type

Web application · API · internal service · mobile · CLI or SDK · infrastructure · AI system · agent · OT/ICS.

> Sets the **base set**: ASVS V3 and V17 apply only to web frontends and WebRTC; V4 to web services; MASVS only to mobile apps; LLM01-10, 800-218A, ATLAS, AI RMF and AI 600-1 only when a model is involved; ATT&CK for ICS only to OT.

### 2. Component

Which concrete part is being created or changed. Do not assess "the application": assess the endpoint, module, pipeline or tool in front of you.

> A change to a single endpoint rarely activates more than 15-25 requirements. If your list has 200, the component is not narrowed down.

### 3. Phase

Requirements · architecture and design · implementation · review and testing · build and supply chain · deployment · operation · maintenance and retirement.

> Decides **which view to use** (`lifecycle.md`) and which SSDF tasks are in play. A design control (PW.1, PW.2) is not verified the same way in production as before code is written.

### 4. Exposure and trust

Internal or external · trust boundaries · connected users and systems · multi-tenant or single-tenant.

> **Multi-tenant changes the assessment at the root**: it activates ASVS V8.4.1, LLM09 risk 1 (cross-tenant leakage through shared similarity search) and LLM02 (shared KV cache).

### 5. Data

Nature and sensitivity: PII · PHI · financial data · credentials and keys · business secrets · classified or export-controlled material · biometric and genomic identifiers · public data.

> Sets severity and the **applicable regulatory regime** (tier B: GDPR, HIPAA, PCI DSS…). Also decides whether LLM02 goes from informational to critical.

### 6. Identity and privileges

How it authenticates · what it authorises · which effective permissions the component has on downstream systems · which identity it connects with.

> Key question for agents: **the identity the tool connects with downstream, not the agent's**. That is where LLM03 (Excessive Agency), ASVS V8 and ASI03 live. For human authentication, the AAL of `standards/nist-800-63b-4.md`.

### 7. Integrations

Third parties · APIs · webhooks · queues · providers · models · plugins · MCP · tools · packages and dependencies.

> Each integration is a supply-chain surface (A03:2025, SSDF PW.4, SLSA, LLM04, mode 3 dependency audit) and an indirect-injection surface (LLM01, semi-trusted and trusted surfaces).

### 8. AI context

LLM use · RAG · embeddings and vector store · persistent memory · agents · tools · degree of autonomy · execution capability.

> If every answer is "no", **LLM01-10, ASI, 800-218A, ATLAS, AI RMF and AI 600-1 are NOT APPLICABLE** and you must say so explicitly instead of ignoring them.

### 9. Business domain

Does the system move money or value (payments, banking, wallets, marketplaces, refunds, loyalty points)? Is it critical infrastructure (energy, OT)? Is it a federal or regulated workload?

> Money or value activates **MITRE F3** for fraud paths and API6:2023. OT activates ATT&CK for ICS (and tier-B IEC 62443, NERC CIP). Federal or FedRAMP context makes **SP 800-53** the expected control language. Organisation-level questions (programme, governance) bring in **CSF 2.0**.

## Applicability rules

1. **NOT APPLICABLE needs a reason.** "We do not use WebRTC" is a reason. Silence is not.
2. **The platform bounds.** An ATLAS or ATT&CK technique whose `platforms` do not match the system is NOT APPLICABLE. The same goes for technology-bound ASVS chapters.
3. **The ASVS level comes from the context, not from taste.** Decide L1, L2 or L3 from exposure and data sensitivity, and declare the chosen level before assessing. An L3 requirement assessed against a system declared L1 is noise.
4. **Aggregation changes the classification.** Individually allowed sources that combine into a forbidden conclusion are a disclosure (LLM02). Assess the whole, not just the pieces.
5. **AI context is inherited upwards, not downwards.** If a single component integrates an LLM, the whole system enters the scope of LLM01-10 through the trust boundary, even if the rest never touches the model.
6. **Re-assess when the context changes.** An internal application exposed to the Internet, or an agent that gains a new tool, invalidates the previous assessment.
7. **Tier-B standards cap the result.** Against a standard whose text this skill lacks (`standards/tier-b-cards.md`), the best result is NOT VERIFIED with the candidate control named.

## Output of this phase

```text
System type:      <...>
Component:        <...>
Phase:            <...>
Exposure:         <internal|external> · <single|multi>-tenant · boundaries: <...>
Data:             <classes> · applicable regime: <...>
Identity:         <authentication> · effective downstream privileges: <...>
Integrations:     <...>
AI context:       <no> | <LLM|RAG|embeddings|memory|tools|MCP|agent> · autonomy: <...>
Business domain:  <payments|OT|federal|none> · extra standards: <F3|ATT&CK ICS|800-53|...>
ASVS level:       L1 | L2 | L3  (justified)
Out of scope:     <standards NOT APPLICABLE + reason>
```

In audit mode, store the same fields in `run-metadata.json` → `context` (keys `system_type`, `component`, `phase`, `exposure`, `data`, `identity`, `integrations`, `ai_context`, `business_domain`, `asvs_level`, `out_of_scope`); the HTML report shows them.
