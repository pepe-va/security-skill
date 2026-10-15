# ASI06: Memory & Context Poisoning

## Description

Agentic systems rely on stored and retrievable information which can be a snapshot of its conversation history, a memory tool or expanded context, which supports continuity across tasks and reasoning cycles. Context includes any information an agent retains, retrieves, or reuses, such as summaries, embeddings, and RAG stores but excludes one-time input prompts covered under LLM01 :2025 Prompt Injection.

In Memory and Context Poisoning, adversaries corrupt or seed this context with malicious or misleading data, causing future reasoning, planning, or tool use to become biased, unsafe, or aid exfiltration. Ingestion sources such as uploads, API feeds, user input, or peer-agent exchanges may be untrusted or only partially validated.

This risk is distinct from ASI01 (Goal Hijack), which captures direct goal manipulation, and ASI08 (Cascading Failures), which describes degradation after poisoning occurs. However, memory poisoning frequently leads to goal hijacking (ASI01), as corrupted context or long-term memory can alter the agent’s goal interpretation, reasoning path, or tool-selection logic.

It builds on LLM01:2025 Prompt Injection, LLM04:2025 Data and Model Poisoning, and LLM08:2025 Vector and Embedding Weaknesses, but focuses on persistent corruption of agent memory and retrievable context that propagates across sessions and alters autonomous reasoning.

It maps to T1 Memory Poisoning in Agentic Threats and Mitigations, with related impacts in T4 Memory Overload, T6 Broken Goals, and T12 Shared Memory Poisoning. In AIVSS, the AARS fields Memory Use and Contextual Awareness raise the agentic vulnerability score.

## Common Examples of the Vulnerability

1. RAG and embeddings poisoning: Malicious or manipulated data enters the vector DB via poisoned sources, direct uploads, or over-trusted pipelines. This results in false answers which are considered and targeted payloads.

2. Shared user context poisoning: Reused or shared contexts let attackers inject data through normal chats, influencing later sessions. Effects include misinformation, unsafe code execution, or incorrect tool actions.

3. Context-window manipulation: An attacker injects crafted content into an ongoing conversation or task so that it is later summarized or persisted in memory, contaminating future reasoning or decisions even after the original session ends.

4. Long-term memory drift: Incremental exposure to subtly tainted data, summaries, or peer-agent feedback gradually shifts stored knowledge or goal weighting, producing behavioral or policy deviations over time.

5. Systemic misalignment and backdoors: Poisoned memory shifts the model’s persona and plants trigger-based backdoors that execute hidden instructions, such as destructive code or data leaks.

6. Cross-agent propagation: Contaminated context or shared memory spreads between cooperating agents, compounding corruption and enabling long-term data leakage or coordinated drift

## Example Attack Scenarios

1. Travel Booking Memory Poisoning: An attacker keeps reinforcing a fake flight price, the assistant stores it as truth, then approves bookings at that price and bypasses payment checks.

2. Context Window Exploitation: The attacker splits attempts across sessions so earlier rejections drop out of context, and the AI eventually grants escalating permissions up to admin access.

3. Memory Poisoning for System: The attacker retrains a security AI’s memory to label malicious activity as normal, letting attacks slip through undetected.

4. Shared Memory Poisoning: The attacker inserts bogus refund policies into shared memory, other agents reuse them, and the business suffers bad decisions, losses, and disputes.

5. Cross tenant vector bleed: Near duplicate content seeded by an attacker exploits loose

- - namespace filters, pulling another tenant’s sensitive chunk into retrieval by high cosine similarity

6. Assistant Memory Poisoning: An attacker implants a user assistants’ memory via Indirect Prompt Injection, compromising that user’s current and future sessions.

## Prevention and Mitigation Guidelines

1. Baseline data protection: Encryption in transit and at rest combined with least-privilege access

2. Content validation: Scan all new memory writes and model outputs (rules + AI) for malicious or sensitive content before commit.

3. Memory segmentation: Isolate user sessions and domain contexts to prevent knowledge and sensitive data leakage.

4. Access and retention: Allow only authenticated, curated sources; enforce context-aware access per task; minimize retention by data sensitivity.

5. Provenance and anomalies: Require source attribution and detect suspicious updates or frequencies.

6. Prevent automatic re-ingestion of an agent’s own generated outputs into trusted memory to avoid self-reinforcing contamination or “bootstrap poisoning.”

7. Resilience and verification: Perform adversarial test, use snapshots/rollback and version control, and require human review for high-risk actions. Where you operate shared vector or memory stores, use per-tenant namespaces and trust scores for entries, decaying or expiring unverified memory over time and supporting rollback/quarantine for suspected poisoning.

8. Expire unverified memory to limit poison persistence.

9. Weight retrieval by trust and tenancy: Require two factors to surface high-impact memory (e.g., provenance score plus human-verified tag) and decay low-trust entries over time.

## References

1. New hack uses prompt injection to corrupt Gemini’s long-term memory, https://arstechnica.com/security/2025/02/new-hack-uses-prompt-injection-to-corrupt-geminis- long-term-memory/

2. Attackers Can Manipulate AI Memory to Spread Lies, https://www.bankinfosecurity.com/attackers- manipulate-ai-memory-to-spread-lies-a-27699

3. Poisoned RAG, https://arxiv.org/pdf/2402.07867

4. AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases, https://arxiv.org/abs/2407.12784

5. Securing Agentic AI: A Comprehensive Threat Model and Mitigation Framework for Generative AI Agents, https://arxiv.org/pdf/2504.19956

6. Dynamic Cheatsheet: Test Time Learning with Adaptive Memory, - https://arxiv.org/abs/2504.07952v1

7. Memento: Fine-tuning LLM Agents without Fine-tuning LLMs, https://arxiv.org/abs/2508.16153

8. AgentFlayer: persistent 0click exploit on ChatGPT.

9. Hacker plants false memories in ChatGPT to steal user data in perpetuity

10. The Trifecta: How Three New Gemini Vulnerabilities in Cloud Assist, Search Model, and Browsing Allowed Private Data Exfiltration
