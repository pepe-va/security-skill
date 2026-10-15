# ASI08: Cascading Failures

## Description

Agentic cascading failures occur when a single fault (hallucination, malicious input, corrupted tool, or poisoned memory) propagates across autonomous agents, compounding into system-wide harm. Because agents plan, persist, and delegate autonomously, a single error can bypass stepwise human checks and persist in a saved state. As agents form emergent links to new tools or peers, these latent faults chain into privileged operations that compromise confidentiality, integrity, availability, leading to widespread service failures across agent networks, systems, and workflows.

Cascading Failures describes the propagation and amplification of an initial fault-not the initial vulnerability itself-across agents, tools, and workflows, turning a single error into system-wide impact.

ASI08 focuses on the propagation and amplification of faults rather than their origin. Use the initial defect under ASI04, ASI06, or ASI07 when it represents a direct compromise - such as a tainted dependency, poisoned memory, or spoofed message - and apply ASI08 only when that defect spreads across agents, sessions, or workflows, causing measurable fan-out or systemic impact beyond the original breach.

Observable symptoms include rapid fan-out where one faulty decision triggers many downstream agents or tasks in a short time, cross-domain or tenant spread beyond the original context, oscillating retries or feedback loops between agents, and downstream queue storms or repeated identical intents-each providing clear detection hooks that make ASI08 operationally actionable.

Cascading failures amplify across interconnected agents, chaining OWASP LLM Top 10 risks. LLM01:2025 Prompt Injection and LLM06:2025 Excessive Agency can trigger autonomous tool runs that spread errors without human checks, while LLM04:2025 Data and Model Poisoning in persistent memory can skew decisions across sessions and workflows. Agentic AI - Threats and Mitigations 1.1 covers this threat in T5 – Cascading Hallucination Attacks while T8 – Repudiation and Untraceability highlights a fundamental defense: the ability to trace, attribute, and audit cascading behaviors through resilient logging and non- repudiation mechanisms that prevent silent propagation. However, these compounding threats illustrate a potential discrepancy in the speed and scale of fault propagation in a multi-agent system and the ability of humans to keep up with them to ensure secure and effective operation of the system. This leaves some unmitigated risks that the enterprise must evaluate carefully to ensure they are within the overall risk budget for the organization.

## Common Examples of the Vulnerability

1. Planner–executor coupling: A hallucinating or compromised planner emits unsafe steps that the executor automatically performs without validation, multiplying impact across agents.

2. Corrupted persistent memory: Poisoned long-term goals or state entries continue influencing new plans and delegations, propagating the same error even after the original source is gone.

3. Inter-agent cascades from poisoned messages: A single corrupted update causes peer agents to act on false alerts or reboot instructions, spreading disruption across regions.

4. Cascading tool misuse and privilege escalation. One agent’s misuse of an integration or elevated credential leads downstream agents to repeat unsafe actions or leak inherited data.

5. Auto-deployment cascade from tainted update: A poisoned or faulty release pushed by an orchestrator propagates automatically to all connected agents, amplifying the breach beyond its origin.

6. Governance drift cascade: Human oversight weakens after repeated success; bulk approvals or policy relaxations propagate unchecked configuration drift across agents.

7. Feedback-loop amplification. Two or more agents rely on each other’s outputs, creating a self- reinforcing loop that magnifies initial errors or false positives.

## Example Attack Scenarios

1. Financial trading cascade: Prompt injection (LLM01:2025) poisons a Market Analysis agent, inflating risk limits; Position and Execution agents auto-trade larger positions while compliance stays blind to “within-parameter” activity.

2. Healthcare protocol propagation: ASI04 supply chain tampering corrupts drug data; Treatment auto-adjusts protocols, and Care Coordination spreads them network-wide without human review.

3. Cloud orchestration breakdown: LLM04:2025 poisoning in Resource Planning adds unauthorized permissions and bloat; Security applies them, and Deployment provisions backdoored, costly infrastructure without per-change approval.

4. Security operations compromise: Stolen service credentials - via LLM06:2025 and LLM03:2025 - make detection defenses mark real alerts false, IR disable controls and purge logs, and compliance report clean metrics.

5. Manufacturing Quality Control (QC) failure: ASI06 memory injection with LLM08:2025 poisoned knowledge makes QC approve defects and reject good items; Inventory and Scheduling optimize on bad data, causing defective shipments and losses.

6. Auto-remediation feedback loop: A remediation agent suppresses alerts to meet latency SLAs; a planning agent interprets fewer alerts as success and widens automation, potentially compounding blind spots across regions.

7. A regional cloud DNS outage in a hyperscaler can simultaneously break multiple AI services that depend on it, causing a cascade of agent failures across many organizations

8. Agentic Cyber defense systems and firewalls: Propagation of hallucination about an imminent attack or injected false alert is propagated in the underlying multi-agent systems, causing unnecessary but catastrophic defensive actions, such as shutdowns, denials, and network disconnects

## Prevention and Mitigation Guidelines

1. Zero-trust model in application design: design system with fault tolerance that assumes availability failure of LLM:2025, agentic function components and external sources.

2. Isolation and trust boundaries: Sandbox agents, least privilege, network segmentation, scoped APIs, and mutual auth. to contain failure propagation.

3. JIT, one-time tool access with runtime checks: Issue short-lived, task-scoped credentials for each agent run and validate every high-impact tool invocation against a policy-as-code rule before executing it. This ensures a compromised or drifting agent cannot trigger chain reactions across other agents or systems.

4. Independent policy enforcement: Separate planning and execution via an external policy engine to prevent corrupt planning from triggering harmful actions.

5. Output validation and human gates: Checkpoints, governance agents, or human review for high risk before agent outputs are propagated downstream.

6. Rate limiting and monitoring: Detect fast-spreading commands and throttle or pause on anomalies.

7. Implement blast-radius guardrails such as quotas, progress caps, circuit breakers between planner and executor.

8. Behavioral and governance drift detection: Track decisions vs baselines and alignment; flag gradual degradation.

9. Digital twin replay and policy gating: Re-run the last week’s recorded agent actions in an isolated clone of the production environment to test whether the same sequence would trigger cascading failures. Gate any policy expansion on these replay tests passing predefined blast-radius caps before deployment.

10. Logging and non-repudiation. Record all inter-agent messages, policy decisions, and execution outcomes in tamper-evident, time-stamped logs bound to cryptographic agent identities. Maintain lineage metadata for every propagated action to support forensic traceability, rollback validation, and accountability during cascades.

## References

1. https://sre.google/sre-book/addressing-cascading-failures/ 2. https://cwe.mitre.org/data/definitions/400.html
