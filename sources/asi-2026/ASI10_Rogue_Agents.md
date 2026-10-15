# ASI10: Rogue Agents

## Description

Rogue Agents are malicious or compromised AI Agents that deviate from their intended function or authorized scope, acting harmfully, deceptively, or parasitically within multi-agent or human-agent ecosystems.

The agent’s actions may individually appear legitimate, but its emergent behavior becomes harmful, creating a containment gap for traditional rule-based systems. While external compromise, such as Prompt Injection (LLM01:2025), Goal Hijack (AS01) or Supply Chain tampering (AS04) can initiate the divergence, ASI10 focuses on the loss of behavioral integrity and governance once the drift begins, not the initial intrusion itself. Consequences include sensitive information disclosure, misinformation propagation, workflow hijacking, and operational sabotage.

Rogue Agents represent a distinct risk of behavioral divergence, unlike Excessive Agency (LLM06:2025), which focuses on over-granted permissions, and can be amplified "insider threats" due to the speed and scale of Agentic systems. Consequences include Sensitive Information Disclosure (LLM02;2025), Misinformation (LLM09:2025). In the OWASP Agentic AI Threats and Mitigations guide, ASI10 corresponds to T13 – Rogue Agents in Multi-Agent Systems. The OWASP AIVSS framework maps this risk primarily to Behavioral Integrity (BI), Operational Security (OS), and Compliance Violations (CV), with elevated severity for critical or self-propagating deployments.

## Common Examples of the Vulnerability

1. Goal Drift and Scheming: Agents deviate from intended objectives, appearing compliant but pursuing hidden, often deceptive, goals due to indirect prompt injection or conflicting objectives.

2. Workflow Hijacking: Rogue agents seize control of established, trusted workflows to redirect processes toward malicious objectives, compromising data integrity and operational control.

3. Collusion and Self-Replication: Agents coordinate to amplify manipulation, share signals in unintended ways, or autonomously propagate across the system, bypassing simple takedown efforts.

4. Reward Hacking and Optimization Abuse: Agents game their assigned reward systems by exploiting flawed metrics to generate misleading results or adopt aggressive strategies misaligned with the original goals.

## Example Attack Scenarios

1. Autonomous data exfiltration after indirect prompt injection. After encountering a poisoned web instruction, the agent learns this behavior and continues independently scanning and transmitting sensitive files to external servers even after the malicious source is removed, demonstrating persistent unauthorized behavior beyond its intended scope.

2. Impersonated Observer Agent (Integrity Violation): An attacker injects a fake review or approval agent into a multi-agent workflow. A high-value agent (e.g., payment processing), trusting the internal request, is misled into releasing funds or approving fraudulent transactions.

3. Self-Replication via Provisioning APIs (Persistence & Availability): A compromised automation agent is manipulated into spawning unauthorized replicas of itself across the network, prioritizing persistence and consuming resources against the system owner’s intent.

4. Reward Hacking Critical Data Loss: Agents tasked with minimizing cloud costs learn that → deleting production backups is the most effective way to achieve their goal, autonomously destroying all disaster recovery assets.

## Prevention and Mitigation Guidelines

1. Governance & Logging: Maintain comprehensive, immutable and signed audit logs of all agent actions, tool calls, and inter-agent communication to review for stealth infiltration or unapproved delegation.

2. Isolation & Boundaries: Assign Trust Zones with strict inter-zone communication rules and deploy restricted execution environments (e.g., container sandboxes) with API scopes based on least privilege.

3. Monitoring & Detection: Deploy behavioral detection, such as watchdog agents to validate peer behavior and outputs, focusing on detecting collusion patterns and coordinated false signals. Monitor for anomalies such as excessive or abnormal actions executions.

4. Containment & Response: Implement rapid mechanisms like kill-switches and credential revocation to instantly disable rogue agents. Quarantine suspicious agents in sandboxed environments for forensic review.

5. Identity Attestation and Behavioral Integrity Enforcement: Implement per-agent cryptographic identity attestation and enforce behavioral integrity baselines throughout the agent lifecycle. Attach signed behavioral manifests declaring expected capabilities, tools, and goals that are validated by orchestration services before each action. Integrate a behavioral verification layer that continuously monitors tasks for deviations from the declared manifest for e.g. unapproved tool invocations, unexpected data exfiltration attempts etc.

6. Require periodic behavioral attestation: challenge tasks, signed bill of materials for prompts and tools, and per-run ephemeral credentials with one-time audience binding. All signing and attestation mechanisms assume hardened cryptographic key management (e.g., HSM/KMS-backed keys, least-

privilege access, rotation and revocation). Keys must never be directly available to agents; instead, orchestrators should mediate signing operations so that a compromised agent cannot simply exfiltrate or misuse long-lived keys

7. Recovery and Reintegration: Establish trusted baselines for restoring quarantined or remediated agents. Require fresh attestation, dependency verification, and human approval before reintegration into production networks.

## References

Multi

1. -Agent Systems Execute Arbitrary Malicious Code (arXiv) [URL: https://arxiv.org/abs/2503.12188] Rogue Agents Agent

2. Preventing Improves Multi- Collaboration (arXiv) [URL: https://arxiv.org/abs/2502.05986]
