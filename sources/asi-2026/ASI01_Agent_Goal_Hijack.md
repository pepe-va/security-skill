# ASI01: Agent Goal Hijack

## Description

AI Agents exhibit autonomous ability to execute a series of tasks to achieve a goal. Due to inherent weaknesses in how natural-language instructions and related content are processed, agents and the underlying model cannot reliably distinguish instructions from related content.

As a result, attackers can manipulate an agent’s objectives, task selection, or decision pathways through a variety of techniques - including, but not limited to, prompt-based manipulation, deceptive tool outputs, malicious artefacts, forged agent-to-agent messages, or poisoned external data. Because agents rely on untyped natural-language inputs and loosely governed orchestration logic, they cannot reliably distinguish legitimate instructions from attacker -controlled content. Unlike LLM01:2025, which focuses on altering a single model response, ASI01 captures the broader agentic impact where manipulated inputs redirect goals, panning (when used) and multi-step behavior.

Agent Goal Hijack differs from ASI06 (Memory & Context Poisoning) and ASI10 (Rogue Agents) because the attacker directly alters the agent’s goals, instructions, or decision pathways - regardless of whether the manipulation occurs interactively or through pre-positioned inputs such as documents, templates, or external data sources. ASI06 focuses on the persistent corruption of stored context or long-term memory, while ASI10 captures autonomous misalignment that emerges without active attacker control. In the OWASP Agentic AI Threats & Mitigations Guide, ASI01 corresponds to T06 Goal Manipulation (altering the agent’s objectives) and T07 Misaligned & Deceptive Behaviors (bypassing safeguards or deceiving humans). Together, these illustrate how attackers can subvert the agent’s objectives and action-selection logic, redirecting its autonomy toward unintended or harmful outcomes.

## Common Examples of the Vulnerability

1. Indirect Prompt Injection via hidden instruction payloads embedded in web pages or documents in a RAG scenario silently redirect an agent to exfiltrate sensitive data or misuse connected tools.

2. Indirect Prompt Injection external communication channels (e.g. email, calendar, teams) sent from outside of the company hijacks an agent’s internal communication capability, sending unauthorized messages under a trusted identity.

3. A malicious prompt override manipulates a financial agent into transferring money to an attacker’s account.

4. Indirect Prompt Injection overrides agent instructions making it produce fraudulent information that impacts business decisions.

## Example Attack Scenarios

1. EchoLeak: Zero-Click Indirect Prompt Injection - An attacker emails a crafted message that silently triggers Microsoft 365 Copilot to execute hidden instructions, causing the AI to exfiltrate confidential emails, files, and chat logs without any user interaction.

2. Operator Prompt Injection via Web Content: An attacker plants malicious content on a web page that the Operator agent processes, e.g., in Search or RAG scenarios, tricking it into following unauthorized instructions. The Operator agent then accesses authenticated internal pages and exposes users’ private data, demonstrating how lightly guarded autonomous agents can leak sensitive information through prompt injection.

3. Goal-lock drift via scheduled prompts. A malicious calendar invite injects a recurring “quiet mode” instruction that subtly reweights objectives each morning, steering the planner toward low friction - approvals while keeping actions inside declared policies.

4. Inception attack on ChatGPT users. A malicious Google Doc injects instructions for ChatGPT to exfiltrate user data and convinces the user to make an ill-advised business decision.

## Prevention and Mitigation Guidelines

1. Treat all natural-language inputs (e.g., user-provided text, uploaded documents, retrieved content) as untrusted. Route them through the same input-validation and prompt-injection safeguards defined in LLM01:2025 before they can influence goal selection, planning, or tool calls.

2. Minimize the impact of goal hijacking by enforcing least privilege for agent tools and requiring human approval for high-impact or goal-changing actions.

3. Define and lock agent system prompts so that goal priorities and permitted actions are explicit and auditable. Changes to changes in goals or reward definitions must go through configuration management and human approval.

4. At run time, validate both user intent and agent intent before executing goal-changing or high- impact actions. Require confirmation - via human approval, policy engine, or platform guardrails whenever the agent proposes actions that deviate from the original task or scope. Pause or block execution on any unexpected goal shift, surface the deviation for review, and record it for audit.

5. When building agents, evaluate use of “intent capsule”, an emerging pattern to bind the declared goal, constraints, and context to each execution cycle in a signed envelope, restricting run-time use.

6. Sanitize and validate any connected data source - including RAG inputs, emails, calendar invites, uploaded files, external APIs, browsing output, and peer-agent messages - using CDR, prompt- carrier detection, and content filtering before the data can influence agent goals or actions.

7. Maintain comprehensive logging and continuous monitoring of agent activity, establishing a behavioral baseline that includes goal state, tool-use patterns, and invariant properties (e.g., schema, access patterns). Track a stable identifier for the active goal where feasible, and alert on

any deviations-such as unexpected goal changes, anomalous tool sequences, or shifts from the established baseline-so that unauthorized goal drift is immediately visible in operations.

8. Conduct periodic red-team tests simulating goal override and verify rollback effectiveness.

9. Incorporate AI Agents into the established Insider Threat Program to monitor any insider prompts intended to get access to sensitive data or to alter the agent behavior and allow for investigation in case of outlier activity.

## References

1. Security Advisory - ChatGPT Crawler Reflective DDOS Vulnerability: Security advisory detailing the vulnerability

2. AIM Echoleak Blog Post: Blog post describing the vulnerability

3. ChatGPT Plugin Exploit Explained: From Prompt Injection to Accessing Private Data.

4. AgentFlayer: 0click inception attack on ChatGPT users.
