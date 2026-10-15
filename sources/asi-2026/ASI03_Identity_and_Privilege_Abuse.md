# ASI03: Identity and Privilege Abuse

## Description

Identity & Privilege Abuse exploits dynamic trust and delegation in agents to escalate access and bypass controls by manipulating delegation chains, role inheritance, control flows, and agent context; context includes cached credentials or conversation history across interconnected systems. In this context, identity refers both to the agent’s defined persona and to any authentication material that represents it. Agent-to- agent trust or inherited credentials can be exploited to escalate access, hijack privileges, or execute unauthorized actions.

This risk arises from the architectural mismatch between user-centric identity systems and agentic design. Without a distinct, governed identity of its own, an agent operates in an attribution gap that makes enforcing true least privilege impossible. Identity in this context includes both the agent’s assigned persona and any authentication material (API keys, OAuth tokens, delegated user sessions) that represent it.

This differs scenario in ASI02 (Tools Misuse) which is an unintended or unsafe use of already granted privilege by a principal misusing its own tools.

Identity & Privilege Abuse is the agentic evolution of Excessive Agency (LLM06:2025). It often leverages Prompt Injection (LLM01:2025), and because of agent permissions, tool integrations, and multi-agent systems, the impact can amplify and exceed Sensitive Information Disclosure (LLM02:2025) to directly compromise the confidentiality, integrity, and availability of systems and data the agent can reach.

In the OWASP ASI Threats and Mitigations, it maps one-to-one to T3: Privilege Compromise, and in OWASP AIVSS it corresponds to Core Risk 2: Agent Access Control Violation.

## Common Examples of the Vulnerability

1. Un-scoped Privilege Inheritance. Occurs when a high-privilege manager delegates tasks without applying least-privilege scoping-often for convenience or due to architectural limits-passing its full access context. A narrow worker then receives excessive rights. Low- or no-code agents with default privileges, such as unrestricted Internet access, also inherit more authority than intended.

2. Memory-Based Privilege Retention & Data Leakage. Arises when agents cache credentials, keys, or retrieved data for context and reuse. If memory is not segmented or cleared between tasks or users,

attackers can prompt the agent to reuse cached secrets, escalate privileges, or leak data from a prior secure session into a weaker one.

3. Cross-Agent Trust Exploitation (Confused Deputy). In multi-agent systems, agents often trust internal requests by default. A compromised low-privilege agent can relay valid-looking instructions to a high-privilege agent, which executes them without re-checking the original user’s intent- misusing its elevated permissions.

4. Time-of-Check to Time-of-Use (TOCTOU) in Agent Workflows. Permissions may be validated at the start of a workflow but change or expire before execution. The agent continues with outdated authorization, performing actions the user no longer has rights to approve.

5. Synthetic Identity Injection. Attackers impersonate internal agents by using unverified descriptors (e.g., “Admin Helper”) to gain inherited trust and perform privileged actions under a fabricated identity.

## Example Attack Scenarios

Delegated Privilege Abuse: A finance agent delegates to a “DB query” agent but passes all its 1. permissions. An attacker steering the query prompts uses the inherited access to exfiltrate HR and legal data. Memory-Based Escalation: An IT admin agent caches SSH credentials during a patch. Later a non- 2. admin reuses the same session and prompts it to use those credentials to create an unauthorized account. Cross-Agent Trust Exploitation: A crafted email from IT instructs an email sorting agent to instruct 3. a finance agent to move money to a specific account. The sorter agent forwards it, and the finance agent, trusting an internal agent, processes the fraudulent payment without verification.

4. Device code phishing across agents: An attacker shares a device code link that a browsing agent

- - follows; a separate “helper” agent completes the code, binding the victim’s tenant to attacker scopes.

5. Workflow Authorization Drift: A procurement agent validates approval at the start of a purchase sequence. Hours later, the user’s spending limit is reduced, but the workflow proceeds with the old authorization token, completing the now-unauthorized transaction.

6. Forged Agent Persona: An attacker registers a fake “Admin Helper” agent in an internal Agent2Agent registry with a forged agent card. Other agents, trusting the descriptor, route privileged maintenance tasks to it. The attacker-controlled agent then issues system-level commands under assumed internal trust.

7. Identity Sharing. An agent gains access to systems on behalf of a user, often their maker. It then allows other users to leverage that identity implicitly by invoking its tools as that identity.

## Prevention and Mitigation Guidelines

1. Enforce Task-Scoped, Time-Bound Permissions: Issue short-lived, narrowly scoped tokens per task and cap rights with permission boundaries - using per-agent identities and short-lived credentials (e.g., mTLS certificates or scoped tokens) - to limit blast radius, block delegated-abuse and maintenance-window attacks, and mitigate un-scoped inheritance, orphaned privileges, and reflection-loop elevation.

2. Isolate Agent Identities and Contexts: Run per-session sandboxes with separated permissions and memory, wiping state between tasks to prevent Memory-Based Escalation and reduce Cross- Repository Data Exfiltration.

3. Mandate Per-Action Authorization: Re-verify each privileged step with a centralized policy engine that checks external data, stopping Cross-Agent Trust Exploitation and Reflection Loop Elevation.

4. Apply Human-in-the-Loop for Privilege Escalation: Require human approval for high-privilege or irreversible actions to provide a safety net that would stop Memory-Based Escalation, Cross-Agent Trust Exploitation, and Maintenance Window attacks.

5. Define Intent: Bind OAuth tokens to a signed intent that includes subject, audience, purpose, and session. Reject any token use where the bound intent doesn’t match the current request.

6. Evaluate Agentic Identity Management Platforms. Major platforms integrate agents into their identity and access management systems, treating them as managed non-human identities with scoped credentials, audit trails, and lifecycle controls. Examples include Microsoft Entra, AWS Bedrock Agents, Salesforce Agentforce, Workday’s Agentic System of Record (ASOR) model, and similar emerging patterns in Google Vertex AI.

7. Bind permissions to subject, resource, purpose, and duration. Require re authentication on - context switch. Prevent privilege inheritance across agents unless the original intent is re validated. - Include automated revocation on idle or anomaly.

8. Detect Delegated and Transitive Permissions: Monitor when an agent gains new permissions indirectly through delegation chains. Flag cases where a low-privilege agent inherits or is handed higher-privilege scopes during multi-agent workflows. 9. Detect abnormal cross-agent privilege elevation and device-code style phishing flows by monitoring when agents request new scopes or reuse tokens outside their original, signed intent.

## References

1. https://research.aimultiple.com/agentic-ai-cybersecurity/

2. https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/

3. https://css.csail.mit.edu/6.858/2015/readings/confused-deputy.html

4. 15 Ways to Break Your Copilot, BHUSA 2024

5. NVD - cve-2025-31491
