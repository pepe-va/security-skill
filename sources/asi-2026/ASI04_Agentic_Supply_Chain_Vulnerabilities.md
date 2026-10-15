# ASI04: Agentic Supply Chain Vulnerabilities

## Description

Agentic Supply Chain Vulnerabilities arise when agents, tools, and related artefacts they work with are provided by third parties and may be malicious, compromised, or tampered with in transit. These can be both static and dynamical sourced components, including models and model weights, tools, plug-ins, datasets, other agents, agentic interfaces - MCP (Model Context Protocol), A2A (Agent2Agent) - agentic registries and related artifacts, or update channels. These dependencies may introduce unsafe code, hidden instructions, or deceptive behaviors into the agent’s execution chain.

Supply chain is covered in depth in LLM03:2025 Supply Chain Vulnerabilities. However, its focus is on static dependencies. Unlike traditional AI or software supply chains, agentic ecosystems often compose capabilities at runtime - loading external tools- agent personas dynamically – thereby increasing the attack surface. This distributed run-time coordination - combined with agentic autonomy - creates a live supply chain that can cascade vulnerabilities across agents. These shifts focus from manifest to run-time security of a diverse and often opaque component. Tackling this problem requires careful development-time tooling and runtime orchestration, where components are dynamically loaded, shared, and trusted.

The entry maps to T17 Supply Chain Compromise in Agentic Threats and Mitigations and across T2 Tool Misuse, T11 Unexpected RCE and Code Attacks, T12 Agent Communication Poisoning, T13 Rogue Agent and T16 Insecure Inter-Agent Protocol Abuse.

## Common Examples of the Vulnerability

1. Poisoned prompt templates loaded remotely: An agent automatically pulls prompt templates from an external source that contain hidden instructions (e.g., to exfiltrate data or perform destructive actions), leading it to execute malicious behavior without developer intent.

2. Tool-descriptor injection: An attacker embeds hidden instructions or malicious payloads into a tool’s metadata or MCP/agent-card, which the host agent interprets as trusted guidance and acts upon.

3. Impersonation and typo squatting: When an agent dynamically discovers or connects to external tools or services, it can be deceived in two ways by a typo squatted endpoint (a look-alike name chosen to trick resolution) or by a symbol attack, where a malicious service deliberately

impersonates a legitimate tool or agent, mimicking its identity, API, and behavior to gain trust and execute malicious actions.

4. Vulnerable Third-Party Agent (Agent Agent). A third-party agent with unpatched vulnerabilities → or insecure defaults is invited into multi-agent workflows. A compromised or buggy peer agent can be used to pivot, leak data, or relay malicious instructions to otherwise trusted agents.

5. Compromised MCP / Registry Server. A malicious or compromised agent-management / MCP server (or package registry) serves signed-looking manifests, plug-ins, or agent descriptors. Because orchestration systems trust the registry, this allows wide exposure of tampered components and descriptor injection at scale.

6. Poisoned knowledge plugin: A popular RAG plugin fetches context from 3rd party indexer seeded with crafted entries. The agent gets biased gradually as it consumes this data and exfiltrates sensitive data during normal use.

## Example Attack Scenarios

1. Amazon Q Supply Chain Compromise: A poisoned prompt in the Q for VS Code repo ships in v1.84.0 to thousands before detection; despite failing, it shows how upstream agent-logic tampering cascades via extensions and amplifies impact.

2. MCP Tool Descriptor Poisoning: A researcher shows a prompt injection in GitHub’s MCP where a malicious public tool hides commands in its metadata; when invoked, the assistant exfiltrates private repo data without the user’s knowledge.

3. Malicious MCP Server Impersonating Postmark: Reported as the first in-the-wild malicious MCP server on npm, it impersonated postmark-mcp and secretly BCC’d emails to the attacker.

4. AgentSmith Prompt-Hub Proxy Attack: Prompt proxying exfiltrates data and hijacks response flows, manipulating dynamic orchestration in Agentic systems.

5. A compromised NPM package (e.g., a poisoned nx/debug release) was automatically installed by coding agents, enabling a hidden backdoor that exfiltrated SSH keys and API tokens and thereby propagated a supply-chain compromise across agentic workflows.

6. Agent-in-the-Middle via Agent Cards: A compromised or rogue peer advertises exaggerated capabilities in its agent card (e.g., host agents pick it for tasks, /.well-known/agent.json); causing sensitive requests and data to be routed through the attacker-controlled agent which then exfiltrates or corrupts responses

## Prevention and Mitigation Guidelines

1. Provenance and SBOMs, AIBOMs: Sign and attest manifests, prompts, and tool definitions; require and operationalize SBOMs, AIBOMs with periodic attestations; maintain inventory of AI components; use curated registries and block untrusted sources.

2. Dependency gatekeeping: Allowlist and pin; scan for typosquats (PyPI, npm, LangChain, LlamaIndex); verify provenance before install or activation; auto-reject unsigned or unverified.

3. Containment and builds: Run sensitive agents in sandboxed containers with strict network or syscall limits; require reproducible builds.

4. Secure prompts and memory: Put prompts, orchestration scripts, and memory schemas under version control with peer review; scan for anomalies.

5. Inter-agent security: Enforce mutual auth and attestation via PKI and mTLS; no open registration; sign and verify all inter-agent messages.

6. Continuous validation and monitoring: Re-check signatures, hashes, and SBOMs (incl. AIBOMs) at runtime; monitor behavior, privilege use, lineage, and inter-module telemetry for anomalies.

7. Pinning: Pin prompts, tools, and configs by content hash and commit ID. Require staged rollout with differential tests and auto rollback on hash drift or behavioral change. -

8. Supply chain kill switch: Implement emergency revocation mechanisms that can instantly disable specific tools, prompts, or agent connections across all deployments when a compromise is detected, preventing further cascading damage.

9. Zero-trust security model in application design: design system with security fault tolerance that assumes failure or exploitation of LLM or agentic function components.

## References

1. https://www.bleepingcomputer.com/news/security/amazon-ai-coding-agent-hacked-to-inject- data-wiping-commands/

2. https://invariantlabs.ai/blog/mcp-github-vulnerability

3. Reconstructing a timeline for Amazon Q prompt infection

4. https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/agent-in-the-middle- abusing-agent-cards-in-the-agent-2-agent-protocol-to-win-all-the-tasks/

5. How an AI Agent Vulnerability in LangSmith Could Lead to Stolen API Keys and Hijacked LLM Responses - Noma Security
