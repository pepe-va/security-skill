# Letter from The Agentic Top 10 Leaders

Agentic AI systems are moving quickly from pilots to production across finance, healthcare, defense, critical infrastructure, and the public sector. Unlike task-specific automations, agents plan, decide, and act across multiple steps and systems, often on behalf of users and teams. The Agentic Security Initiative has already begun defining safeguards for Agentic applications but publishing a set of guidelines spanning across the lifecycle.

Our core taxonomy (Agentic AI - Threats and Mitigations) provides a baseline definition of agents, their relationship to LLM applications, the role of autonomy, and a detailed treatment of threats and mitigations. Additional documents cover Threat Modelling (Agentic Threat Modelling Guide), Securing architecture, design, development, and deployment of Agentic apps (Securing Agentic Applications), as well as governance (State of Agentic AI Security and Governance)

These publications provide a comprehensive set of guidelines intended as a reference and an in-depth cover. Nevertheless, their breadth can make them difficult to translate into day-to-day practice for builders, defenders, and decision-makers.

Our OWASP Top 10 for Agentic Applications (or OWASP Agentic Top 10) serves as a compass and go-to reference for security leaders and practitioners to understand and address the Top 10 highest-impact threats and begin their journey.

It uses the standard and popular OWASP Top 10 format to provide concise, practical, and actionable guidance. Each entry has a brief description, common vulnerabilities, example scenarios, and most importantly, actionable mitigations that teams can start implementing today.

We aim to simplify and connect existing guidance, not contribute to an overload of overlapping guidance. We map to our Agentic AI Threats and Mitigations, which remains our foundational and detailed taxonomy that this Top 10 relies upon.

Our focus is on Agentic Apps, but these will not exist in isolation and will be part of developing an LLM App. As a result, our entries reference the OWASP Top 10 for LLM Applications and other relevant standards. These includes various other OWASP Top 10s, the CycloneDX standard, the Top 10 for Non-Human Identities (NHI), and the OWASP AI Vulnerability Scoring System (AIVSS) for scoring and prioritization.

Agents amplify existing vulnerabilities. We expand on the concepts of Least-Privilege and Excessive Agency by citing Least-Agency. This captures our advice to organizations to avoid unnecessary autonomy; deploying agentic behavior where it is not needed expands the attack surface without adding value. Similarly, strong observability becomes non-negotiable: without clear visibility into what agents are doing, why they are doing it, and which tools they are invoking, unnecessary autonomy can quietly expand the attack surface and turn minor issues into system-wide failures.

This document is the work of the global OWASP community. Dozens of security experts from industry, academia, and government contributed threat research, red-team findings, and field-tested mitigations, with support from organizations building agentic platforms, public institutions, and product vendors.

The Acknowledgements section provides a list of our Entry Leads, Contributors, our distinguished expert review board and the organizations that took part in our review, allowing us to incorporate diverse, real- world insights.

We are indebted to them and will continue to evolve using our OWASP expert-led community-driven approach of open collaboration, peer review, and evidence from research, exploits, incidents, and challenges from real-world deployments.

With Warm Regards,

John Sotiropoulos, OWASP GenAI Security Project Board Member & ASI Co-lead, Agentic Top 10 Chair

Keren Katz, Agentic Top 10 Lead, OWASP GenAI Security Project - ASI Core Team

Ron F. Del Rosario, OWASP GenAI Security Project Core Team Member & ASI Co-lead
