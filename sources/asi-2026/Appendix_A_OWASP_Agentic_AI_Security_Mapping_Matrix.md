# Appendix A - OWASP Agentic AI Security Mapping Matrix

Cross-Mapping the ASI Top 10, LLM Top 10, Agentic AI Threats & Mitigations, and AIVSS Core Risks

ASI ID / Title OWASP LLM Top 10 Agentic AI Threats & AIVSS Core Risk (2025) Mitigations Alignment

ASI 01 – Agent Goal LLM01:2025Prompt T6 Goal Manipulation · T7 Agent Goal & Hijack Injection · LLM06:2025 Misaligned & Deceptive Instruction Excessive Agency Behaviors Manipulation

ASI 02 – Tool Misuse & LLM06:2025 Excessive T2 Tool Misuse · T4 Agentic AI Tool Misuse Exploitation Agency Resource Overload · T16 Insecure Inter-Agent Protocol Abuse

ASI 03 – Identity & LLM01:2025 Prompt T3 Privilege Compromise Agent Access Control Privilege Abuse Injection · LLM06:2025 Violation Excessive Agency · LLM02:2025 Sensitive Info Disclosure

ASI 04 – Agentic Supply LLM03:2025 Supply T17 Supply Chain Agent Supply Chain & Chain Vulnerabilities Chain Vulnerabilities Compromise · T2 Tool Dependency Attacks Misuse · T11 Unexpected RCE · T12 Agent Comm Poisoning · T13 Rogue Agent · T16 Insecure Inter-Agent Protocol Abuse

ASI 05 – Unexpected LLM01:2025 Prompt T11 Unexpected RCE & Insecure Agent Critical Code Execution (RCE) Injection · LLM05 Code Attacks Systems Interaction Improper Output Handling

ASI 06 – Memory & LLM01:2025 Prompt T1 Memory Poisoning · T4 Memory Use & Context Poisoning Injection · LLM04:2025 Memory Overload · T6 Contextual Awareness Data & Model Poisoning ·

LLM08:2025 Vector & Broken Goals · T12 Shared Embedding Weaknesses Memory Poisoning

ASI 07 – Insecure Inter- LLM02:2025 Sensitive T12 Agent Agent Memory & Agent Communication Information Disclosure · Communication Context Manipulation LLM06:2025 Excessive Poisoning · T16 Insecure Agency Inter-Agent Protocol Abuse

ASI 08 – Cascading LLM01:2025 Prompt T5 Cascading Agent Cascading Failures Injection · LLM04 Data & Hallucination Attacks · T8 Failures Model Poisoning · Repudiation & LLM06:2025 Excessive Untraceability Agency

ASI 09 – Human-Agent LLM01:2025 Prompt T7 Misaligned & Agent Untraceability / Trust Exploitation Injection · LLM05:2025 Deceptive Behaviors · T8 Human Manipulation Improper Output Repudiation & Handling · LLM06:2025 Untraceability · T10 Excessive Agency · Overwhelming Human in LLM09 Misinformation the Loop

ASI 10 – Rogue Agents T13 Rogue Agents in Behavioral Integrity (BI) LLM02:2025 Sensitive Multi-Agent Systems · · Operational Security , Information Disclosure T14 Human Attacks on (OS) · Compliance LLM09:2025 Multi-Agent Systems · T15 Violations (CV) Misinformation Human Manipulation

Notes

LLM Top 10 alignment: captures root LLM vulnerabilities extended into agentic systems. • Agentic Threats & Mitigations (T1–T17): represent granular attack pathways referenced by the ASI • framework. AIVSS Core Risks: map to the quantitative scoring categories for prioritization and severity ranking • (e.g., BI, OS, CV). Crossover insight: ASI entries often blend multiple LLM entries-e.g., ASI01 combines LLM01:2025 • (prompt) with LLM06 (autonomy)-representing how agentic autonomy compounds model-level risks.
