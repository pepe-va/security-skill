# Appendix C - Mapping Between OWASP Non-Human Identities Top 10 (2025) and OWASP Agentic AI Top 10

The table below maps the OWASP Non-Human Identities (NHI) Top 10 (2025) risks to the OWASP Agentic AI Top 10 (ASI), Agentic-AI Threats & Mitigations (T-codes), and AIVSS Core Risk categories to show alignment between identity-centric and agentic-behavior-centric risks.

NHI Risk ID / Brief Description Mapped ASI Top Mapped T-codes Mapped AIVSS Title 10 Entries / Threats & Core Risk Mitigations Alignment

NHI1: Improper Failure to ASI04 – Agentic T17 Supply Chain Agent Supply Chain Offboarding deactivate or Supply Chain Compromise · T2 & Dependency remove unused Vulnerabilities Tool Misuse Attacks non-human identities leads to persistent attack surface.

NHI2: Secret Exposure of API ASI02 – Tool Misuse T6 Goal Memory Use & Leakage keys, tokens, or & Exploitation · Manipulation · T1 Contextual certificates used by ASI06 – Memory & Memory Poisoning Awareness non-human Context Poisoning identities.

NHI3: Third-party ASI04 – Supply T12 Agent Agent Supply Chain Vulnerable integrated Chain Communication & Dependency Third-Party identities are Vulnerabilities · Poisoning · T13 Attacks NHI compromised and ASI03 – Identity & Rogue Agents exploited. Privilege Abuse

NHI4: Insecure Weak or deprecated ASI03 – Identity & T16 Insecure Inter- Agent Access Authentication authentication Privilege Abuse · Agent Protocol Control Violation mechanisms for ASI07 – Insecure Abuse NHIs. Inter-Agent Communication

NHI5: Non-human ASI02 – Tool Misuse T2 Tool Misuse · T3 Agent Access Overprivileged identities granted & Exploitation · Privilege Control Violation NHI excessive ASI03 – Identity & Compromise permissions. Privilege Abuse

NHI6: Insecure Misconfigured ASI04 – Supply T11 Unexpected RCE Insecure Agent Cloud CI/CD and cloud Chain & Code Attacks Critical Systems Deployment setups with static Vulnerabilities · Interaction Configurations credentials. ASI05 – Unexpected Code Execution (RCE)

NHI7: Long- Credentials or keys ASI06 – Memory & T4 Memory Overload Memory Use & Lived Secrets with long expiry Context Poisoning · · T12 Shared Memory Contextual increase attacker ASI08 – Cascading Poisoning Awareness dwell time. Failures

NHI8: Reuse of NHIs ASI08 – Cascading T8 Repudiation & Agent Cascading Environment across Failures · ASI07 – Untraceability · T12 Failures Isolation dev/test/prod Insecure Inter- Agent enabling lateral Agent Communication movement. Communication Poisoning

NHI9: NHI Reusing same NHI ASI08 – Cascading T5 Cascading Agent Cascading Reuse across services Failures · ASI04 – Hallucination Failures amplifies impact of Supply Chain Attacks · T13 Rogue compromise. Vulnerabilities Agents

NHI10: Human Humans using non- ASI09 – Human- T10 Overwhelming Agent Use of NHI human credentials Agent Trust Human in the Loop · Untraceability / causes loss of Exploitation · ASI01 T7 Misaligned & Human accountability and – Agent Goal Hijack Deceptive Manipulation privilege misuse. Behaviors
