# cybersec-skill

A skill that turns security standards into checkable controls and audits code and dependencies against them, citing the source of every result.

## Language

**Standard**:
A published, versioned body of requirements or knowledge (OWASP ASVS 5.0.0, NIST SP 800-53 Rev. 5, MITRE ATT&CK 20.0). The source of truth for every result.
_Avoid_: framework (except in a standard's own name), norm, guideline

**Tier**:
How much of a standard this skill holds. **A**: full text generated from the official source; can support PASS or FAIL. **B**: reference card only, because the licence or the law forbids reproducing it; the best result is NOT VERIFIED with a candidate control. **C**: a format, protocol or data feed that is only mentioned.

**Control state**:
The result of checking one requirement in context: **PASS**, **FAIL**, **NOT APPLICABLE** (with the reason) or **NOT VERIFIED** (with how to verify). In Spanish reports: CUMPLE, NO CUMPLE, NO APLICA, NO VERIFICADO.
_Avoid_: compliant / non-compliant, status

**Finding**:
One record of an audit: a security problem with a trust boundary and a concrete result an attacker obtains. Lives in `findings.json`.
_Avoid_: issue, vulnerability (for a finding that is not confirmed)

**Verdict**:
How sure an audit is about a finding: **confirmed** (source trace plus bounded local evidence), **needs_validation** (blocked by a fact outside the source), **rejected** (kept so later runs do not repeat it).

**Severity**:
The impact anchor of a confirmed finding: critical, high, medium, low or informational. Never given to a lead that needs validation. Separate from **priority** (KEV, EPSS, 800-218A priority), which ranks work.

**Source**:
A citation attached to a finding or a control result: standard, version, identifier, the skill file that holds it, and its **relation** (violated-requirement, weakness, risk-category, attack-technique, countermeasure, threat, governance-outcome, maturity-practice, severity-basis, candidate-control).

**SC control**:
An entry of `references/sc-controls-catalog.md` that binds the requirements of several standards expressing the same demand, and adds the agent's action, the verification and the PASS / FAIL criteria. Never a source on its own: a finding cites the requirements in the control's traceability line.

**Mode**:
What the skill is doing: **consultation** (default, no files), **code audit** or **dependency audit** (explicit request only; they can run together as a full audit).

**Mitigation prompt**:
The panel of the HTML report that builds a prompt for a coding agent from the findings the user ticks; criticals are preselected, or the most severe level present when there is no critical.

**Playbook**:
A practitioner procedure from Anthropic-Cybersecurity-Skills, copied under `references/playbooks/`. It tells how to do the work; a standard judges it.

**Crosswalk**:
The OWASP GenAI mappings from each Agentic Top 10 risk to controls in 25 other frameworks. Unreviewed at source: a navigation hint, never a requirement.

## Relationships

- A **Finding** carries one **Verdict** and, when confirmed, one **Severity**
- A **Finding** cites one or more **Sources**; a confirmed one cites at least a tier-A violated requirement and a weakness (CWE)
- A confirmed **Finding** sets the **Control state** of the requirement it breaks to FAIL; a finding that needs validation sets it to NOT VERIFIED
- An **SC control** binds requirements from several **Standards**

## Flagged ambiguities

- "Norma" in the Spanish predecessor (systema-cure) meant both a standard and a single requirement. Resolved: **standard** is the publication, **requirement** is one identified demand inside it.
- "Priority" was read as severity in some sources (800-218A, ATLAS maturity). Resolved: priority ranks work and never sets **Severity**.
