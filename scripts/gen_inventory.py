#!/usr/bin/env python3
"""Build the inventory of every standard cited by the three source repositories.

Walks:
  ../../systema-cure                      standards it incorporates
  ../../security-audit-skill              methodology and stray references
  ../../Anthropic-Cybersecurity-Skills    frontmatter of the 818 playbooks + text of SKILL.md and references/*.md

Output:
  references/standards/INVENTORY.md       each standard, how many playbooks cite it, and its tier A/B/C
  references/standards/tier-b-cards.md    one card per tier-B standard: what it is, what covers it, who cites it

Tiers:
  A  full text incorporated in this skill, generated from the official source
  B  reference card only (licence, law or scope); best achievable result is NOT VERIFIED
  C  mention: format, protocol, conceptual model or operational data feed

Each entry also gets its publication date and status (current, living, withdrawn/superseded, draft, unmaintained,
newer release exists). --refresh-status checks them online — NIST CSRC publication pages, the RFC Editor
index and the projects' release metadata — and caches the result in sources/status/status.json;
entries no machine-readable source covers carry editorial values marked as such.

Stdlib only. Point --base at the folder holding the three source repositories. Without them the generator
uses the snapshot of the last scan, sources/inventory-scan.json.
"""
import argparse, collections, json, pathlib, re

ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = ROOT.parent / "sources"
SKILL = ROOT.parent / "skills" / "security" / "cybersec-skill"
OUT = SKILL / "references" / "standards" / "INVENTORY.md"
CARDS = SKILL / "references" / "standards" / "tier-b-cards.md"

# Curated catalogue. Fields: key, name, tier, version (incorporated for A, cited for B/C),
# file in this skill (A) or the tier-A standard that covers its subject (B/C), official URL,
# note, origin repos known a priori, detection patterns.
CATALOGUE = [
    # --- Tier A inherited from systema-cure -------------------------------------------
    ("owasp-top10", "OWASP Top 10", "A", "2025", "standards/owasp-top10-2025.md",
     "https://owasp.org/Top10/", "Inherited from systema-cure.", {"systema-cure"},
     [r"OWASP Top ?10(?! for LLM)(?! LLM)(?!.{0,6}API)", r"\bA0\d:20(?:21|25)\b"]),
    ("owasp-asvs", "OWASP ASVS", "A", "5.0.0", "standards/owasp-asvs-5.0.0.md",
     "https://owasp.org/www-project-application-security-verification-standard/",
     "Inherited from systema-cure.", {"systema-cure"}, [r"\bASVS\b"]),
    ("owasp-samm", "OWASP SAMM", "A", "2.0", "standards/owasp-samm-2.0.md",
     "https://owaspsamm.org/", "Inherited from systema-cure.", {"systema-cure"}, [r"\bSAMM\b"]),
    ("nist-ssdf", "NIST SP 800-218 (SSDF)", "A", "1.1", "standards/nist-ssdf-800-218.md",
     "https://doi.org/10.6028/NIST.SP.800-218", "Inherited from systema-cure (re-sourced from the English original).",
     {"systema-cure"}, [r"\bSSDF\b", r"800-218(?!A)"]),
    ("nist-218a", "NIST SP 800-218A", "A", "July 2024", "standards/nist-800-218a.md",
     "https://doi.org/10.6028/NIST.SP.800-218A", "Inherited from systema-cure.", {"systema-cure"}, [r"800-218A"]),
    ("owasp-llm", "OWASP Top 10 for LLM Applications", "A", "2026", "standards/owasp-llm-top10-2026.md",
     "https://genai.owasp.org/", "Inherited from systema-cure. Playbooks cite the 2025 edition.", {"systema-cure"},
     [r"OWASP (?:Top 10 for LLM|LLM Top 10|Top 10 LLM)", r"\bLLM0\d(?::20\d\d)?\b", r"\bLLM10\b"]),
    ("owasp-asi", "OWASP Top 10 for Agentic Applications (ASI)", "A", "2026", "standards/owasp-asi-top10-2026.md",
     "https://genai.owasp.org/", "Inherited from systema-cure.", {"systema-cure"},
     [r"\bASI0\d\b", r"\bASI10\b", r"Agentic (?:Top 10|Applications)"]),
    ("owasp-agentic-tm", "OWASP Agentic AI - Threats and Mitigations", "A", "1.1",
     "standards/owasp-agentic-threats-mitigations-1.1.md", "https://genai.owasp.org/",
     "Inherited from systema-cure.", {"systema-cure"}, [r"Agentic AI (?:-|—|–)? ?Threats and Mitigations"]),
    ("mitre-atlas", "MITRE ATLAS", "A", "2026.09", "standards/mitre-atlas.md",
     "https://atlas.mitre.org/", "Inherited from systema-cure. Playbooks use 2026.07.", {"systema-cure"},
     [r"\bATLAS\b", r"\bAML\.T\d{4}"]),
    # --- Tier A new: frameworks of Anthropic-Cybersecurity-Skills ----------------------
    ("mitre-attack", "MITRE ATT&CK (Enterprise, ICS, Mobile)", "A", "latest release at generation",
     "standards/mitre-attack/", "https://attack.mitre.org/", "Core framework of the playbooks.", set(),
     [r"ATT&CK"]),
    ("nist-csf", "NIST Cybersecurity Framework", "A", "2.0", "standards/nist-csf-2.0.md",
     "https://www.nist.gov/cyberframework", "Core framework of the playbooks.", set(),
     [r"\bCSF\b", r"Cybersecurity Framework"]),
    ("mitre-d3fend", "MITRE D3FEND", "A", "latest release at generation", "standards/mitre-d3fend.md",
     "https://d3fend.mitre.org/", "Core framework of the playbooks (cited by name, not by ID).", set(),
     [r"D3FEND", r"\bD3-[A-Z]{2,}"]),
    ("nist-ai-rmf", "NIST AI Risk Management Framework", "A", "1.0", "standards/nist-ai-rmf-1.0.md",
     "https://www.nist.gov/itl/ai-risk-management-framework", "Core framework of the playbooks.", set(),
     [r"AI RMF", r"AI Risk Management Framework", r"NIST AI 100-1"]),
    ("mitre-f3", "MITRE Fight Fraud Framework (F3)", "A", "1.2", "standards/mitre-f3-1.2.md",
     "https://ctid.mitre.org/fraud/", "Core framework of the fraud playbooks (they map v1.1).", set(),
     [r"Fight Fraud Framework", r"MITRE F3", r"\bF1\d{3}(?:\.\d{3})?\b", r"\bFA000[12]\b"]),
    # --- Tier A new: added by user decision -------------------------------------------
    ("cwe", "MITRE CWE", "A", "latest release at generation", "standards/cwe/",
     "https://cwe.mitre.org/", "Common language for weaknesses.", set(), [r"\bCWE-\d+", r"\bCWE\b"]),
    ("cvss", "FIRST CVSS", "A", "4.0", "standards/cvss-4.0.md", "https://www.first.org/cvss/v4-0/",
     "Playbooks mostly cite CVSS 3.1; this skill scores in 4.0.", set(), [r"\bCVSS"]),
    ("nist-ai-600-1", "NIST AI 600-1 (Generative AI Profile)", "A", "July 2024", "standards/nist-ai-600-1.md",
     "https://doi.org/10.6028/NIST.AI.600-1", "Complements AI RMF and 800-218A.", set(), [r"AI 600-1"]),
    ("owasp-api", "OWASP API Security Top 10", "A", "2023", "standards/owasp-api-top10-2023.md",
     "https://owasp.org/API-Security/", "AppSec package.", set(),
     [r"API Security Top ?10", r"\bAPI\d{1,2}:20(?:19|23)\b"]),
    ("nist-800-63b", "NIST SP 800-63B (authentication)", "A", "800-63B-4", "standards/nist-800-63b-4.md",
     "https://pages.nist.gov/800-63-4/", "AppSec package. Playbooks cite revision 3.", set(), [r"800-63B"]),
    ("owasp-masvs", "OWASP MASVS", "A", "latest release at generation", "standards/owasp-masvs.md",
     "https://mas.owasp.org/MASVS/", "AppSec package.", set(), [r"\bMASVS\b"]),
    ("nist-800-53", "NIST SP 800-53 (security and privacy controls)", "A", "Rev. 5", "standards/nist-800-53r5/",
     "https://doi.org/10.6028/NIST.SP.800-53r5", "Control catalogue; informative reference of CSF 2.0.", set(),
     [r"800-53(?![AB])"]),
    ("slsa", "SLSA", "A", "latest stable", "standards/slsa.md", "https://slsa.dev/",
     "Infrastructure and supply chain package.", set(), [r"\bSLSA\b"]),
    ("nist-800-190", "NIST SP 800-190 (containers)", "A", "2017", "standards/nist-800-190.md",
     "https://doi.org/10.6028/NIST.SP.800-190", "Infrastructure and supply chain package.", set(), [r"800-190"]),
    ("nist-800-207", "NIST SP 800-207 (Zero Trust Architecture)", "A", "2020", "standards/nist-800-207.md",
     "https://doi.org/10.6028/NIST.SP.800-207", "Infrastructure and supply chain package.", set(), [r"800-207"]),
    ("cisa-ztmm", "CISA Zero Trust Maturity Model", "A", "2.0", "standards/cisa-ztmm-2.0.md",
     "https://www.cisa.gov/zero-trust-maturity-model", "Infrastructure and supply chain package.", set(),
     [r"Zero Trust Maturity Model", r"\bZTMM\b"]),
    ("nist-800-61", "NIST SP 800-61 (incident response)", "A", "Rev. 3", "standards/nist-800-61r3.md",
     "https://doi.org/10.6028/NIST.SP.800-61r3", "Operations and IR package. Many playbooks cite Rev. 2.", set(),
     [r"800-61"]),
    ("nist-800-86", "NIST SP 800-86 (forensics)", "A", "2006", "standards/nist-800-86.md",
     "https://doi.org/10.6028/NIST.SP.800-86", "Operations and IR package.", set(), [r"800-86"]),
    ("nist-800-115", "NIST SP 800-115 (technical testing)", "A", "2008", "standards/nist-800-115.md",
     "https://doi.org/10.6028/NIST.SP.800-115", "Operations and IR package.", set(), [r"800-115"]),
    ("nist-800-40", "NIST SP 800-40 (patch management)", "A", "Rev. 4", "standards/nist-800-40r4.md",
     "https://doi.org/10.6028/NIST.SP.800-40r4", "Operations and IR package.", set(), [r"800-40\b"]),
    # --- Tier B: no incorporated text ---------------------------------------------------
    ("pci-dss", "PCI DSS", "B", "4.0 / 4.0.1", "ASVS, 800-53 r5, SSDF",
     "https://www.pcisecuritystandards.org/", "Licence does not allow redistributing the text.", set(), [r"PCI[ -]?DSS"]),
    ("iso-27001", "ISO/IEC 27001", "B", "2022", "800-53 r5, CSF 2.0",
     "https://www.iso.org/standard/27001", "ISO licence: text not redistributable.", set(), [r"ISO(?:/IEC)? ?27001"]),
    ("soc2", "AICPA SOC 2 (Trust Services Criteria)", "B", "2017 (rev. 2022)", "CSF 2.0, 800-53 r5",
     "https://www.aicpa-cima.com/", "AICPA licence: text not redistributable.", set(), [r"\bSOC ?2\b"]),
    ("cis-controls", "CIS Critical Security Controls", "B", "v8 / v8.1", "CSF 2.0, 800-53 r5",
     "https://www.cisecurity.org/controls", "CC BY-NC-ND licence: no derivatives allowed.", set(),
     [r"CIS (?:Critical Security )?Controls"]),
    ("cis-benchmarks", "CIS Benchmarks", "B", "per product", "800-53 r5 (CM-6), 800-190",
     "https://www.cisecurity.org/cis-benchmarks", "CIS licence.", set(),
     [r"CIS Benchmark", r"CIS (?:AWS|Azure|GCP|Docker|Kubernetes|Linux|Windows) "]),
    ("disa-stig", "DISA STIG", "B", "per product", "800-53 r5",
     "https://public.cyber.mil/stigs/", "Per-product configuration guides; out of text scope.", set(), [r"\bSTIG"]),
    ("iec-62443", "ISA/IEC 62443", "B", "series", "ATT&CK ICS",
     "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
     "IEC/ISA licence: text not redistributable.", set(), [r"62443"]),
    ("nerc-cip", "NERC CIP", "B", "current", "ATT&CK ICS, CSF 2.0",
     "https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx", "North American electric sector regulation.", set(),
     [r"NERC CIP"]),
    ("hipaa", "HIPAA", "B", "current", "800-53 r5 (not legal advice)",
     "https://www.hhs.gov/hipaa/", "Law: out of scope, as in systema-cure.", set(), [r"\bHIPAA\b"]),
    ("gdpr", "GDPR", "B", "2016/679", "800-53 r5 (not legal advice)",
     "https://eur-lex.europa.eu/eli/reg/2016/679/oj", "Law: out of scope.", set(), [r"\bGDPR\b", r"\bRGPD\b"]),
    ("sox", "SOX", "B", "current", "CSF 2.0 (not legal advice)", "—", "Law: out of scope.", set(),
     [r"\bSOX\b", r"Sarbanes"]),
    ("dora", "DORA", "B", "2022/2554", "CSF 2.0, ASI crosswalk", "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
     "Law: out of scope.", set(), [r"\bDORA\b"]),
    ("nis2", "NIS2", "B", "2022/2555", "CSF 2.0", "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
     "Law: out of scope.", set(), [r"\bNIS ?2\b"]),
    ("eu-ai-act", "EU AI Act", "B", "2024/1689", "AI RMF, AI 600-1, ASI crosswalk",
     "https://eur-lex.europa.eu/eli/reg/2024/1689/oj", "Law: out of scope.", set(), [r"EU AI Act"]),
    ("cmmc", "CMMC", "B", "2.0", "800-171 (B), 800-53 r5", "https://dodcio.defense.gov/CMMC/",
     "DoD certification programme.", set(), [r"\bCMMC\b"]),
    ("fedramp", "FedRAMP", "B", "Rev. 5", "800-53 r5", "https://www.fedramp.gov/",
     "Programme based on 800-53.", set(), [r"FedRAMP"]),
    ("csa-ccm", "CSA Cloud Controls Matrix", "B", "v4", "800-53 r5, CSF 2.0",
     "https://cloudsecurityalliance.org/research/cloud-controls-matrix", "CSA licence.", set(),
     [r"Cloud Controls Matrix", r"CSA CCM"]),
    ("owasp-wstg", "OWASP Web Security Testing Guide", "B", "4.2", "ASVS 5.0.0, 800-115",
     "https://owasp.org/www-project-web-security-testing-guide/", "Large testing guide; not chosen for tier A.", set(),
     [r"Web Security Testing Guide", r"\bWSTG\b", r"OWASP Testing Guide"]),
    ("owasp-mastg", "OWASP MASTG", "B", "current", "MASVS", "https://mas.owasp.org/MASTG/",
     "Mobile testing guide; companion of MASVS.", set(), [r"\bMASTG\b", r"\bMSTG\b"]),
    ("owasp-mobile-top10", "OWASP Mobile Top 10", "B", "2024", "MASVS",
     "https://owasp.org/www-project-mobile-top-10/", "Awareness list; MASVS gives the requirement.", set(),
     [r"Mobile Top ?10"]),
    ("k8s-pss", "Kubernetes Pod Security Standards", "B", "current", "800-190",
     "https://kubernetes.io/docs/concepts/security/pod-security-standards/", "Platform policies.", set(),
     [r"Pod Security Standards"]),
    ("ptes", "PTES", "B", "—", "800-115", "http://www.pentest-standard.org/", "Penetration testing methodology.",
     set(), [r"\bPTES\b"]),
    ("osstmm", "OSSTMM", "B", "3", "800-115", "https://www.isecom.org/", "Testing methodology.", set(), [r"OSSTMM"]),
    ("tiber-eu", "TIBER-EU", "B", "—", "800-115, DORA (B)",
     "https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html", "ECB red-teaming framework.",
     set(), [r"TIBER"]),
    ("crest", "CREST", "B", "—", "800-115", "https://www.crest-approved.org/", "Provider accreditation.", set(),
     [r"\bCREST\b"]),
    ("mitre-car", "MITRE CAR", "B", "—", "ATT&CK", "https://car.mitre.org/", "Detection analytics.", set(),
     [r"MITRE CAR\b", r"\bCAR-\d{4}"]),
    ("mitre-engage", "MITRE Engage", "B", "—", "D3FEND (Deceive)", "https://engage.mitre.org/",
     "Deception and denial.", set(), [r"MITRE Engage"]),
    ("swc", "SWC Registry", "B", "—", "CWE", "https://swcregistry.io/", "Smart-contract weaknesses.", set(),
     [r"SWC[- ]\d{3}", r"SWC Registry"]),
    # --- Tier C: formats, protocols, conceptual models and operational data -------------
    ("cisa-kev", "CISA Known Exploited Vulnerabilities", "C", "live data", "operational data for mode 3",
     "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "Queried at run time to prioritise.", set(),
     [r"Known Exploited Vulnerabilities", r"CISA KEV", r"\bKEV\b"]),
    ("epss", "FIRST EPSS", "C", "live data", "operational data for mode 3", "https://www.first.org/epss/",
     "Exploitation probability; queried at run time.", set(), [r"\bEPSS\b"]),
    ("osv", "OSV / OpenSSF Malicious Packages", "C", "live data", "operational data for mode 3", "https://osv.dev/",
     "Known vulnerabilities and known malicious packages.", set(), [r"\bOSV\b", r"osv\.dev"]),
    ("stix-taxii", "OASIS STIX / TAXII", "C", "2.1", "format", "https://oasis-open.github.io/cti-documentation/",
     "Threat-intelligence exchange format.", set(), [r"\bSTIX\b", r"\bTAXII\b"]),
    ("sigma", "Sigma", "C", "—", "format", "https://github.com/SigmaHQ/sigma", "Detection rule format.", set(),
     [r"\bSigma\b"]),
    ("yara", "YARA", "C", "—", "format", "https://virustotal.github.io/yara/", "Malware detection rule format.",
     set(), [r"\bYARA\b"]),
    ("cyclonedx", "OWASP CycloneDX", "C", "1.6", "format (mode 3 SBOM)", "https://cyclonedx.org/", "SBOM format.",
     set(), [r"CycloneDX"]),
    ("spdx", "SPDX", "C", "2.3 / 3.0", "format", "https://spdx.dev/", "SBOM format.", set(), [r"\bSPDX\b"]),
    ("tlp", "FIRST Traffic Light Protocol", "C", "2.0", "convention", "https://www.first.org/tlp/",
     "Sharing labels.", set(), [r"Traffic Light Protocol", r"\bTLP\b"]),
    ("diamond", "Diamond Model", "C", "—", "conceptual model", "—", "Intrusion analysis model.", set(),
     [r"Diamond Model"]),
    ("kill-chain", "Lockheed Martin Cyber Kill Chain", "C", "—", "conceptual model", "—", "Attack phase model.",
     set(), [r"Kill Chain"]),
    ("sans-models", "SANS maturity models", "C", "—", "conceptual model", "—", "Awareness.", set(),
     [r"SANS .{0,30}Maturity Model"]),
]

# Known names for NIST SPs not in the catalogue; anything else is still detected by family.
NIST_SP_NAMES = {
    "800-171": "CUI in non-federal systems", "800-82": "OT security", "800-83": "Malware prevention",
    "800-57": "Key management", "800-177": "Trustworthy email", "800-92": "Log management",
    "800-50": "Awareness and training", "800-37": "RMF", "800-30": "Risk assessment",
    "800-63": "Digital identity (umbrella)", "800-63A": "Identity proofing", "800-63C": "Federation",
    "800-163": "Mobile app vetting", "800-150": "Threat information sharing", "800-161": "C-SCRM",
    "800-184": "Cybersecurity event recovery", "800-128": "Configuration management",
    "800-137": "Continuous monitoring", "800-144": "Public cloud", "800-145": "Cloud definition",
    "800-160": "Systems security engineering", "800-204": "Microservices", "800-210": "Cloud access control",
    "800-215": "Secure enterprise networks", "800-41": "Firewalls", "800-94": "IDPS", "800-123": "Servers",
    "800-124": "Mobile devices", "800-125": "Virtualisation", "800-34": "Contingency planning",
    "800-39": "Risk management", "800-52": "TLS", "800-77": "IPsec", "800-81": "Secure DNS",
    "800-88": "Media sanitisation", "800-90": "Random bit generation", "800-95": "Web services",
    "800-100": "Management handbook", "800-101": "Mobile forensics", "800-111": "Storage encryption",
    "800-113": "SSL VPN", "800-116": "PIV", "800-153": "WLAN", "800-162": "ABAC",
    "800-167": "Application allowlisting", "800-175": "Using cryptography", "800-181": "NICE",
    "800-189": "BGP", "800-193": "Firmware resiliency", "800-53A": "Assessing 800-53 controls",
    "800-53B": "800-53 control baselines",
}

# (family, regex, key format, default tier, covered by)
FAMILIES = [
    ("NIST SP", re.compile(r"(?:NIST\s+(?:SP\s*)?|\bSP\s*)(800-\d+[A-C]?)"), "NIST SP {}", "B", "see CSF 2.0 / 800-53 r5"),
    ("NIST SP 1800", re.compile(r"(?:NIST\s+(?:SP\s*)?|\bSP\s*)(1800-\d+)"), "NIST SP {}", "B", "NCCoE practice guide"),
    ("NISTIR", re.compile(r"\bNIST\s?IR\s?(\d{4})"), "NISTIR {}", "B", "NIST interagency report"),
    ("FIPS", re.compile(r"\bFIPS\s?(?:PUB\s?)?(\d{2,3}(?:-\d)?)"), "FIPS {}", "B", "800-53 r5 (SC-13)"),
    ("ISO", re.compile(r"\bISO(?:/IEC)?\s?(\d{4,5})(?::\d{4})?"), "ISO/IEC {}", "B", "ISO licence"),
    ("IEC", re.compile(r"(?<!ISO/)\bIEC\s?(6\d{4})"), "IEC {}", "B", "IEC licence"),
    ("RFC", re.compile(r"\bRFC\s?(\d{3,5})\b"), "RFC {}", "C", "protocol"),
]
ISO_TIER_C = {"8601"}   # formats, not security standards
# Numbers already covered by a catalogue entry: the family match is skipped for these.
COVERED = {"NIST SP": {"800-218", "800-218A", "800-63B", "800-53", "800-190", "800-207", "800-61",
                       "800-86", "800-115", "800-40"},
           "ISO": {"27001"}, "IEC": {"62443"}}


STATUS_FILE = SOURCES / "status" / "status.json"
# What the last scan of the three repositories found. Written whenever they are present; read when they are not,
# so the inventory can be rebuilt (and its statuses refreshed) without them. Changing CATALOGUE patterns or
# FAMILIES needs a fresh scan: re-clone them into the repository root (URLs in the skill's references/governance.md).
SCAN_FILE = SOURCES / "inventory-scan.json"
RFC_INDEX = SOURCES / "status" / "rfc-index.xml"
CSRC = "https://csrc.nist.gov/pubs/"
UA = "cybersec-skill-inventory/1.0"

# CSRC publication pages of the NIST standards incorporated in tier A (checked with --refresh-status).
CSRC_TIER_A = {"nist-ssdf": "sp/800/218/final", "nist-218a": "sp/800/218/a/final", "nist-csf": "cswp/29/the-nist-cybersecurity-framework-csf-20/final",
               "nist-800-63b": "sp/800/63/b/4/final", "nist-800-53": "sp/800/53/r5/upd1/final",
               "nist-800-190": "sp/800/190/final", "nist-800-207": "sp/800/207/final", "nist-800-61": "sp/800/61/r3/final",
               "nist-800-86": "sp/800/86/final", "nist-800-115": "sp/800/115/final", "nist-800-40": "sp/800/40/r4/final"}

# Status of the entries that no machine-readable official source covers. Each value:
# (date, kind, text). kind: current | living | n/a | unchecked | draft | unmaintained.
# These are editorial (marked ≈ in the output): re-check them when updating the skill.
EDITORIAL = {
    "owasp-top10": ("2025", "current", "Latest edition"),
    "owasp-llm": ("August 2026", "current", "Latest edition"),
    "owasp-asi": ("December 2025", "current", "Latest edition"),
    "nist-ai-rmf": ("January 2023", "current", "Latest version (AI 100-1)"),
    "nist-ai-600-1": ("July 2024", "current", "Latest version"),
    "cvss": ("November 2023", "current", "Latest version of CVSS"),
    "cisa-ztmm": ("April 2023", "current", "Latest version"),
    "pci-dss": ("June 2024 (v4.0.1)", "current", "v4.0.1 is current; v4.0 was retired on 31 December 2024"),
    "iso-27001": ("October 2022 (+ Amd 1:2024)", "current", "ISO/IEC 27001:2022 is current"),
    "soc2": ("2017 (points of focus revised 2022)", "current", "Current criteria"),
    "cis-controls": ("June 2024 (v8.1)", "current", "v8.1 is current"),
    "cis-benchmarks": ("per product", "living", "Updated per product"),
    "disa-stig": ("per product", "living", "Updated per product"),
    "iec-62443": ("series, parts 2009–2024", "current", "Series in force; parts are revised individually"),
    "nerc-cip": ("continuous", "living", "Standards revised by NERC over time"),
    "hipaa": ("1996 (Security Rule 2003)", "current", "In force"),
    "gdpr": ("April 2016 (applies May 2018)", "current", "In force"),
    "sox": ("July 2002", "current", "In force"),
    "dora": ("December 2022 (applies January 2025)", "current", "In force"),
    "nis2": ("December 2022", "current", "In force"),
    "eu-ai-act": ("July 2024 (phased application)", "current", "In force, obligations phased in"),
    "cmmc": ("December 2024 (32 CFR 170)", "current", "Program rule in force"),
    "fedramp": ("2023 (Rev. 5 baselines)", "current", "Rev. 5 baselines current"),
    "csa-ccm": ("2021 (v4)", "unchecked", "Newer v4.x releases may exist"),
    "owasp-wstg": ("December 2020 (v4.2)", "current", "Latest stable release"),
    "owasp-mastg": ("continuous", "living", "Continuously updated"),
    "owasp-mobile-top10": ("2024", "current", "Latest edition"),
    "k8s-pss": ("continuous", "living", "Maintained with Kubernetes"),
    "ptes": ("2014", "unmaintained", "No update since 2014"),
    "osstmm": ("2010 (v3)", "unmaintained", "No release since v3 (2010)"),
    "tiber-eu": ("2018 (updated February 2025)", "current", "Current framework"),
    "crest": ("—", "n/a", "Accreditation body, not a document"),
    "mitre-car": ("continuous", "living", "Continuously updated"),
    "mitre-engage": ("2022", "current", "Latest version"),
    "swc": ("2020", "unmaintained", "Registry no longer maintained"),
    "cisa-kev": ("live", "living", "Live data feed"),
    "epss": ("live", "living", "Live data feed"),
    "osv": ("live", "living", "Live data feed"),
    "stix-taxii": ("June 2021 (2.1)", "current", "OASIS Standard 2.1"),
    "sigma": ("continuous", "living", "Specification and rules maintained by SigmaHQ"),
    "yara": ("continuous", "living", "Maintained by VirusTotal"),
    "cyclonedx": ("April 2024 (1.6)", "unchecked", "A newer specification version may exist"),
    "spdx": ("April 2024 (3.0)", "current", "SPDX 3.0 is current"),
    "tlp": ("August 2022 (2.0)", "current", "Current version"),
    "diamond": ("2013", "n/a", "Conceptual model"),
    "kill-chain": ("2011", "n/a", "Conceptual model"),
    "sans-models": ("—", "n/a", "Conceptual model"),
}

# Specific old revisions the playbooks cite. Value: (label, regex, kind, replacement text, basis).
# NIST SP revisions are discovered generically below and checked on CSRC.
OLD_REVISIONS = [
    ("PCI DSS v4.0", r"PCI[ -]?DSS\s*v?4\.0(?!\.\d)", "retired", "Retired 31 December 2024; superseded by v4.0.1", "≈"),
    ("PCI DSS v3.2.1", r"PCI[ -]?DSS\s*v?3\.2", "retired", "Retired 31 March 2024; superseded by v4.0.x", "≈"),
    ("CIS Controls v8", r"CIS (?:Critical Security )?Controls\s*v?8(?!\.\d)", "superseded", "Superseded by v8.1 (June 2024)", "≈"),
    ("CIS Controls v7.x", r"CIS (?:Critical Security )?Controls\s*v?7", "superseded", "Superseded by v8 / v8.1", "≈"),
    ("ISO/IEC 27001:2013", r"ISO(?:/IEC)?\s?27001:2013", "superseded", "Superseded by ISO/IEC 27001:2022", "≈"),
    ("ISO/IEC 27002:2013", r"ISO(?:/IEC)?\s?27002:2013", "superseded", "Superseded by ISO/IEC 27002:2022", "≈"),
    ("CVSS v3.x", r"CVSS\s*(?:v|version\s*)?3\.[01]", "superseded", "Superseded by CVSS v4.0 (November 2023); v3.1 scores are still published", "≈"),
    ("CVSS v2", r"CVSS\s*(?:v|version\s*)?2(?:\.0)?\b", "superseded", "Superseded by v3 and v4.0", "≈"),
    ("OWASP Top 10 2021", r"OWASP Top ?10[^\n]{0,12}2021|\bA\d\d:2021\b", "superseded", "Superseded by OWASP Top 10:2025", "≈"),
    ("OWASP Top 10 2017", r"OWASP Top ?10[^\n]{0,12}2017|\bA\d\d?:2017\b", "superseded", "Superseded by 2021 and 2025", "≈"),
    ("OWASP LLM Top 10 2025 / v1.1", r"(?:LLM Top ?10|Top 10 for LLM)[^\n]{0,30}(?:2025|v1\.1|2023)|\bLLM\d\d:2025\b", "superseded",
     "Superseded by the 2026 edition", "≈"),
    ("OWASP API Security Top 10 2019", r"API Security Top ?10[^\n]{0,12}2019|\bAPI\d{1,2}:2019\b", "superseded",
     "Superseded by the 2023 edition", "✓ GitHub editions"),
    ("OWASP ASVS 4.0.x", r"ASVS\s*v?4\.0", "superseded", "Superseded by ASVS 5.0.0 (May 2025)", "✓ GitHub releases"),
    ("OWASP MASVS 1.x", r"MASVS\s*v?1\.\d", "superseded", "Superseded by MASVS 2.x", "✓ GitHub releases"),
    ("NIST CSF 1.1", r"(?:CSF|Cybersecurity Framework)\s*(?:v|Version\s*)?1\.1", "superseded", "Superseded by CSF 2.0 (February 2024)", "≈"),
    ("MITRE ATT&CK v18 or earlier", r"ATT&CK\s*v(?:1[0-8]|[1-9])\b", "superseded", "Superseded by ATT&CK v20.0", "✓ ATT&CK index"),
    ("SLSA v0.1", r"SLSA\s*v?0\.1", "superseded", "Superseded by SLSA 1.x", "≈"),
]
OLD_DATES = {'PCI DSS v4.0': 'March 2022',
             'PCI DSS v3.2.1': 'May 2018',
             'CIS Controls v8': 'May 2021',
             'CIS Controls v7.x': '2019 (v7.1)',
             'ISO/IEC 27001:2013': 'October 2013',
             'ISO/IEC 27002:2013': 'October 2013',
             'CVSS v3.x': 'June 2019 (v3.1)',
             'CVSS v2': 'June 2007',
             'OWASP Top 10 2021': 'September 2021',
             'OWASP Top 10 2017': 'November 2017',
             'OWASP LLM Top 10 2025 / v1.1': 'November 2024 (2025 edition)',
             'OWASP API Security Top 10 2019': 'December 2019',
             'OWASP ASVS 4.0.x': 'October 2021 (4.0.3)',
             'OWASP MASVS 1.x': '2022 (1.5)',
             'NIST CSF 1.1': 'April 2018',
             'MITRE ATT&CK v18 or earlier': '—',
             'SLSA v0.1': '2021'}  # editorial (≈)
NIST_REV = re.compile(r"(?:NIST\s+(?:SP\s*)?|\bSP\s*)(800-\d+[A-C]?)\s*(?:Rev(?:ision)?\.?\s*|r)(\d)\b")


def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---", text, re.S)
    return m.group(1) if m else ""


def read(p):
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# ------------------------------------------------------------------------------------------- status refresh

def _get(url, timeout=60):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def csrc_page(path):
    """Release date, withdrawal and superseding publications from a CSRC publication page."""
    import html as _html
    try:
        t = _get(CSRC + path).decode("utf-8", "replace")
    except Exception as e:
        return {"path": path, "error": type(e).__name__}
    def span(i):
        m = re.search(rf"id=[\"']{i}[\"'][^>]*>(.*?)</", t, re.S)
        return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(1)))).strip() if m else None
    sup = [{"label": _html.unescape(m.group(2)).strip(), "path": m.group(1).replace("/pubs/", "", 1)}
           for m in re.finditer(r'<a href="(/pubs/[^"]+)" id="pub-superseded-by-\d+">([^<]+)</a>', t)]
    rel = span("pub-release-date")
    if not rel:
        m = re.search(r"Date Published:\s*([^<]+)", t)
        rel = m.group(1).strip() if m else None
    return {"path": path, "title": span("pub-title"), "release": rel, "withdrawn": span("pub-withdrawn-date"),
            "superseded_by": sup}


def csrc_chain(path, pages):
    """Follow 'superseded by' links. When a publication was split (800-63-2 -> 800-63-3, 63A, 63B, 63C), stay on
    the line that keeps the cited document's number instead of jumping to a lettered part."""
    base = re.sub(r"/(?:final|ipd|\dpd|draft)$", "", path)
    chain, seen = [], set()
    while path and path not in seen and len(chain) < 30:
        seen.add(path)
        if path not in pages:
            pages[path] = csrc_page(path)
        chain.append(path)
        nxt = pages[path].get("superseded_by") or []
        same_line = [x for x in nxt if not re.match(re.escape(base) + r"/[a-z]/", x["path"])]
        path = (same_line or nxt)[0]["path"] if nxt else None
    return chain


# Publications whose CSRC page is not at the default path: multi-part or multi-volume documents (the part this
# skill means) and drafts that never became final.
FAMILY_PATHS = {
    "NIST SP 800-57": "sp/800/57/pt1/r5/final",      # Part 1 (General) is the part cited for key management
    "NIST SP 800-60": "sp/800/60/v1/r1/final",
    "NISTIR 8547": "ir/8547/ipd",
    "NIST SP 800-154": "sp/800/154/ipd",
    "NIST SP 800-155": "sp/800/155/ipd",
    "NIST SP 800-94 Rev. 1": "sp/800/94/r1/ipd",
}
# Families cited as a whole: no single publication page carries their status.
SERIES = {
    "NIST SP 800-38": "Series 800-38A to 800-38G (block cipher modes); each part has its own status",
    "NIST SP 1800-38": "Multi-volume practice guide 1800-38A to 1800-38C; each volume has its own status",
}


def is_draft(path):
    return bool(re.search(r"/(?:ipd|\dpd|draft)$", path))


def family_path(key):
    if key in FAMILY_PATHS:
        return FAMILY_PATHS[key]
    if key in SERIES:
        return None
    m = re.fullmatch(r"NIST SP (800|1800)-(\d+)([A-C]?)", key)
    if m:
        return f"sp/{m.group(1)}/{m.group(2)}/" + (f"{m.group(3).lower()}/" if m.group(3) else "") + "final"
    m = re.fullmatch(r"NISTIR (\d+)", key)
    if m:
        return f"ir/{m.group(1)}/final"
    m = re.fullmatch(r"FIPS (\d+(?:-\d)?)", key)
    if m:
        return f"fips/{m.group(1)}/final"
    return None


def refresh_status(family_keys, revision_keys, rfc_numbers):
    import datetime
    status = {"checked": datetime.date.today().isoformat(), "csrc": {}, "chains": {}, "github": {}, "rfc": {}}
    pages = status["csrc"]
    for key, path in CSRC_TIER_A.items():
        status["chains"][key] = csrc_chain(path, pages)
    for key in family_keys:
        path = family_path(key)
        if path:
            status["chains"][key] = csrc_chain(path, pages)
    for key in revision_keys:
        m = re.fullmatch(r"NIST SP 800-(\d+)([A-C]?) Rev\. (\d)", key)
        if key in FAMILY_PATHS:
            status["chains"][key] = csrc_chain(FAMILY_PATHS[key], pages)
        elif m:
            letter = f"{m.group(2).lower()}/" if m.group(2) else ""
            status["chains"][key] = csrc_chain(f"sp/800/{m.group(1)}/{letter}r{m.group(3)}/final", pages)

    def gh(path):
        try:
            return json.loads(_get("https://api.github.com/repos/" + path))
        except Exception as e:
            return {"error": type(e).__name__}
    g = status["github"]
    rel = gh("OWASP/ASVS/releases?per_page=20")
    tags = [r for r in rel if isinstance(r, dict) and re.match(r"v\d", r.get("tag_name", ""))] if isinstance(rel, list) else []
    g["owasp-asvs"] = {"latest": tags[0]["tag_name"], "date": tags[0]["published_at"][:10]} if tags else rel
    rel = gh("owaspsamm/core/releases?per_page=5")
    g["owasp-samm"] = {"latest": rel[0]["tag_name"], "date": rel[0]["published_at"][:10]} if isinstance(rel, list) and rel else rel
    rel = gh("OWASP/masvs/releases/latest")
    g["owasp-masvs"] = {"latest": rel.get("tag_name"), "date": (rel.get("published_at") or "")[:10]} if "tag_name" in rel else rel
    lst = gh("mitre-atlas/atlas-data/contents/dist/v6")
    names = sorted(x["name"] for x in lst if isinstance(x, dict) and re.match(r"ATLAS-\d{4}\.\d{2}\.yaml", x["name"])) if isinstance(lst, list) else []
    g["mitre-atlas"] = {"latest": names[-1][6:-5]} if names else lst
    lst = gh("OWASP/API-Security/contents/editions")
    g["owasp-api"] = {"editions": sorted(x["name"] for x in lst if isinstance(x, dict))} if isinstance(lst, list) else lst
    lst = gh("slsa-framework/slsa/tags?per_page=30")
    vs = sorted((t["name"] for t in lst if isinstance(t, dict) and re.fullmatch(r"v1\.\d+(\.\d+)?", t["name"])),
                key=lambda v: [int(x) for x in v[1:].split(".")]) if isinstance(lst, list) else []
    g["slsa"] = {"latest": vs[-1]} if vs else lst
    lst = gh("center-for-threat-informed-defense/fight-fraud-framework/contents/public")
    vs = sorted((x["name"] for x in lst if isinstance(x, dict) and re.fullmatch(r"f3-stix-v[\d.]+\.json", x["name"])),
                key=lambda v: [int(x) for x in v[9:-5].split(".")]) if isinstance(lst, list) else []
    g["mitre-f3"] = {"latest": vs[-1][9:-5]} if vs else lst
    try:
        idx = json.loads(_get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"))
        g["mitre-attack"] = {"latest": idx["collections"][0]["versions"][0]["version"],
                             "date": idx["collections"][0]["versions"][0]["modified"][:10]}
    except Exception as e:
        g["mitre-attack"] = {"error": type(e).__name__}
    try:
        if not RFC_INDEX.exists():
            RFC_INDEX.parent.mkdir(parents=True, exist_ok=True)
            RFC_INDEX.write_bytes(_get("https://www.rfc-editor.org/rfc-index.xml", timeout=180))
    except Exception as e:
        status["rfc_error"] = type(e).__name__
    if RFC_INDEX.exists():
        import xml.etree.ElementTree as ET
        ns = "{https://www.rfc-editor.org/rfc-index}"
        root = ET.parse(RFC_INDEX).getroot()
        want = {f"RFC{int(n):04d}" for n in rfc_numbers}
        for e in root.iter(ns + "rfc-entry"):
            doc = e.findtext(ns + "doc-id")
            if doc in want:
                status["rfc"][doc] = {"title": e.findtext(ns + "title"),
                                      "date": f"{e.findtext(ns + 'date/' + ns + 'month')} {e.findtext(ns + 'date/' + ns + 'year')}",
                                      "status": e.findtext(ns + "current-status"),
                                      "obsoleted_by": [x.text for x in (e.find(ns + "obsoleted-by") if e.find(ns + "obsoleted-by") is not None else [])
                                                       if x.tag == ns + "doc-id"]}
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATUS_FILE.write_text(json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return status


# ------------------------------------------------------------------------------------------- status per row

def _clean_date(s):
    return re.sub(r"\s*\(.*?\)\s*", " ", s or "").strip() or "—"


def nist_status(chain, pages):
    """(date, kind, text) from a CSRC chain: first page is what is cited, last page is the live one."""
    if not chain:
        return None
    first, last = pages.get(chain[0], {}), pages.get(chain[-1], {})
    if first.get("error"):
        return ("—", "unchecked", f"CSRC page not found ({first['error']})")
    if len(chain) == 1 and is_draft(chain[0]):
        if first.get("withdrawn"):
            return (_clean_date(first.get("release")), "superseded",
                    f"Draft never finalised; withdrawn {first['withdrawn']}")
        return (_clean_date(first.get("release")), "draft", "Draft never finalised")
    if len(chain) == 1 and not first.get("withdrawn"):
        return (_clean_date(first.get("release")), "current", "Final, not withdrawn")
    if len(chain) == 1:
        return (_clean_date(first.get("release")), "superseded", f"Withdrawn {first['withdrawn']}; no successor")
    prev = pages.get(chain[-2], {}) if len(chain) > 1 else {}
    label = next((x["label"] for x in prev.get("superseded_by", []) if x["path"] == chain[-1]), chain[-1])
    if last.get("withdrawn"):
        label += " (also withdrawn)"
    # Updates of the same revision (".../r2/final" -> ".../r2/upd1/final") do not retire the revision itself:
    # report the withdrawal date of its last update.
    prefix = chain[0].rsplit("/", 1)[0] + "/"
    same = [p for p in chain if p == chain[0] or p.startswith(prefix)]
    withdrawn = pages.get(same[-1], {}).get("withdrawn") or first.get("withdrawn") or ""
    return (_clean_date(first.get("release")), "superseded",
            f"Withdrawn {withdrawn}; current: {label} ({_clean_date(last.get('release'))})".replace("  ", " "))


def live_revision(chain, pages):
    """(label, release date, withdrawn) of the last publication in a CSRC chain."""
    last = pages.get(chain[-1], {})
    prev = pages.get(chain[-2], {}) if len(chain) > 1 else {}
    label = next((x["label"] for x in prev.get("superseded_by", []) if x["path"] == chain[-1]),
                 last.get("title") or chain[-1])
    return label, _clean_date(last.get("release")), last.get("withdrawn")


def tier_a_status(key, status, local):
    """Status of a tier-A entry from CSRC, GitHub or local source metadata."""
    pages, chains, g = status.get("csrc", {}), status.get("chains", {}), status.get("github", {})
    if key in chains:
        s = nist_status(chains[key], pages)
        if s:
            return s + ("—" if s[1] == "unchecked" else "✓ CSRC",)
    if key == "owasp-asvs" and "latest" in g.get(key, {}):
        cur = g[key]["latest"].startswith("v5.0.0")
        return ("May 2025", "current" if cur else "newer", "Latest numbered release" if cur else f"Newer release {g[key]['latest']} ({g[key]['date']})", "✓ GitHub releases")
    if key == "owasp-samm" and "latest" in g.get(key, {}):
        return ("January 2020 (v2.0 PDF)", "newer",
                f"Model v2 in force; the core model data has release {g[key]['latest']} ({g[key]['date']}), newer than the 2020 PDF used here — differences not checked",
                "✓ GitHub releases")
    if key == "owasp-masvs" and "latest" in g.get(key, {}):
        cur = g[key]["latest"] == "v2.1.0"
        return (g[key]["date"] if cur else "January 2024", "current" if cur else "newer",
                "Latest release" if cur else f"Newer release {g[key]['latest']}", "✓ GitHub releases")
    if key == "mitre-atlas" and "latest" in g.get(key, {}):
        cur = g[key]["latest"] == "2026.09"
        return ("September 2026", "current" if cur else "newer", "Latest release" if cur else f"Newer release {g[key]['latest']}", "✓ atlas-data")
    if key == "owasp-api" and "editions" in g.get(key, {}):
        cur = max(g[key]["editions"]) == "2023"
        return ("June 2023", "current" if cur else "newer", "Latest edition" if cur else f"Newer edition {max(g[key]['editions'])}", "✓ GitHub editions")
    if key == "slsa" and "latest" in g.get(key, {}):
        cur = g[key]["latest"] == "v1.2"
        return ("November 2025", "current" if cur else "newer", "Latest stable release" if cur else f"Newer release {g[key]['latest']}", "✓ GitHub tags")
    if key == "mitre-f3" and "latest" in g.get(key, {}):
        cur = g[key]["latest"] == "1.2"
        return (local.get("f3", "—"), "current" if cur else "newer", "Latest release" if cur else f"Newer release {g[key]['latest']}", "✓ F3 repository")
    if key == "mitre-attack" and "latest" in g.get(key, {}):
        cur = g[key]["latest"] == "20.0"
        return (g[key].get("date", "—"), "current" if cur else "newer", "Latest release" if cur else f"Newer release v{g[key]['latest']}", "✓ ATT&CK index")
    if key == "cwe" and local.get("cwe"):
        return (local["cwe"], "current", "Latest catalogue at download (cwec_latest)", "✓ CWE")
    if key == "mitre-d3fend" and local.get("d3fend"):
        return (local["d3fend"], "current", "Live ontology at download", "✓ D3FEND")
    if key == "owasp-agentic-tm":
        return ("December 2025", "current", "Only version in the OWASP GenAI corpus", "✓ GenAI corpus")
    if key in EDITORIAL:
        return EDITORIAL[key] + ("≈",)
    return ("—", "unchecked", "Not checked", "—")


def local_dates():
    out = {}
    try:
        import zipfile
        z = zipfile.ZipFile(SOURCES / "cwe" / "cwec_latest.xml.zip")
        head = z.open(z.namelist()[0]).read(600).decode("utf-8", "ignore")
        m = re.search(r'Version="([\d.]+)" Date="([\d-]+)"', head)
        if m:
            out["cwe"] = f"{m.group(2)} (v{m.group(1)})"
    except (OSError, KeyError, IndexError):
        pass
    try:
        g = json.loads((SOURCES / "d3fend" / "d3fend.json").read_text())["@graph"]
        onto = next(n for n in g if n.get("@id", "").endswith("d3fend.owl"))
        out["d3fend"] = str(onto.get("d3f:release-date", {}).get("@value", ""))[:10]
    except (OSError, ValueError, StopIteration):
        pass
    try:
        objs = json.loads((SOURCES / "f3" / "f3-stix-v1.2.json").read_text())["objects"]
        out["f3"] = next(o for o in objs if o["type"] == "x-mitre-matrix").get("modified", "")[:10]
    except (OSError, ValueError, StopIteration, KeyError):
        pass
    return out


# ------------------------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=str(ROOT.parent), help="folder holding the three source repositories")
    ap.add_argument("--refresh-status", action="store_true",
                    help="check publication dates and status online (CSRC, GitHub, RFC Editor) and cache them")
    args = ap.parse_args()
    base = pathlib.Path(args.base)
    anth = base / "Anthropic-Cybersecurity-Skills" / "skills"
    sa = base / "security-audit-skill" / "skills" / "security-audit"
    sc = base / "systema-cure"
    repos_present = all(p.exists() for p in (anth, sa, sc))
    if not repos_present and not SCAN_FILE.exists():
        raise SystemExit(f"the source repositories are not in {base} and there is no {SCAN_FILE.name}; "
                         "use --base to point at them")

    cites = collections.defaultdict(set)
    origin = collections.defaultdict(set)
    family_keys = {}
    fm_frameworks = collections.Counter()
    rev_cites = collections.defaultdict(set)

    compiled = [(c[0], [re.compile(p) for p in c[8]]) for c in CATALOGUE]
    old_compiled = [(lbl, re.compile(rx, re.I if "CVSS" in lbl else 0), kind, txt, basis)
                    for lbl, rx, kind, txt, basis in OLD_REVISIONS]
    for c in CATALOGUE:
        origin[c[0]] |= c[7]

    def scan(text, who, repo):
        for key, pats in compiled:
            if any(p.search(text) for p in pats):
                cites[key].add(who)
                origin[key].add(repo)
        for family, rx, fmt, tier, covered in FAMILIES:
            for m in rx.finditer(text):
                num = m.group(1)
                if num in COVERED.get(family, ()):
                    continue
                key = fmt.format(num)
                family_keys[key] = (family, "C" if family == "ISO" and num in ISO_TIER_C else tier, covered)
                cites[key].add(who)
                origin[key].add(repo)
        for lbl, rx, *_ in old_compiled:
            if rx.search(text):
                rev_cites[lbl].add(who)
        for m in NIST_REV.finditer(text):
            rev_cites[f"NIST SP {m.group(1)} Rev. {m.group(2)}"].add(who)

    playbooks = sorted(d for d in anth.iterdir() if (d / "SKILL.md").exists()) if repos_present else []
    fm_map = {"mitre_attack": "mitre-attack", "nist_csf": "nist-csf", "atlas_techniques": "mitre-atlas",
              "d3fend_techniques": "mitre-d3fend", "nist_ai_rmf": "nist-ai-rmf", "mitre_f3": "mitre-f3"}
    for d in playbooks:
        skill_md = read(d / "SKILL.md")
        fm = frontmatter(skill_md)
        for k, key in fm_map.items():
            if re.search(rf"^{k}:", fm, re.M):
                fm_frameworks[k] += 1
                cites[key].add(d.name)
                origin[key].add("anthropic")
        text = skill_md + "".join(read(f) for f in sorted((d / "references").glob("*.md")))
        scan(text, d.name, "anthropic")
    n_playbooks = len(playbooks)
    if repos_present:
        for f in sorted(sa.glob("*.md")):
            scan(read(f), "security-audit:" + f.name, "security-audit")
        for f in sorted((sc / "references").rglob("*.md")):
            scan(read(f), "systema-cure:" + f.name, "systema-cure")
        SCAN_FILE.write_text(json.dumps({
            "cites": {k: sorted(v) for k, v in sorted(cites.items())},
            "origin": {k: sorted(v) for k, v in sorted(origin.items())},
            "family_keys": {k: list(v) for k, v in sorted(family_keys.items())},
            "fm_frameworks": dict(sorted(fm_frameworks.items())),
            "rev_cites": {k: sorted(v) for k, v in sorted(rev_cites.items())},
            "playbooks": n_playbooks,
        }, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        snap = json.loads(SCAN_FILE.read_text(encoding="utf-8"))
        for k, v in snap["cites"].items():
            cites[k] |= set(v)
        for k, v in snap["origin"].items():
            origin[k] |= set(v)
        family_keys.update({k: tuple(v) for k, v in snap["family_keys"].items()})
        fm_frameworks.update(snap["fm_frameworks"])
        for k, v in snap["rev_cites"].items():
            rev_cites[k] |= set(v)
        n_playbooks = snap["playbooks"]
        print(f"source repositories not found: using the snapshot {SCAN_FILE.name}")

    nist_rev_keys = [k for k in rev_cites if k.startswith("NIST SP ")]
    rfc_numbers = [k.split(" ")[1] for k in family_keys if k.startswith("RFC ")]
    if args.refresh_status:
        status = refresh_status([k for k in family_keys if family_path(k)], nist_rev_keys, rfc_numbers)
    elif STATUS_FILE.exists():
        status = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    else:
        status = {}
    local = local_dates()
    pages = status.get("csrc", {})

    def count(key):
        return sum(1 for q in cites[key] if ":" not in q)

    def abbrev(repos):
        return " ".join(a for a, r in (("SC", "systema-cure"), ("SA", "security-audit"), ("AN", "anthropic"))
                        if r in repos) or "—"

    # One row per standard: (tier, playbooks, name, version, target, url, note, origin, date, kind, status_text, basis)
    rows = []
    for key, name, tier, version, target, url, note, _, _ in CATALOGUE:
        date, kind, stext, basis = (tier_a_status(key, status, local) if tier == "A"
                                    else (EDITORIAL[key] + ("≈",) if key in EDITORIAL else ("—", "unchecked", "Not checked", "—")))
        rows.append(dict(tier=tier, n=count(key), name=name, version=version, target=target, url=url, note=note,
                         origin=abbrev(origin[key]), date=date, kind=kind, status=stext, basis=basis))
    for key, (family, tier, covered) in family_keys.items():
        num = key.split(" ")[-1]
        name = f"{key} ({NIST_SP_NAMES[num]})" if family == "NIST SP" and num in NIST_SP_NAMES else key
        date, kind, stext, basis = "—", "unchecked", "Not checked", "—"
        if key in SERIES:
            kind, stext = "n/a", SERIES[key]
        elif key in status.get("chains", {}):
            chain = status["chains"][key]
            s = nist_status(chain, pages)
            if s:
                date, kind, stext = s
                basis = "—" if kind == "unchecked" else "✓ CSRC"
                if kind == "superseded" and len(chain) > 1:
                    # Cited without revision: the standard's state is that of its live revision.
                    label, live_date, live_withdrawn = live_revision(chain, pages)
                    date = live_date
                    if live_withdrawn:
                        stext = f"Cited without revision; last revision {label} withdrawn {live_withdrawn}"
                    else:
                        kind, stext = "current", f"Cited without revision; live revision: {label}"
        elif family == "RFC":
            r = status.get("rfc", {}).get(f"RFC{int(num):04d}")
            if r:
                obs = r.get("obsoleted_by") or []
                date = r.get("date") or "—"
                kind = "superseded" if obs or (r.get("status") or "").upper() == "HISTORIC" else "current"
                stext = (f"Obsoleted by {', '.join(obs)}" if obs else (r.get("status") or "").title())
                basis = "✓ RFC Editor"
        elif family in ("ISO", "IEC"):
            stext, basis = "Not checked (licensed text)", "—"
        rows.append(dict(tier=tier, n=count(key), name=name, version="see citation", target=covered, url="—",
                         note=f"Detected by family ({family}).", origin=abbrev(origin[key]), date=date, kind=kind,
                         status=stext, basis=basis))

    # Old revisions cited by the playbooks (the not-current section).
    old = []
    for lbl, rx, kind, txt, basis in old_compiled:
        if rev_cites.get(lbl):
            old.append(dict(name=lbl, n=sum(1 for q in rev_cites[lbl] if ":" not in q), kind=kind, status=txt, basis=basis,
                            date=OLD_DATES.get(lbl, "—")))
    for key in nist_rev_keys:
        chain = status.get("chains", {}).get(key)
        s = nist_status(chain, pages) if chain else None
        same_revision = (bool(chain) and len(chain) > 1 and chain[-1].startswith(chain[0].rsplit("/", 1)[0] + "/")
                         and not pages.get(chain[-1], {}).get("withdrawn"))
        if s and s[1] == "superseded" and not same_revision:
            old.append(dict(name=key, n=sum(1 for q in rev_cites[key] if ":" not in q), kind="withdrawn", status=s[2],
                            basis="✓ CSRC", date=s[0]))
    old.sort(key=lambda r: (-r["n"], r["name"]))
    not_current_rows = [r for r in rows if r["kind"] in ("superseded", "draft", "unmaintained", "newer")]
    current_rows = [r for r in rows if r not in not_current_rows]

    def status_cell(r):
        mark = {"current": "Current", "living": "Living", "n/a": "N/A", "unchecked": "Not checked",
                "superseded": "Not current", "draft": "Draft", "unmaintained": "Unmaintained",
                "newer": "Newer release exists"}[r["kind"]]
        detail = r["status"] if r["status"] and r["status"] not in ("Not checked",) else ""
        return f"{mark}{' — ' + detail if detail and detail != mark else ''} {r['basis'] if r['basis'] != '—' else ''}".strip()

    out = []
    w = out.append
    w("# Inventory of standards across the three source repositories")
    w("")
    w("> Generated by `scripts/gen_inventory.py`. Do not edit by hand: regenerate. Publication dates and status "
      + (f"were checked online on **{status['checked']}** (`--refresh-status`)." if status.get("checked")
         else "have not been checked online yet: run `python scripts/gen_inventory.py --refresh-status`."))
    w("")
    w("## Contents")
    w("")
    for anchor, title in (("tiers", "Tiers"), ("date-and-status-columns", "Date and status columns"),
                          ("frameworks-in-playbook-frontmatter", "Frameworks in playbook frontmatter"),
                          ("security-audit", "security-audit"), ("tier-a--full-text-incorporated", "Tier A — full text incorporated"),
                          ("tier-b--reference-cards", "Tier B — reference cards"), ("tier-c--mentions", "Tier C — mentions"),
                          ("not-current-revisions-and-standards", "Not current: revisions and standards"),
                          ("totals", "Totals")):
        w(f"- [{title}](#{anchor})")
    w("")
    w(f"**Repositories scanned:** systema-cure · security-audit-skill · Anthropic-Cybersecurity-Skills "
      f"({n_playbooks} playbooks: frontmatter + `SKILL.md` + `references/*.md`).")
    w("")
    w("## Tiers")
    w("")
    w("| Tier | Meaning | Best achievable result against the standard |")
    w("|---|---|---|")
    w("| **A** | Full text incorporated under `references/standards/`, generated from the official source | PASS / FAIL |")
    w("| **B** | Reference card without text (licence, law or scope). *Covered by* names the tier-A standard that treats the subject | NOT VERIFIED, naming the candidate control |")
    w("| **C** | Format, protocol, conceptual model or operational data feed. Never a compliance criterion | — |")
    w("")
    w("**Reading *Playbooks*:** number of Anthropic-Cybersecurity-Skills playbooks that cite the standard in their "
      "frontmatter or text. A citation does not mean the playbook applies the standard; it is often context. "
      "**Origin** says where it appears: `SC` systema-cure, `SA` security-audit, `AN` Anthropic-Cybersecurity-Skills.")
    w("")
    w("## Date and status columns")
    w("")
    w("- **Date** is the publication date of the version this skill incorporates (tier A) or of the current version "
      "(tiers B and C). For NIST publications cited without a revision, it is the date of that base publication.")
    w("- **Status** is one of: *Current* · *Living* (continuously maintained, no fixed version) · *Not current* "
      "(withdrawn, superseded or obsoleted) · *Unmaintained* · *Newer release exists* (the version incorporated here "
      "is not the latest) · *Not checked*.")
    w("- How each status was established: **✓** checked online against the official source named next to it "
      "(CSRC publication pages, the RFC Editor index, the project's release metadata); **≈** editorial knowledge "
      "recorded in the generator, not verified online — re-check before relying on it in a formal opinion.")
    w("- Entries that are not current are listed in their own section, [Not current](#not-current-revisions-and-standards), "
      "not in the tier tables.")
    w("")
    w("## Frameworks in playbook frontmatter")
    w("")
    w("| Field | Playbooks |")
    w("|---|---:|")
    for k, v in fm_frameworks.most_common():
        w(f"| `{k}` | {v} |")
    w("")
    w("## security-audit")
    w("")
    names = {c[0]: c[1] for c in CATALOGUE}
    sa_refs = sorted(names.get(k, k) for k in cites if any(q.startswith("security-audit:") for q in cites[k]))
    w("It does not rest on external standards: its rules are its own methodology (a trust boundary plus a concrete "
      "result, the `confirmed / needs_validation / rejected` verdicts, the severity scale, sandboxed execution and "
      "coverage). They are incorporated as methodology under `references/audit/`. External references found in its "
      "text: " + (", ".join(sa_refs) or "none") + ".")
    w("")
    totals = collections.Counter()
    for tier, title in (("A", "Tier A — full text incorporated"), ("B", "Tier B — reference cards"),
                        ("C", "Tier C — mentions")):
        w(f"## {title}")
        w("")
        sel = sorted((r for r in current_rows if r["tier"] == tier), key=lambda r: (-r["n"], r["name"]))
        totals[tier] = sum(1 for r in rows if r["tier"] == tier)
        if tier == "A":
            w("| Standard | Version in this skill | Date | Status | File | Playbooks | Origin | Note |")
            w("|---|---|---|---|---|---:|---|---|")
            for r in sel:
                w(f"| {r['name']} | {r['version']} | {r['date']} | {status_cell(r)} | `{r['target']}` | {r['n']} | {r['origin']} | {r['note']} |")
        else:
            w("| Standard | Version cited | Date | Status | Covered by | Playbooks | Origin | Official URL | Note |")
            w("|---|---|---|---|---|---:|---|---|---|")
            for r in sel:
                w(f"| {r['name']} | {r['version']} | {r['date']} | {status_cell(r)} | {r['target']} | {r['n']} | {r['origin']} | {r['url']} | {r['note']} |")
        w("")
    w("## Not current: revisions and standards")
    w("")
    w("What a reader must not treat as the current text. A finding never cites anything in this section as its "
      "requirement; use the replacement.")
    w("")
    w("### Old revisions cited by the source repositories")
    w("")
    if old:
        w("| Cited revision | Status | Date of the cited revision | Playbooks | How checked |")
        w("|---|---|---|---:|---|")
        for r in old:
            w(f"| {r['name']} | {r['status']} | {r['date']} | {r['n']} | {r['basis']} |")
    else:
        w("None detected.")
    w("")
    for kind, title, text in (("superseded", "Withdrawn, superseded or obsoleted standards",
                               "Detected citations whose publication is no longer in force."),
                              ("draft", "Drafts that never became final",
                               "Public drafts with no final publication; cite them as drafts, never as requirements."),
                              ("unmaintained", "Unmaintained standards", "Still published but no longer updated."),
                              ("newer", "Incorporated here, but a newer release exists",
                               "Regenerate from the newer release, or record why this skill stays on the older one.")):
        sel = sorted((r for r in not_current_rows if r["kind"] == kind), key=lambda r: (-r["n"], r["name"]))
        w(f"### {title}")
        w("")
        w(text)
        w("")
        if sel:
            w("| Standard | Tier | Date | Status | Playbooks | Covered by / file |")
            w("|---|---|---|---|---:|---|")
            for r in sel:
                w(f"| {r['name']} | {r['tier']} | {r['date']} | {r['status']} {r['basis'] if r['basis'] != '—' else ''} | {r['n']} | {r['target']} |")
        else:
            w("None.")
        w("")
    total = sum(totals.values())
    w("## Totals")
    w("")
    w(f"{total} distinct standards or references: **{totals['A']} in tier A**, {totals['B']} in tier B and "
      f"{totals['C']} in tier C; {len(not_current_rows)} of them not current, plus {len(old)} old revisions cited. "
      "No detected citation is left without a tier: anything outside the curated catalogue enters through its family "
      "(NIST SP, NISTIR, FIPS, ISO/IEC, IEC, RFC).")
    w("")
    w("**Detection limit:** names and identifiers are matched with regular expressions. A standard cited under a "
      "name that fits none of the patterns does not appear here. To extend the catalogue, add an entry to "
      "`CATALOGUE` in the generator.")
    missing = [c[4] for c in CATALOGUE if c[2] == "A" and not (SKILL / "references" / c[4]).exists()]
    if missing:
        w("")
        w("**Tier-A files not generated yet:** " + ", ".join(f"`{m}`" for m in missing))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")

    cards = ["# Tier-B reference cards", "",
             "> Generated by `scripts/gen_inventory.py`. This skill does **not** hold the text of these standards (licence, "
             "law or scope). A finding can point to them only as a candidate: the best achievable result is NOT "
             "VERIFIED, with the control named and the tier-A standard that covers the subject. Do not edit by hand.", ""]
    rows_b = sorted((c for c in CATALOGUE if c[2] == "B"), key=lambda c: (-count(c[0]), c[1]))
    for key, name, _, version, covered, url, note, _, _ in rows_b:
        who = sorted(q for q in cites[key] if ":" not in q)
        date, kind, stext = EDITORIAL.get(key, ("—", "unchecked", "Not checked"))
        cards += [f"## {name}", "",
                  f"- **Version cited:** {version}",
                  f"- **Date / status:** {date} — {stext} (≈ editorial)",
                  f"- **Official URL:** {url}",
                  f"- **Why tier B:** {note}",
                  f"- **Covered in this skill by:** {covered}",
                  f"- **Cited by {len(who)} playbook(s):** " + (", ".join(f"`{x}`" for x in who[:12]) +
                                                               (f" … (+{len(who) - 12})" if len(who) > 12 else "") if who else "—"),
                  ""]
    fam = sorted(((k, v) for k, v in family_keys.items() if v[1] == "B"), key=lambda kv: (-count(kv[0]), kv[0]))
    cards += ["## Other tier-B publications detected by family", "",
              "| Publication | Playbooks | Covered by |", "|---|---:|---|"]
    for k, (familyname, _, covered) in fam:
        num = k.split(" ")[-1]
        name = f"{k} ({NIST_SP_NAMES[num]})" if familyname == "NIST SP" and num in NIST_SP_NAMES else k
        cards.append(f"| {name} | {count(k)} | {covered} |")
    CARDS.write_text("\n".join(cards) + "\n", encoding="utf-8")
    print(f"OK {OUT.relative_to(SKILL)}: {total} entries (A={totals['A']}, B={totals['B']}, C={totals['C']}); "
          f"not current: {len(not_current_rows)}; old revisions cited: {len(old)}; "
          f"status checked: {status.get('checked', 'never')}")


if __name__ == "__main__":
    main()
