#!/usr/bin/env python3
"""Download the official sources that the generators read, and record their provenance.

Every file lands under sources/<path> and gets an entry in sources/manifest.json with
its URL, final URL after redirects, size, SHA-256 and download date. Existing files are skipped
unless --force is given, so a re-run only fetches what is missing. An existing file with no manifest
entry (the inputs inherited from systema-cure) is adopted: hashed and recorded with "adopted": true.

Files larger than SHIP_LIMIT are download caches: they are listed in sources/.gitignore and
left out of the packaged skill. The manifest keeps their hash, so a regeneration can prove it used
the same input.

Usage:
  python fetch_sources.py              fetch everything missing
  python fetch_sources.py attack csf   fetch only the named groups
  python fetch_sources.py --force ...  re-download even if present
  python fetch_sources.py --list       show the groups

Stdlib only.
"""
import argparse, datetime, hashlib, json, pathlib, sys, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = ROOT.parent / "sources"
SKILL = ROOT.parent / "skills" / "security" / "cybersec-skill"
SRC = SOURCES
MANIFEST = SRC / "manifest.json"
SHIP_LIMIT = 5 * 1024 * 1024
UA = "cybersec-skill-source-fetcher/1.0 (+official standards download)"

RAW = "https://raw.githubusercontent.com"
CPRT = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/{}/export/json?element=all"
GENAI = RAW + "/GenAI-Security-Project/GenAI-Security-Advisor/main/corpus/llm-top10/2026/"
API23 = RAW + "/OWASP/API-Security/master/editions/2023/en/"
SLSA = RAW + "/slsa-framework/slsa/v1.2/docs/spec/v1.2/"
CVSSCALC = RAW + "/FIRSTdotorg/cvss-v4-calculator/main/"
ASI = RAW + "/GenAI-Security-Project/translations/main/owasp-top-10-for-agentic-applications-2026-12-6-1/_source/"

GROUPS = {
    "attack": [
        ("attack/enterprise-attack-20.0.json", RAW + "/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json"),
        ("attack/mobile-attack-20.0.json", RAW + "/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-20.0.json"),
        ("attack/ics-attack-20.0.json", RAW + "/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-20.0.json"),
    ],
    "d3fend": [("d3fend/d3fend.json", "https://d3fend.mitre.org/ontologies/d3fend.json")],
    "csf": [("csf/csf-2.0.0.json", CPRT.format("csf_2_0_0"))],
    "ssdf": [("ssdf/sp800-218-1.1.0.json", CPRT.format("sp_800_218_1_1_0"))],
    "218a": [("ssdf/NIST.SP.800-218A.pdf", "https://doi.org/10.6028/NIST.SP.800-218A")],
    "ai-rmf": [("ai-rmf/playbook.json", "https://airc.nist.gov/docs/playbook.json"),
               ("ai-rmf/NIST.AI.100-1.pdf", "https://doi.org/10.6028/NIST.AI.100-1")],
    "ai-600-1": [("ai-rmf/NIST.AI.600-1.pdf", "https://doi.org/10.6028/NIST.AI.600-1")],
    "f3": [("f3/f3-stix-v1.2.json", RAW + "/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-stix-v1.2.json"),
           ("f3/f3-stix-v1.1.json", RAW + "/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-stix-v1.1.json")],
    "cwe": [("cwe/cwec_latest.xml.zip", "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"),
            ("cwe/2025_cwe_top25.html", "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html")],
    "cvss": [
        ("cvss/specification-document.html", "https://www.first.org/cvss/v4.0/specification-document"),
        ("cvss/examples.html", "https://www.first.org/cvss/v4.0/examples"),
    ] + [(f"cvss/calculator/{n}", CVSSCALC + n) for n in
         ("cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js", "metrics.js", "cvss_details.js")],
    "api-top10": [(f"api-top10-2023/{n}", API23 + n) for n in (
        "0x10-api-security-risks.md", "0x11-t10.md",
        "0xa1-broken-object-level-authorization.md", "0xa2-broken-authentication.md",
        "0xa3-broken-object-property-level-authorization.md", "0xa4-unrestricted-resource-consumption.md",
        "0xa5-broken-function-level-authorization.md", "0xa6-unrestricted-access-to-sensitive-business-flows.md",
        "0xa7-server-side-request-forgery.md", "0xa8-security-misconfiguration.md",
        "0xa9-improper-inventory-management.md", "0xaa-unsafe-consumption-of-apis.md")],
    "800-63b": [("nist-800-63b-4/sp800-63b.html", "https://pages.nist.gov/800-63-4/sp800-63b.html")],
    "masvs": [("masvs/OWASP_MASVS-2.1.0.yaml", "https://github.com/OWASP/masvs/releases/download/v2.1.0/OWASP_MASVS.yaml")],
    "800-53": [("nist-800-53/NIST_SP-800-53_rev5_catalog.json",
                RAW + "/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json")],
    "slsa": [(f"slsa-1.2/{n}", SLSA + n) for n in (
        "index.md", "whats-new.md", "about.md", "terminology.md", "tracks.md", "requirements.md",
        "build-track-basics.md", "build-requirements.md", "source-requirements.md", "threats-overview.md",
        "threats.md", "verifying-artifacts.md", "verifying-source.md", "build-provenance.md",
        "assessing-build-platforms.md", "assessing-source-systems.md")],
    "nist-guides": [
        ("nist-guides/NIST.SP.800-190.pdf", "https://doi.org/10.6028/NIST.SP.800-190"),
        ("nist-guides/NIST.SP.800-207.pdf", "https://doi.org/10.6028/NIST.SP.800-207"),
        ("nist-guides/NIST.SP.800-61r3.pdf", "https://doi.org/10.6028/NIST.SP.800-61r3"),
        ("nist-guides/NIST.SP.800-86.pdf", "https://doi.org/10.6028/NIST.SP.800-86"),
        ("nist-guides/NIST.SP.800-115.pdf", "https://doi.org/10.6028/NIST.SP.800-115"),
        ("nist-guides/NIST.SP.800-40r4.pdf", "https://doi.org/10.6028/NIST.SP.800-40r4"),
    ],
    "ztmm": [("cisa-ztmm/zero_trust_maturity_model_v2_508.pdf",
              "https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf")],
    "llm-top10": [(f"llm-top10-2026/{n}", GENAI + n) for n in (
        "LLM00_Preface.md", "LLM01_PromptInjection.md", "LLM02_SensitiveInformationDisclosure.md",
        "LLM03_ExcessiveAgency.md", "LLM04_SupplyChain.md", "LLM05_DataModelPoisoning.md",
        "LLM06_UnboundedConsumption.md", "LLM07_Misinformation.md", "LLM08_HiddenContextExposure.md",
        "LLM09_VectorAndEmbeddingWeaknesses.md", "LLM10_ImproperOutputHandling.md",
        "Appendix_A_Related_Framework_Mappings.md", "Appendix_B_LLM_Application_Architecture_and_Threat_Modeling.md",
        "LLMZZ_Appendix_AISVS_Mapping.md", "references.md")],
    # Inherited from systema-cure (its tools/fuentes folder). Present files are adopted (hashed, not re-downloaded),
    # so the pinned inputs that systema-cure verified stay the same; --force re-downloads them.
    "asvs": [("asvs.csv", RAW + "/OWASP/ASVS/v5.0.0/5.0/docs_en/"
              "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv")],
    "atlas": [("atlas-2026.09.yaml", RAW + "/mitre-atlas/atlas-data/main/dist/v6/ATLAS-2026.09.yaml")],
    "threats": [("threats-1.1.pdf", RAW + "/GenAI-Security-Project/GenAI-Security-Advisor/main/"
                 "corpus/agentic-top10/companions/Agentic-AI-Threats-and-Mitigations-1.1.pdf")],
    "crosswalk": [(f"crosswalk/{n}.json", RAW + f"/GenAI-Security-Project/crosswalk/main/data/entries/{n}.json")
                  for n in (f"ASI{i:02d}" for i in range(1, 11))],
    "asi": [(f"asi-2026/{n}", ASI + n) for n in (
        "OWASP_Top_10_For_Agentic_Applications_2026.md", "Table_of_Content.md",
        "Letter_from_The_Agentic_Top_10_Leaders.md", "Agentic_Top_10_At_A_Glance.md",
        "ASI01_Agent_Goal_Hijack.md", "ASI02_Tool_Misuse_and_Exploitation.md",
        "ASI03_Identity_and_Privilege_Abuse.md", "ASI04_Agentic_Supply_Chain_Vulnerabilities.md",
        "ASI05_Unexpected_Code_Execution_RCE.md", "ASI06_Memory_Context_Poisoning.md",
        "ASI07_Insecure_Inter_Agent_Communication.md", "ASI08_Cascading_Failures.md",
        "ASI09_Human_Agent_Trust_Exploitation.md", "ASI10_Rogue_Agents.md",
        "Appendix_A_OWASP_Agentic_AI_Security_Mapping_Matrix.md",
        "Appendix_B_Relationship_to_OWASP_CycloneDX_and_AIBOM.md",
        "Appendix_C_Mapping_Between_OWASP_Non_Human_Identities_Top_10_2025_and_OWASP_Agentic_AI_Top_10.md",
        "Appendix_D_ASI_Agentic_Exploits_Incidents_Tracker.md", "Appendix_E_Abbreviations.md",
        "Acknowledgements.md", "Project_Supporters.md")],
    # The SAMM V2.0 PDF reached systema-cure without a recorded download URL: adopt-only.
    "samm": [("SAMM-v2-PDF.pdf", None)],
}


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=180) as r:
        data = r.read()
        final = r.geturl()
        ctype = r.headers.get("Content-Type", "")
    return data, final, ctype


def looks_wrong(path, data, ctype):
    """Catch the classic failure: an HTML error or login page saved as a PDF/JSON/ZIP."""
    head = data[:512].lstrip().lower()
    if path.endswith(".pdf") and not data.startswith(b"%PDF"):
        return "not a PDF"
    if path.endswith(".zip") and not data.startswith(b"PK"):
        return "not a ZIP"
    if path.endswith((".json", ".yaml", ".md", ".js")) and (head.startswith(b"<!doctype") or head.startswith(b"<html")):
        return "HTML page instead of data"
    if path.endswith(".json"):
        try:
            json.loads(data)
        except ValueError:
            return "invalid JSON"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("groups", nargs="*")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for g, items in GROUPS.items():
            print(f"{g:12s} {len(items)} file(s)")
        return
    unknown = set(args.groups) - set(GROUPS)
    if unknown:
        sys.exit(f"unknown group(s): {', '.join(sorted(unknown))}")
    manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    failures = []
    for g in args.groups or GROUPS:
        for rel, url in GROUPS[g]:
            dest = SRC / rel
            if dest.exists() and not args.force and rel in manifest:
                print(f"skip  {rel}")
                continue
            if dest.exists() and not args.force:
                data = dest.read_bytes()
                manifest[rel] = {
                    "group": g, "url": url, "final_url": None, "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "fetched": datetime.date.today().isoformat(), "adopted": True,
                    "shipped": len(data) <= SHIP_LIMIT,
                }
                print(f"adopt {rel} (existing copy hashed, not downloaded)")
                continue
            if url is None:
                failures.append((rel, "(no download URL recorded)", "supply the file by hand"))
                print(f"FAIL  {rel}: no download URL recorded")
                continue
            try:
                data, final, ctype = fetch(url)
            except Exception as e:  # report and continue with the rest
                failures.append((rel, url, str(e)))
                print(f"FAIL  {rel}: {e}")
                continue
            problem = looks_wrong(rel, data, ctype)
            if problem:
                failures.append((rel, url, f"{problem} (final URL {final}, {ctype})"))
                print(f"FAIL  {rel}: {problem} -> {final}")
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            manifest[rel] = {
                "group": g, "url": url, "final_url": final, "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "fetched": datetime.date.today().isoformat(),
                "shipped": len(data) <= SHIP_LIMIT,
            }
            print(f"ok    {rel} ({len(data):,} bytes)")
    MANIFEST.write_text(json.dumps(dict(sorted(manifest.items())), indent=2) + "\n")
    cache = sorted(k for k, v in manifest.items() if not v["shipped"])
    gi = SRC / ".gitignore"
    keep = [ln for ln in (gi.read_text().splitlines() if gi.exists() else []) if not ln.startswith("# >5MB cache: ")
            and ln not in cache]
    gi.write_text("\n".join(keep + [f"# >5MB cache: regenerate with fetch_sources.py (hash in manifest.json)"]
                            + cache) + "\n")
    if failures:
        print("\nFailed downloads:")
        for rel, url, err in failures:
            print(f"  {rel}\n    {url}\n    {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
