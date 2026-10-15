#!/usr/bin/env python3
"""Verify every identifier cited in the skill's own text against the standard files that define it.

Scans SKILL.md, the views under references/, the SC catalogue, governance.md, the audit docs and the source
constants of scripts/audit_deps.py. Generated files (references/standards/, crosswalk/, playbooks/) are not
scanned: their generators verify them against the official sources.

Each identifier family is resolved against the definitions in its standard file, taken from headings (or the
table that defines them), so an identifier that only appears in a "revoked", "deprecated" or "withdrawn" list
does not count as defined. Backticked file paths are checked to exist.

Usage:
  python scripts/verify_ids.py            report and exit 1 on any unknown identifier or missing path
  python scripts/verify_ids.py --verbose  also print the count of verified identifiers per family

Stdlib only.
"""
import argparse, collections, pathlib, re, sys

SKILL = pathlib.Path(__file__).resolve().parent.parent
REFS = SKILL / "references"
STD = REFS / "standards"

SCANNED = ["SKILL.md", "references/context-model.md", "references/lifecycle.md", "references/by-component.md",
           "references/domains.md", "references/ai-llm-agents.md", "references/verification.md",
           "references/sc-controls-catalog.md", "references/governance.md", "references/audit/README.md",
           "references/audit/dependencies.md", "references/audit/exposures.md", "scripts/audit_deps.py",
           "scripts/find_exposures.py"]

# Identifiers cited on purpose although they are not defined: (files allowed to cite them, reason).
EXCEPTIONS = {
    "AML.T0045": ({"references/governance.md"}, "retired from ATLAS; cited as a crosswalk divergence"),
    "CWE-730": ({"references/governance.md"}, "CWE category; cited as a crosswalk divergence"),
    "T0807": ({"references/governance.md"}, "deprecated ICS technique cited by playbooks"),
    "T0853": ({"references/governance.md"}, "deprecated ICS technique cited by playbooks"),
}

# Files written by an audit run, or looked for in an audited target, named in the docs but not part of the skill.
OUTPUT_FILES = {"findings.json", "run-metadata.json", "coverage-ledger.json", "security-report.html", "sbom.cdx.json",
                "deps-raw.json", "deps-findings.json", "exposures-raw.json", "exposures-findings.json", "REPORT.md",
                "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md", "status.json", "manifest.json", "local.settings.json",
                "config.json"}

HEAD = re.compile(r"^#{1,6}\s+(.*)$")
# Where a bare file name in backticks may live (a table of upstream files, a list of index files...).
# The source repository around the skill (skills/<bucket>/<skill>/): build scripts, sources and tests live there.
# An installed copy has no repository, so paths that only exist in it cannot be checked and are skipped.
REPO = SKILL.parents[1].parent
HAS_REPO = (REPO / "scripts" / "build_all.py").exists()
PATH_ROOTS = ((REPO, REPO / "scripts", REPO / "sources", REPO / "tests") if HAS_REPO else ()) + (SKILL, REFS, STD, SKILL / "scripts", SKILL / "schemas", SKILL / "assets", REFS / "audit", REFS / "audit" / "upstream",
              REFS / "playbooks", STD / "nist-800-53r5", STD / "mitre-attack", STD / "cwe")


def headings(path):
    return [m.group(1) for m in (HEAD.match(ln) for ln in path.read_text(encoding="utf-8").splitlines()) if m]


def tokens(rx, lines):
    out = set()
    for ln in lines:
        out.update(m.group(0) for m in rx.finditer(ln))
    return out


# ------------------------------------------------------------------------------------------- definitions

def build_index():
    ix = {}
    asvs = headings(STD / "owasp-asvs-5.0.0.md")
    ix["asvs-req"] = {m.group(1) for h in asvs for m in [re.match(r"v5\.0\.0-(\d+\.\d+\.\d+)", h)] if m}
    ix["asvs-sec"] = {m.group(1) for h in asvs for m in [re.match(r"V(\d+(?:\.\d+)?)\b", h)] if m}

    ssdf_rx = re.compile(r"\b(?:PO|PS|PW|RV)\.\d+(?:\.\d+)?\b")
    ix["ssdf"] = tokens(ssdf_rx, headings(STD / "nist-ssdf-800-218.md"))
    a = set()
    task = None
    for ln in (STD / "nist-800-218a.md").read_text(encoding="utf-8").splitlines():
        h = HEAD.match(ln)
        if h:
            m = ssdf_rx.search(h.group(1))
            task = m.group(0) if m else None
            if m:
                a.add(m.group(0))
            continue
        m = re.match(r"- \*\*([RCN]\d+):\*\*", ln)
        if m and task:
            a.add(f"{task}.{m.group(1)}")
    ix["218a"] = a

    ix["top10"] = {m.group(1) for h in headings(STD / "owasp-top10-2025.md") for m in [re.match(r"(A\d\d):2025", h)] if m}
    ix["api"] = set(re.findall(r"API(\d{1,2}):2023", (STD / "owasp-api-top10-2023.md").read_text(encoding="utf-8")))
    ix["llm"] = {m.group(1) for h in headings(STD / "owasp-llm-top10-2026.md") for m in [re.match(r"LLM(\d\d):2026", h)] if m}
    ix["asi"] = tokens(re.compile(r"\bASI\d\d\b"), headings(STD / "owasp-asi-top10-2026.md"))
    ix["atlas"] = tokens(re.compile(r"AML\.(?:TA|T|M)\d{4}(?:\.\d{3})?"), headings(STD / "mitre-atlas.md"))

    att_lines = []
    for f in sorted((STD / "mitre-attack").glob("*.md")):
        att_lines += headings(f)
        att_lines += [ln for ln in f.read_text(encoding="utf-8").splitlines() if ln.startswith("- **TA")]
    ix["attack"] = tokens(re.compile(r"(?<![\w.])(?:TA|T|M)\d{4}(?:\.\d{3})?(?![\w])"), att_lines)

    ix["d3fend"] = tokens(re.compile(r"\bD3-[A-Z0-9]+\b"), headings(STD / "mitre-d3fend.md"))
    f3 = (STD / "mitre-f3-1.2.md").read_text(encoding="utf-8")
    ix["f3"] = (tokens(re.compile(r"(?<![\w.])F\d{4}(?:\.\d{3})?(?![\w])"), headings(STD / "mitre-f3-1.2.md"))
                | set(re.findall(r"\bFA\d{4}\b", f3)))

    active, deprecated, in_dep = set(), set(), False
    for ln in (STD / "cwe" / "weaknesses.md").read_text(encoding="utf-8").splitlines():
        if ln.startswith("## Deprecated"):
            in_dep = True
        m = re.match(r"#{2,4}\s+CWE-(\d+)\b", ln) or (re.match(r"[-|]\s*`?CWE-(\d+)", ln) if in_dep else None)
        if m:
            (deprecated if in_dep else active).add(m.group(1))
    ix["cwe"], ix["cwe-deprecated"] = active, deprecated

    ix["csf"] = tokens(re.compile(r"\b(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}(?:-\d{2})?\b"), headings(STD / "nist-csf-2.0.md"))
    ix["ai-rmf"] = {re.sub(r"\s+", " ", m.group(0)) for h in headings(STD / "nist-ai-rmf-1.0.md")
                    for m in [re.match(r"(?:GOVERN|MAP|MEASURE|MANAGE) \d+(?:\.\d+)?", h)] if m}
    ix["ai-600-1"] = set(re.findall(r"`((?:GV|MP|MS|MG)-\d+\.\d+-\d{3})`", (STD / "nist-ai-600-1.md").read_text(encoding="utf-8")))
    n53 = set()
    for f in (STD / "nist-800-53r5").glob("*.md"):
        for h in headings(f):
            m = re.match(r"([A-Z]{2}-\d+(?:\(\d+\))?)\s+—\s+(.*)", h)
            if m and "withdrawn" not in m.group(2).lower():
                n53.add(m.group(1))
    ix["800-53"] = n53
    masvs = headings(STD / "owasp-masvs.md")
    ix["masvs"] = tokens(re.compile(r"\bMASVS-[A-Z]+-\d+\b"), masvs) | set(
        re.findall(r"\*\*(MASVS-[A-Z]+) —", (STD / "owasp-masvs.md").read_text(encoding="utf-8")))
    ix["sc"] = tokens(re.compile(r"\bSC-[A-Z]+-\d{2}\b"), headings(REFS / "sc-controls-catalog.md"))
    ix["slsa"] = set(re.findall(r"\b((?:Build|Source) L\d)\b", (STD / "slsa.md").read_text(encoding="utf-8")))

    ix["doc"] = {}
    for doc, fname in DOCS.items():
        sections, items, current = set(), {}, None
        for ln in (STD / fname).read_text(encoding="utf-8").splitlines():
            o = re.match(r"\s*- (\d+(?:\.\d+)*)\.?\s", ln)   # the Outline list names every section
            if o:
                sections.add(o.group(1))
            h = HEAD.match(ln)
            if h:
                m = re.match(r"(\d+(?:\.\d+)*)\.?\s", h.group(1))
                if m:
                    current = m.group(1)
                    sections.add(current)
                continue
            m = re.match(r"- \*\*R(\d+)\*\*", ln)
            if m and current:
                items[m.group(1)] = current
        ix["doc"][doc] = (sections, items)
    return ix


DOCS = {"800-63B": "nist-800-63b-4.md", "800-190": "nist-800-190.md", "800-207": "nist-800-207.md",
        "800-86": "nist-800-86.md", "800-115": "nist-800-115.md", "800-40": "nist-800-40r4.md"}

# ------------------------------------------------------------------------------------------- citations

R_218A_CTX = re.compile(r"800-218A[`\s]*$")


def check_text(rel, text, ix):
    """Yield (family, identifier, ok, why, line) for every identifier in the text."""
    lines = text.splitlines()
    for no, ln in enumerate(lines, 1):
        for m in re.finditer(r"v5\.0\.0-(\d+\.\d+\.\d+)", ln):
            yield "ASVS", m.group(0), m.group(1) in ix["asvs-req"], "not an ASVS 5.0.0 requirement", no
        for m in re.finditer(r"(?<![\w.])V(\d+)((?:\.\d+){0,2})(?![\w])", ln):
            if "SAMM" in ln[:m.start()]:   # SAMM V2.0, not an ASVS chapter
                continue
            ident = m.group(1) + m.group(2)
            ok = ident in ix["asvs-req"] if ident.count(".") == 2 else ident in ix["asvs-sec"]
            yield "ASVS", "V" + ident, ok, "not an ASVS 5.0.0 chapter, section or requirement", no
        for m in re.finditer(r"(?<![\w.-])((?:PO|PS|PW|RV)\.\d+(?:\.\d+)?)((?:\.[RCN]\d+)?)(?![\w])", ln):
            ident = m.group(1) + m.group(2)
            if m.group(2) or R_218A_CTX.search(ln[:m.start()]):
                yield "800-218A", ident, ident in ix["218a"], "not a task or item of SP 800-218A", no
            else:
                yield "SSDF", ident, ident in ix["ssdf"], "not an SSDF 1.1 practice or task", no
        for m in re.finditer(r"\b(A\d\d):(\d{4})\b", ln):
            yield "Top 10", m.group(0), m.group(2) == "2025" and m.group(1) in ix["top10"], "not an OWASP Top 10:2025 category", no
        for m in re.finditer(r"\bAPI(\d{1,2})(?::(\d{4}))?\b", ln):
            ok = (m.group(2) in (None, "2023")) and str(int(m.group(1))) in {str(int(x)) for x in ix["api"]}
            yield "API Top 10", m.group(0), ok, "not an API Security Top 10 2023 risk", no
        for m in re.finditer(r"\bLLM(\d\d)(?::(\d{4}))?\b", ln):
            ok = m.group(2) in (None, "2026") and m.group(1) in ix["llm"]
            yield "LLM Top 10", m.group(0), ok, "not an LLM Top 10 2026 risk", no
        for m in re.finditer(r"\bASI\d\d\b", ln):
            yield "ASI", m.group(0), m.group(0) in ix["asi"], "not an ASI 2026 risk", no
        for m in re.finditer(r"AML\.(?:TA|T|M)\d{4}(?:\.\d{3})?", ln):
            yield "ATLAS", m.group(0), m.group(0) in ix["atlas"], "not in ATLAS 2026.09", no
        for m in re.finditer(r"(?<![\w.])(?:TA|T|M)\d{4}(?:\.\d{3})?(?![\w])", ln):
            yield "ATT&CK", m.group(0), m.group(0) in ix["attack"], "not a live ATT&CK 20.0 object", no
        for m in re.finditer(r"\bD3-[A-Z0-9]+\b", ln):
            yield "D3FEND", m.group(0), m.group(0) in ix["d3fend"], "not a D3FEND technique", no
        for m in re.finditer(r"(?<![\w.])F\d{4}(?:\.\d{3})?(?![\w])|\bFA\d{4}\b", ln):
            yield "F3", m.group(0), m.group(0) in ix["f3"], "not in F3 1.2", no
        for m in re.finditer(r"\bCWE-(\d+)\b", ln):
            n = m.group(1)
            why = "deprecated CWE entry" if n in ix["cwe-deprecated"] else "not a CWE 4.20 weakness (category, view or unknown)"
            yield "CWE", m.group(0), n in ix["cwe"], why, no
        for m in re.finditer(r"(?<![\w.])(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}(?:-\d{2})?(?![\w])", ln):
            yield "CSF 2.0", m.group(0), m.group(0) in ix["csf"], "not a CSF 2.0 category or subcategory", no
        for m in re.finditer(r"\b(?:GOVERN|MAP|MEASURE|MANAGE) \d+(?:\.\d+)?\b", ln):
            yield "AI RMF", m.group(0), m.group(0) in ix["ai-rmf"], "not an AI RMF 1.0 category or subcategory", no
        for m in re.finditer(r"(?<![\w-])(?:GV|MP|MS|MG)-\d+\.\d+-\d{3}\b", ln):
            yield "AI 600-1", m.group(0), m.group(0) in ix["ai-600-1"], "not an AI 600-1 action", no
        for m in re.finditer(r"(?<![\w.-])(?:AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)-\d{1,2}(?:\(\d{1,2}\))?(?![\w-])", ln):
            yield "800-53", m.group(0), m.group(0) in ix["800-53"], "not a current SP 800-53 Rev. 5 control", no
        for m in re.finditer(r"\bMASVS-[A-Z]+(?:-\d+)?\b", ln):
            yield "MASVS", m.group(0), m.group(0) in ix["masvs"], "not a MASVS 2.1.0 group or control", no
        for m in re.finditer(r"\bSC-[A-Z]+-\d{2}\b", ln):
            yield "SC", m.group(0), m.group(0) in ix["sc"], "not a control of sc-controls-catalog.md", no
        for m in re.finditer(r"\b(?:Build|Source) L\d\b", ln):
            yield "SLSA", m.group(0), m.group(0) in ix["slsa"], "not a SLSA 1.2 level", no
        for m in re.finditer(r"\b(800-63B|800-190|800-207|800-86|800-115|800-40)(?:-4|r4)?\b[^§\n]{0,30}?§\s?(\d+(?:\.\d+)*)(?:\s+R(\d+))?",
                             ln, re.I):
            doc = m.group(1).upper()
            sections, items = ix["doc"][doc]
            ident = f"{doc} §{m.group(2)}" + (f" R{m.group(3)}" if m.group(3) else "")
            if m.group(2) not in sections:
                yield "NIST guide", ident, False, "no such section", no
            elif m.group(3):
                sec = items.get(m.group(3))
                ok = sec is not None and (sec == m.group(2) or sec.startswith(m.group(2) + "."))
                yield "NIST guide", ident, ok, f"R{m.group(3)} is in §{sec}" if sec else "no such item", no
            else:
                yield "NIST guide", ident, True, "", no
        for m in re.finditer(r"`([\w./<>*-]+\.(?:md|py|json|html|js))`", ln):
            p = m.group(1)
            if (any(c in p for c in "<>*") or "0n" in p or ".." in p or p.startswith("-")
                    or pathlib.PurePath(p).name in OUTPUT_FILES):
                continue
            ok = any((d / p).exists() for d in ((SKILL / rel).parent,) + PATH_ROOTS)
            if not ok and not HAS_REPO:
                continue
            yield "path", p, ok, "file not found", no


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    ix = build_index()
    counts, bad, excused = collections.Counter(), [], []
    for rel in SCANNED:
        text = (SKILL / rel).read_text(encoding="utf-8")
        for family, ident, ok, why, no in check_text(rel, text, ix):
            if ok:
                counts[family] += 1
            elif ident in EXCEPTIONS and rel in EXCEPTIONS[ident][0]:
                excused.append((rel, no, ident, EXCEPTIONS[ident][1]))
            else:
                bad.append((rel, no, family, ident, why))
    if args.verbose:
        for family, n in sorted(counts.items()):
            print(f"  {family:12s} {n} citations verified")
    for rel, no, ident, reason in excused:
        print(f"exception  {rel}:{no}  {ident}  ({reason})")
    for rel, no, family, ident, why in bad:
        print(f"UNKNOWN    {rel}:{no}  [{family}] {ident} — {why}")
    total = sum(counts.values())
    print(f"{'OK' if not bad else 'FAIL'}: {total} citations verified in {len(SCANNED)} files, "
          f"{len(excused)} documented exceptions, {len(bad)} unknown")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
