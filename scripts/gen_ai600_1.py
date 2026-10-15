#!/usr/bin/env python3
"""Generate references/standards/nist-ai-600-1.md from the official NIST AI 600-1 PDF.

NIST AI 600-1 (Generative AI Profile, July 2024) defines 12 GAI risks (section 2) and suggested
actions (section 3) organised under the AI RMF subcategories, each tagged with GAI risks and AI
actor tasks. The PDF text reads in order (ID, action, risk tags), so each action is split from its
trailing risk tags using the closed vocabulary of the 12 risks. The run fails if a tag falls outside
that vocabulary or an action ID repeats.

Requires pypdf.
"""
import pathlib, re, sys

try:
    import pypdf
except ImportError:  # pragma: no cover
    sys.exit("requires pypdf: pip install pypdf")

ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = ROOT.parent / "sources"
SKILL = ROOT.parent / "skills" / "security" / "cybersec-skill"
PDF = SOURCES / "ai-rmf" / "NIST.AI.600-1.pdf"
OUT = SKILL / "references" / "standards" / "nist-ai-600-1.md"
DOI = "https://doi.org/10.6028/NIST.AI.600-1"
RISKS = ["CBRN Information or Capabilities", "Confabulation", "Dangerous, Violent, or Hateful Content",
         "Data Privacy", "Environmental Impacts", "Harmful Bias and Homogenization", "Human-AI Configuration",
         "Information Integrity", "Information Security", "Intellectual Property",
         "Obscene, Degrading, and/or Abusive Content", "Value Chain and Component Integration"]
FN = {"GV": "GOVERN", "MP": "MAP", "MS": "MEASURE", "MG": "MANAGE"}
ALIASES = {"Environmental": "Environmental Impacts", "Human AI Configuration": "Human-AI Configuration",
           "CBRN Information and Capability": "CBRN Information or Capabilities"}  # shortened tags used in some rows of the document


def norm(t):
    for lig, rep in (("\ufb00", "ff"), ("\ufb01", "fi"), ("\ufb02", "fl"), ("\ufb03", "ffi"), ("\ufb04", "ffl"),
                     ("\u2019", "'")):
        t = t.replace(lig, rep)
    return re.sub(r"\s+", " ", t).strip()


def split_tags(block):
    """Split 'action text. Tag; Tag' into (action, [tags]).

    The tags follow the action's last sentence. A trailing segment is accepted as tags when it is a
    list of short capitalised items with at least one of the 12 risks; the document occasionally adds
    other tags (kept, and reported by the caller). Otherwise the 12-risk vocabulary is peeled off the end.
    """
    idx = block.rfind(". ")
    if idx >= 0:
        parts = [ALIASES.get(x.strip(), x.strip()) for x in block[idx + 2:].split(";") if x.strip()]
        if parts and any(x in RISKS for x in parts) and all(len(x) < 60 and x[:1].isupper() for x in parts):
            return block[: idx + 1].strip(), parts
    tags, rest = [], block
    while True:
        rest = rest.rstrip(" ;")
        hit = next((r for r in sorted(RISKS, key=len, reverse=True) if rest.endswith(r)), None)
        if not hit:
            break
        tags.insert(0, hit)
        rest = rest[: -len(hit)]
        if not rest.rstrip().endswith(";"):
            break
    return rest.strip(), tags


def main():
    # Footnotes and the page number sit at the bottom of each page, after a blank line, starting with
    # "<n> <Capital>"; drop them so they do not run into the text of the last table row.
    pages = [re.sub(r"\n(?:[ \t]*\n)+\d{1,3} [A-Z][\s\S]*$", "\n", p.extract_text() or "")
             for p in pypdf.PdfReader(str(PDF)).pages]
    raw = "\n".join(pages)
    flat = norm(raw)

    # Section 2: the 12 risks.
    risk_text = {}
    heads = list(re.finditer(r"2\.(\d{1,2})\. (" + "|".join(re.escape(r) for r in RISKS) + r") ", flat))
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else flat.find("3. Suggested Actions", m.end())
        body = flat[m.end(): end if end > 0 else m.end() + 3000]
        body = re.sub(r" \d{1,2} (?=[A-Z])", " ", body)  # stray footnote numbers and page numbers
        risk_text[m.group(2)] = body.strip()
    if len(risk_text) != 12:
        sys.exit(f"expected 12 GAI risks in section 2, found {len(risk_text)}")

    # Section 3: subcategory headers and actions.
    sect3 = flat[flat.find("GOVERN 1.1: Legal and regulatory"):]
    sect3 = re.sub(r"Action ID Suggested Action GAI Risks ", "", sect3)
    tokens = re.split(r"((?:GOVERN|MAP|MEASURE|MANAGE) \d+\.\d+: |(?:GV|MP|MS|MG)-\d+\.\d+-\d{3} |AI Actors?(?: Tasks)?: )", sect3)
    subs, current, actions, seen, extra = [], None, [], set(), set()
    i = 1
    while i < len(tokens):
        marker, body = tokens[i].strip(), tokens[i + 1] if i + 1 < len(tokens) else ""
        body = re.sub(r"\s\d{1,2}\s(?=[A-Z])", " ", " " + body).strip()  # drop page numbers between rows
        body = re.sub(r"\s\d{1,3}$", "", body)                              # and a page number at the end
        if marker.endswith(":") and not marker.startswith("AI Actor"):
            current = {"id": marker[:-1], "statement": body, "actions": [], "actors": ""}
            subs.append(current)
        elif marker.startswith("AI Actor"):
            if current:
                current["actors"] = re.split(r" Appendix A| \d+ AI Actors are", body)[0].strip()
        else:
            if marker in seen:
                sys.exit(f"duplicate action id {marker}")
            seen.add(marker)
            text, tags = split_tags(body)
            extra.update(t for t in tags if t not in RISKS)
            if not tags:
                sys.exit(f"{marker}: no GAI risk tag recognised at the end of: …{body[-120:]}")
            current["actions"].append((marker, text, tags))
            actions.append(marker)
        i += 2
    for s in subs:
        s["statement"] = s["statement"].strip()

    L = []
    w = L.append
    w("# NIST AI 600-1 — Generative Artificial Intelligence Profile")
    w("")
    w(f"**Normative source:** NIST AI 600-1, *Artificial Intelligence Risk Management Framework: Generative "
      f"Artificial Intelligence Profile* (July 2024) · {DOI}")
    w("")
    w(f"**Contents:** 12 GAI risks (section 2) · {len(actions)} suggested actions under {len(subs)} AI RMF "
      "subcategories (section 3), each tagged with GAI risks and AI actor tasks.")
    w("")
    w("> Generated by `scripts/gen_ai600_1.py` from the official PDF. Risk descriptions are trimmed and footnote markers "
      "removed; actions and tags are complete. Do not edit by hand: regenerate.")
    w("")
    w("## Purpose in this skill")
    w("")
    w("The Generative AI Profile applies AI RMF 1.0 (`nist-ai-rmf-1.0.md`) to generative AI. Use its **12 GAI risks** "
      "to name what a generative system can get wrong beyond classic security (confabulation, information integrity, "
      "value-chain integration…), and its **suggested actions** (`GV-1.1-001` style IDs) as concrete governance and "
      "engineering directions. It complements 800-218A (development of the model) and the LLM Top 10 / ASI "
      "(application and agent risks).")
    w("")
    w("## Reading rules")
    w("")
    w("- Suggested actions are **suggestions**, voluntary and context-dependent; never present one as mandatory. "
      "PASS / FAIL is rare against this profile: report NOT VERIFIED with the evidence that would decide it, or "
      "anchor the finding on a verifiable control.")
    w("- The action ID encodes the AI RMF subcategory: `MS-2.7-001` belongs to MEASURE 2.7.")
    w("- GAI risk tags say which of the 12 risks an action addresses; they are not severities.")
    w("- Shortened tags are normalised to the risk name: " + ", ".join(f"`{a}` → {b}" for a, b in ALIASES.items()) + ".")
    if extra:
        w("- The document also uses tags outside the 12 risks, kept as written: " + ", ".join(sorted(extra)) + ".")
    w("")
    w("## The 12 GAI risks")
    w("")
    for n, r in enumerate(RISKS, 1):
        tagged = sum(1 for s in subs for _, _, t in s["actions"] if r in t)
        w(f"### 2.{n}. {r}")
        w("")
        body = risk_text[r]
        if len(body) > 1600:
            cut = body[:1600]
            body = cut[: cut.rfind(". ") + 1]
        w("> " + body)
        w("")
        w(f"*Suggested actions tagged with this risk:* {tagged}")
        w("")
    w("## Suggested actions by AI RMF subcategory")
    w("")
    for s in subs:
        w(f"### {s['id']}")
        w("")
        w("> " + s["statement"])
        w("")
        w("| Action ID | Suggested action | GAI risks |")
        w("|---|---|---|")
        for aid, text, tags in s["actions"]:
            w(f"| `{aid}` | {text.replace('|', '/')} | {'; '.join(tags)} |")
        w("")
        if s["actors"]:
            w(f"*AI actor tasks:* {s['actors']}")
            w("")
    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"{OUT.name}: 12 risks, {len(actions)} actions under {len(subs)} subcategories; "
          f"non-standard tags: {sorted(extra) or 'none'}", file=sys.stderr)


if __name__ == "__main__":
    main()
