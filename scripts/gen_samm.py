#!/usr/bin/env python3
"""Generate references/standards/owasp-samm-2.0.md from the official OWASP SAMM V2.0 PDF.

The PDF layout is very regular: each page carries a 2-4 line header naming the
practice / business function / section, and a `OWASP SAMM V2.0<n>` footer. That is
enough to rebuild the 90 maturity-level cards without ambiguity.
"""
import collections, pathlib, re, sys

try:
    import pypdf
except ImportError:  # pragma: no cover
    sys.exit("requires pypdf: pip install pypdf")

SOURCE = "OWASP SAMM V2.0 (SAMM-v2-PDF.pdf, 303 pages)"
PROJECT = "https://owaspsamm.org/"
ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = ROOT.parent / "sources"
SKILL = ROOT.parent / "skills" / "security" / "cybersec-skill"
SRC = SOURCES / "SAMM-v2-PDF.pdf"
OUT = SKILL / "references" / "standards" / "owasp-samm-2.0.md"

FUNCTIONS = ["Governance", "Design", "Implementation", "Verification", "Operations"]
MARKERS = {"Benefit", "Activity", "Activity (continued)", "Quality Criteria", "Answers"}


def extract_pages():
    reader = pypdf.PdfReader(str(SRC))
    return [(p.extract_text() or "") for p in reader.pages]


def flow(lines):
    """Join hard-wrapped lines into one readable paragraph."""
    out = " ".join(l.strip() for l in lines if l.strip())
    # In this PDF a hyphen at line end belongs to a real compound
    # (custom-developed, high-severity...), not to syllable splitting: keep it.
    out = re.sub(r"(\w)-\s+(\w)", r"\1-\2", out)
    return re.sub(r"\s+", " ", out).strip()


def merge_items(lines):
    """Regroup list items whose text continues on the next line."""
    items = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        if items and (ln[:1].islower() or ln[:1] in ",;)"):
            items[-1] = items[-1] + " " + ln
        else:
            items.append(ln)
    return [re.sub(r"\s+", " ", i) for i in items]


def main():
    raw = extract_pages()
    pages = []
    for text in raw:
        lines = [l.rstrip() for l in text.strip().splitlines()]
        page_no = None
        if lines and lines[-1].startswith("OWASP SAMM V2.0"):
            m = re.search(r"(\d+)\s*$", lines[-1])
            page_no = int(m.group(1)) if m else None
            lines = lines[:-1]
        pages.append((page_no, lines))

    func_overview = {}
    practice_overview = {}      # (func, practice) -> text
    streams_overview = {}       # (func, practice) -> [(stream, text)]
    cards = collections.OrderedDict()
    page_of = {}

    for page_no, lines in pages:
        if len(lines) < 3:
            continue
        a, b = lines[0], lines[1]
        if b == "Business Function Overview" and a in FUNCTIONS:
            body = lines[2:]
            if "Security Practices Overview" in body:
                body = body[:body.index("Security Practices Overview")]
            func_overview[a] = flow(body)
            continue
        if len(lines) >= 4 and re.fullmatch(r"Maturity level [123]", lines[3]) \
                and lines[2] in FUNCTIONS and lines[1].startswith("Stream "):
            key = (lines[2], lines[0], lines[1], lines[3])
            cards.setdefault(key, []).append(lines[4:])
            page_of.setdefault(key, page_no)
            continue
        if len(lines) >= 3 and b in FUNCTIONS:
            title = lines[2]
            key = (b, a)
            if title == "Security Practice Overview":
                practice_overview[key] = flow(lines[3:])
            elif title == "Streams Overview":
                acc, cur = [], None
                for ln in lines[3:]:
                    if ln.startswith("Stream ") and " - " in ln:
                        cur = (ln, [])
                        acc.append(cur)
                    elif cur:
                        cur[1].append(ln)
                streams_overview[key] = [(s, flow(t)) for s, t in acc]

    def parse(pagelist):
        sec = collections.defaultdict(list)
        state = None
        for body in pagelist:
            if body and body[0] not in MARKERS and "Quality Criteria" in body:
                state = "question"
            for ln in body:
                if ln == "Benefit":
                    state = "benefit"; continue
                if ln in ("Activity", "Activity (continued)"):
                    state = "activity"; continue
                if ln == "Quality Criteria":
                    state = "quality"; continue
                if ln == "Answers":
                    state = "answers"; continue
                if state:
                    sec[state].append(ln)
        return sec

    practices = collections.OrderedDict()
    for (func, practice, stream, lvl) in cards:
        practices.setdefault((func, practice), [])
        if stream not in [s for s, _ in practices[(func, practice)]]:
            practices[(func, practice)].append((stream, []))
        for s, lst in practices[(func, practice)]:
            if s == stream:
                lst.append(lvl)

    L = []
    w = L.append
    w("# OWASP SAMM V2.0 — software assurance maturity model")
    w("")
    w(f"**Normative source:** {SOURCE}")
    w("")
    w(f"**Official project:** {PROJECT}")
    w("")
    w(f"**Contents:** {len(FUNCTIONS)} business functions · {len(practices)} security practices · "
      f"{len(practices) * 2} streams · {len(cards)} maturity-level cards")
    w("")
    w("> Generated by `scripts/gen_samm.py` from the official PDF. Do not edit by hand: regenerate.")
    w("")
    w("## Purpose in this skill")
    w("")
    w("SAMM is used to **classify a security practice and assess the maturity level the evidence "
      "supports**, never to score the software. It is a view of *how the organisation runs its security "
      "practices*, complementary to the technical controls of ASVS, SSDF or the LLM Top 10.")
    w("")
    w("## Hierarchy")
    w("")
    w("`Business Function -> Security Practice -> Stream A / Stream B -> Maturity level -> "
      "Activity -> Assessment Question -> Quality Criteria -> Answers`")
    w("")
    w("## Assessment rules")
    w("")
    w("1. Set the **scope**: organisation, unit, team, product, service or programme.")
    w("2. Identify the Business Function, Security Practice and Stream that describe the observed activity.")
    w("3. Assess maturity levels **in order**, using each level's official Activity, Assessment Question, "
      "Quality Criteria and Answers.")
    w("4. Gather verifiable evidence and tie it to the specific criterion it supports.")
    w("5. Record the **official answer** that matches the evidence. Do not replace SAMM's Answers with a "
      "scale of your own or invent a numeric score.")
    w("6. Report a maturity level as reached only if the evidence supports its Activity and Quality "
      "Criteria and the lower levels of the same Stream were assessed consistently.")
    w("7. V2.0 defines levels 1, 2 and 3. If the evidence does not reach level 1, the result is "
      "**BELOW LEVEL 1**. If there is not enough evidence to decide, it is **NOT VERIFIED**. "
      "Never confuse the two: missing evidence is not missing maturity.")
    w("")
    w("### Minimum output of a SAMM assessment")
    w("")
    w("```text")
    for line in ("Business Function: <...>", "Security Practice: <...>", "Stream: <A/B + name>",
                 "Assessed maturity: <Level 1 | Level 2 | Level 3 | Below Level 1 | Not verified>",
                 "Assessment answer: <selected official answer>", "Quality Criteria met: <...>",
                 "Evidence: <...>", "Gap to next level: <...>", "Target maturity: <if any>",
                 "SAMM reference: <hierarchy path + page>"):
        w(line)
    w("```")
    w("")
    w("## Index")
    w("")
    for func in FUNCTIONS:
        w(f"- **{func}**")
        for (f, practice) in practices:
            if f != func:
                continue
            streams = " · ".join(s for s, _ in practices[(f, practice)])
            w(f"  - {practice} — {streams}")
    w("")

    for func in FUNCTIONS:
        w(f"## {func}")
        w("")
        if func in func_overview:
            w(func_overview[func])
            w("")
        for (f, practice) in practices:
            if f != func:
                continue
            w(f"### {practice}")
            w("")
            if (f, practice) in practice_overview:
                w("**Security Practice Overview (official)**")
                w("")
                w(practice_overview[(f, practice)])
                w("")
            if (f, practice) in streams_overview:
                w("**Streams Overview (official)**")
                w("")
                for stream, text in streams_overview[(f, practice)]:
                    w(f"- **{stream}:** {text}")
                w("")
            for stream, levels in practices[(f, practice)]:
                w(f"#### {stream}")
                w("")
                for lvl in levels:
                    key = (f, practice, stream, lvl)
                    s = parse(cards[key])
                    pg = page_of.get(key)
                    w(f"##### {lvl}")
                    w("")
                    w(f"**Benefit:** {flow(s['benefit'])}")
                    w("")
                    w("**Activity**")
                    w("")
                    w(flow(s["activity"]))
                    w("")
                    w(f"**Assessment Question:** {flow(s['question'])}")
                    w("")
                    w("**Quality Criteria**")
                    w("")
                    for item in merge_items(s["quality"]):
                        w(f"- {item}")
                    w("")
                    w("**Answers**")
                    w("")
                    for item in merge_items(s["answers"]):
                        w(f"- {item}")
                    w("")
                    w(f"**SAMM reference:** {f} -> {practice} -> {stream} -> {lvl}"
                      + (f" (p. {pg})" if pg else ""))
                    w("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"{OUT.name}: {len(practices)} practices, {len(cards)} cards", file=sys.stderr)


if __name__ == "__main__":
    main()
