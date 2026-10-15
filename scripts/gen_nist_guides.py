#!/usr/bin/env python3
"""Generate the references of six NIST guidance publications from their official PDFs.

  NIST SP 800-190  Application Container Security Guide
  NIST SP 800-207  Zero Trust Architecture
  NIST SP 800-61r3 Incident Response Recommendations and Considerations for Cyber Risk Management
  NIST SP 800-86   Guide to Integrating Forensic Techniques into Incident Response
  NIST SP 800-115  Technical Guide to Information Security Testing and Assessment
  NIST SP 800-40r4 Guide to Enterprise Patch Management Planning

These are prose guides, not requirement catalogues. Each output keeps the section outline and turns
the guide's explicit recommendations into numbered, citable items:

  - 800-61r3: its CSF 2.0 Community Profile tables, rebuilt from the page layout, give per CSF
    element a priority and R (recommendation), C (consideration) and N (note) items.
  - the other five: every sentence with "should", "shall" or "recommend(s/ed)" in the body, with the
    bullets that complete a sentence ending in ":"; numbered R1..Rn with their section.
  - 800-207 additionally keeps the seven tenets of zero trust (section 2.1) verbatim.

PASS / FAIL may be issued only against these items; the rest of each guide is context to read in the
PDF. Requires pypdf.
"""
import collections, pathlib, re, sys

try:
    import pypdf
except ImportError:  # pragma: no cover
    sys.exit("requires pypdf: pip install pypdf")

ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = ROOT.parent / "sources"
SKILL = ROOT.parent / "skills" / "security" / "cybersec-skill"
SRC = SOURCES / "nist-guides"
STD = SKILL / "references" / "standards"

GUIDES = {
    "NIST.SP.800-190.pdf": ("nist-800-190.md", "NIST SP 800-190", "Application Container Security Guide", "September 2017",
        "Use it for container images, registries, orchestrators (Kubernetes), container runtimes and host OSs: section 3 "
        "names the risks and section 4 the countermeasures. Pairs with Kubernetes Pod Security Standards and CIS "
        "Benchmarks (tier B) and with ATT&CK Containers techniques."),
    "NIST.SP.800-207.pdf": ("nist-800-207.md", "NIST SP 800-207", "Zero Trust Architecture", "August 2020",
        "Use it for the principles of a zero trust architecture: the seven tenets, the logical components (policy "
        "engine, administrator, enforcement point) and deployment models. CISA ZTMM 2.0 measures maturity against "
        "these principles."),
    "NIST.SP.800-61r3.pdf": ("nist-800-61r3.md", "NIST SP 800-61r3", "Incident Response Recommendations and "
        "Considerations for Cyber Risk Management: A CSF 2.0 Community Profile", "April 2025",
        "Use it for incident response capability: it is a CSF 2.0 Community Profile, so each CSF element carries a "
        "priority for incident response and R/C/N items. Pairs with `nist-csf-2.0.md` and with the incident-response "
        "playbooks."),
    "NIST.SP.800-86.pdf": ("nist-800-86.md", "NIST SP 800-86", "Guide to Integrating Forensic Techniques into "
        "Incident Response", "August 2006",
        "Use it for evidence handling and forensic process (collection, examination, analysis, reporting) of files, "
        "operating systems, network traffic and applications. Pairs with the digital-forensics playbooks."),
    "NIST.SP.800-115.pdf": ("nist-800-115.md", "NIST SP 800-115", "Technical Guide to Information Security Testing "
        "and Assessment", "September 2008",
        "Use it to plan and scope security testing (review, target identification, vulnerability validation, "
        "post-testing). The audit mode of this skill is a source-first, sandboxed subset of this activity."),
    "NIST.SP.800-40r4.pdf": ("nist-800-40r4.md", "NIST SP 800-40r4", "Guide to Enterprise Patch Management "
        "Planning: Preventive Maintenance for Technology", "April 2022",
        "Use it for patch and vulnerability-remediation programmes: maintenance plans, risk responses (accept, "
        "mitigate, transfer, avoid) and metrics. Pairs with SSDF RV.1-RV.2, mode 3 (dependencies) and CISA KEV."),
}
KEYWORDS = re.compile(r"\b(should|shall|recommends?|recommended)\b", re.I)
# A figure or table caption that the PDF text flow glued to the start of the next sentence.
CAPTION = re.compile(r"^(?:Figure|Table) [\d.-]+: .*?(?=\b[A-Z][a-z]+ (?:should|shall|must|recommends?)\b)")
HEADING = re.compile(r"^(\d{1,2}(?:\.\d{1,2}){0,3})\.?\s+([A-Z][A-Za-z0-9 ,:;()/&'’\-]{2,95})$")
STOP_TITLES = re.compile(r"^(References|Appendix|Acronyms|Glossary|Bibliography)", re.I)


def norm(t):
    for a, b in (("ﬀ", "ff"), ("ﬁ", "fi"), ("ﬂ", "fl"), ("ﬃ", "ffi"), ("ﬄ", "ffl"),
                 ("’", "'"), ("“", '"'), ("”", '"'), ("–", "-"), ("—", " - ")):
        t = t.replace(a, b)
    return t


def page_lines(reader):
    pages = [norm(p.extract_text() or "").splitlines() for p in reader.pages]
    key = lambda ln: re.sub(r"\d+", "#", ln.strip())
    counts = collections.Counter(k for lines in pages for k in {key(ln) for ln in lines if ln.strip()})
    common = {k for k, n in counts.items() if n >= max(3, len(pages) * 0.3)}
    out = []
    for i, lines in enumerate(pages):
        keep = [ln.rstrip() for ln in lines if ln.strip() and key(ln) not in common
                and "doi.org/10.6028" not in ln and not re.fullmatch(r"\s*(\d+|[ivx]+|ES-\d+|\d+-\d+)\s*", ln)]
        out.append(keep)
    return out


def dehyphenate(lines, vocabulary):
    text = ""
    for ln in lines:
        ln = ln.strip()
        if text.endswith("-") and ln[:1].islower():
            head = re.search(r"(\w+)-$", text)
            tail = re.match(r"(\w+)", ln)
            if head and tail and (head.group(1) + tail.group(1)).lower() in vocabulary:
                text = text[:-1] + ln
                continue
            text += ln
        else:
            text += ("\n" if ln[:1] in "•▪-●" or not text else " ") + ln
    return text


def toc_entries(pages, toc):
    """(number, title) pairs from the table of contents pages; titles may wrap over lines."""
    entries, cur = [], None
    for i in sorted(toc):
        for ln in pages[i]:
            s = ln.strip()
            m = re.match(r"^(\d{1,2}(?:\.\d{1,2}){0,3})\.?\s+(.*)$", s)
            if m and not re.match(r"^\d+\.\d+\s*$", s):
                cur = [m.group(1), m.group(2)]
                entries.append(cur)
            elif cur is not None and not s.startswith(("Appendix", "List of", "Figure", "Table", "Fig.")):
                cur[1] += " " + s
            if cur is not None and re.search(r"\.{4,}\s*[\dA-Z]+(?:-\d+)?\s*$", cur[1]):
                cur[1] = re.sub(r"\s*\.{4,}.*$", "", cur[1]).strip()
                cur = None
    return {num: title for num, title in entries}


def _key(t):
    return re.sub(r"[^a-z0-9]", "", t.lower())[:22]


def generic(reader):
    pages = page_lines(reader)
    vocab = set(w.lower() for lines in pages for ln in lines for w in re.findall(r"[A-Za-z]{4,}", ln))
    toc = {i for i, lines in enumerate(pages) if sum("...." in ln for ln in lines) >= 3}
    outline = toc_entries(pages, toc)
    sections, body, current, started = [], collections.OrderedDict(), None, False
    for i, lines in enumerate(pages):
        if i in toc:
            continue
        for ln in lines:
            s = ln.strip()
            if not started and re.match(r"^Executive Summary\s*$", s):
                current, started = ("ES", "Executive Summary"), True
                sections.append(current)
                body[current] = []
                continue
            m = HEADING.match(s)
            if m and "...." not in s:
                num, title = m.group(1), m.group(2).strip()
                if STOP_TITLES.match(title) and started:
                    return sections, body, vocab
                official = outline.get(num)
                if official and _key(title) and _key(official).startswith(_key(title)[:15]) \
                        and not any(n == num for n, _ in sections):
                    current, started = (num, official), True
                    sections.append(current)
                    body[current] = []
                    continue
            if started and current:
                body[current].append(ln)
    return sections, body, vocab


def recommendations(text):
    units = [u.strip() for u in re.split(r"\n", text) if u.strip()]
    out, pending = [], None
    for u in units:
        bullet = u[:1] in "•▪●-"
        if bullet and pending is not None:
            pending[1].append(u.lstrip("•▪●- ").strip())
            continue
        pending = None
        for s in re.split(r"(?<=[.!?])\s+(?=[A-Z(\"])", u.lstrip("•▪●- ")):
            s = CAPTION.sub("", s)
            if KEYWORDS.search(s) and len(s) > 25:
                item = [s.strip(), []]
                out.append(item)
                if s.rstrip().endswith(":"):
                    pending = item
    return out


def profile_tables(reader):
    """800-61r3: rebuild the CSF Community Profile rows (element, priority, R/C/N items) from the layout."""
    rows, current = [], None
    head_cols = ["CSF Element", "CSF Element Description", "Priority", "Recommendations, Considerations, Notes"]
    for page in reader.pages:
        lines = norm(page.extract_text(extraction_mode="layout") or "").splitlines()
        hidx = next((i for i, ln in enumerate(lines) if "CSF Element Description" in ln and "Priority" in ln), None)
        if hidx is None:
            continue
        head = lines[hidx]
        starts = [head.index(c) for c in head_cols]
        for ln in lines[hidx + 1:]:
            if re.match(r"^\s*NIST SP 800-61r3", ln):
                break
            cells = ["", "", "", ""]
            for m in re.finditer(r"\S+(?: \S+)*", ln):
                ci = min(range(4), key=lambda i: abs(starts[i] - m.start()))
                cells[ci] += " " + m.group(0)
            elem = cells[0].strip()
            em = re.match(r"^((?:GV|ID|PR|DE|RS|RC)(?:\.[A-Z]{2}(?:-\d\d)?)?)\b", elem)
            if em:
                current = {"id": em.group(1), "priority": "", "text": ""}
                rows.append(current)
            if current is None:
                continue
            if cells[2].strip() in ("High", "Medium", "Low"):
                current["priority"] = cells[2].strip()
            current["text"] += " " + cells[3]
    for r in rows:
        t = re.sub(r"\s+", " ", r["text"]).strip()
        t = re.sub(r"(\w)- (\w)", r"\1-\2", t)
        r["items"] = [(m.group(1), m.group(2).strip()) for m in re.finditer(r"\b([RCN]\d+): (.+?)(?= [RCN]\d+: |$)", t)]
    return rows


def tenets(reader):
    """The seven tenets of 800-207 §2.1: first sentence (the tenet) and its explanation, in order."""
    flat = re.sub(r"\s+", " ", norm("\n".join(p.extract_text() or "" for p in reader.pages)))
    hits = [m.start() for m in re.finditer(r"2\.1 Tenets of Zero Trust(?! ?\.)", flat)]
    if not hits:
        return []
    seg = flat[hits[-1]: flat.find("2.2 A Zero Trust View", hits[-1])]
    pos, out = [], []
    cursor = 0
    for n in range(1, 8):
        k = seg.find(f" {n}. ", cursor)
        if k < 0:
            return []
        pos.append(k)
        cursor = k + 3
    pos.append(len(seg))
    for n in range(7):
        item = seg[pos[n] + 4: pos[n + 1]].strip()
        out.append(item)
    return out


def main():
    for pdf_name, (out_name, code, title, date, purpose) in GUIDES.items():
        reader = pypdf.PdfReader(str(SRC / pdf_name))
        doi = "https://doi.org/10.6028/" + pdf_name[:-4]
        L = [f"# {code} — {title}", "",
             f"**Official source:** {doi} ({date}, {len(reader.pages)} pages)", ""]
        if "800-61r3" in code:
            rows = profile_tables(reader)
            items = sum(len(r["items"]) for r in rows)
            L += [f"**Contents:** CSF 2.0 Community Profile — {len(rows)} CSF elements with an incident-response priority, "
                  f"{items} R/C/N items.", "",
                  "> Generated by `scripts/gen_nist_guides.py` from the official PDF; the profile tables are rebuilt from "
                  "the page layout and the items are verbatim. CSF element descriptions are in `nist-csf-2.0.md`. Do "
                  "not edit by hand: regenerate.", "",
                  "## Purpose in this skill", "", purpose, "",
                  "## Reading rules", "",
                  "- **Priority** (High, Medium, Low) is the element's priority *for incident response*, not a severity.",
                  "- **R** = recommendation, **C** = consideration, **N** = note. Cite as `800-61r3 RS.MA-01 R2`. PASS / "
                  "FAIL is issued against R items only; C and N inform.",
                  "- An element without items relies on the CSF 2.0 outcome alone.", "",
                  "## Profile", "",
                  "| CSF element | Priority | Recommendations, considerations, notes |", "|---|---|---|"]
            for r in rows:
                cell = "<br>".join(f"**{k}:** {v}" for k, v in r["items"]) or "—"
                L.append(f"| {r['id']} | {r['priority'] or '—'} | {cell.replace('|', '/')} |")
            L.append("")
            summary = f"{len(rows)} elements, {items} items"
        else:
            sections, body, vocab = generic(reader)
            L += ["**Contents:** section outline and the guide's explicit recommendations as numbered items.", "",
                  "> Generated by `scripts/gen_nist_guides.py` from the official PDF. Items are the sentences of the body "
                  "that contain *should*, *shall* or *recommend*, verbatim, with the bullets that complete a sentence "
                  "ending in a colon. Do not edit by hand: regenerate.", "",
                  "## Purpose in this skill", "", purpose, "",
                  "## Reading rules", "",
                  f"- Cite an item as `{code.replace('NIST SP ', '')} §<section> R<n>`. PASS / FAIL is issued against these "
                  "items only; the rest of the guide is context to read in the PDF.",
                  "- *Should* is a recommendation in NIST guidance, not a mandate. Report a missing recommendation as "
                  "FAIL only when the context makes it applicable, and say why.", ""]
            if "800-207" in code:
                ts = tenets(reader)
                if len(ts) != 7:
                    sys.exit("800-207: expected 7 tenets in section 2.1")
                L += ["## Tenets of zero trust (§2.1, verbatim)", ""]
                for i, t in enumerate(ts, 1):
                    head, _, rest = t.partition(". ")
                    L.append(f"{i}. **{head}.** {rest}".rstrip())
                L.append("")
            L += ["## Outline", ""]
            for num, t in sections:
                depth = 0 if num == "ES" else num.count(".")
                L.append("  " * depth + f"- {num} {t}")
            L += ["", "## Recommendations", ""]
            n = 0
            for key in sections:
                recs = recommendations(dehyphenate(body[key], vocab))
                if not recs:
                    continue
                L += [f"### {key[0]} {key[1]}", ""]
                for sentence, bullets in recs:
                    n += 1
                    L.append(f"- **R{n}** — {sentence}")
                    L += [f"  - {b}" for b in bullets]
                L.append("")
            summary = f"{len(sections)} sections, {n} recommendation items"
        (STD / out_name).write_text("\n".join(L) + "\n", encoding="utf-8")
        print(f"{out_name}: {summary}", file=sys.stderr)


if __name__ == "__main__":
    main()
