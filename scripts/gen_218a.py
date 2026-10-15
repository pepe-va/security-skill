#!/usr/bin/env python3
"""Generate references/standards/nist-800-218a.md and verify it against the official PDF.

Table 1 of SP 800-218A is a five-column table whose cells interleave when a PDF is read as
text, so it is kept as a hand transcription (sources/ssdf/nist-800-218a-table1.transcription.md,
inherited from systema-cure). This generator renders that transcription and proves it against
the PDF instead of trusting it:

  - every task identifier of the transcription appears in the PDF;
  - every quoted text (practice, task, R/C/N item) is matched by word 5-grams against the PDF
    text; a unit whose coverage falls below THRESHOLD fails the run.

Interleaving, page breaks and footnote markers break a few 5-grams at cell borders. A unit
below THRESHOLD gets a second, stricter test: its words must appear in the PDF in the same
order, allowing gaps of up to GAP tokens between consecutive words (the gap absorbs a repeated
table header or a neighbouring column), with at least ORDERED of its words matched.

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
PDF = SOURCES / "ssdf" / "NIST.SP.800-218A.pdf"
TRANSCRIPTION = SOURCES / "ssdf" / "nist-800-218a-table1.transcription.md"
OUT = SKILL / "references" / "standards" / "nist-800-218a.md"
DOI = "https://doi.org/10.6028/NIST.SP.800-218A"
THRESHOLD = 0.85
ORDERED = 0.97
GAP = 120


def words(text):
    text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    text = text.replace("—", " ").replace("–", " ")
    return re.findall(r"[a-z0-9]+", text.lower())


def grams(tokens, n=5):
    return {tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def ordered_coverage(unit, pdf_tokens, positions):
    """Best fraction of unit words found in order in the PDF token stream, allowing gaps."""
    best = 0.0
    for start in positions.get(unit[0], []):
        i, matched = start, 1
        for tok in unit[1:]:
            nxt = next((j for j in positions.get(tok, []) if i < j <= i + GAP), None)
            if nxt is not None:
                i, matched = nxt, matched + 1
        best = max(best, matched / len(unit))
        if best == 1.0:
            break
    return best


def units(md):
    """Yield (label, text) for every quoted normative text in the transcription."""
    label = None
    for line in md.splitlines():
        m = re.match(r"^#{3,4} ((?:PO|PS|PW|RV)\.\d+(?:\.\d+)?)", line)
        if m:
            label = m.group(1)
            continue
        if line.startswith("> ") and label and not line.startswith("> **Note"):
            yield label, line[2:]
        m = re.match(r"^- \*\*([RCN]\d+):\*\* (.*)", line)
        if m and label:
            yield f"{label}.{m.group(1)}", m.group(2)


def verify(md):
    pdf_text = "\n".join((p.extract_text() or "") for p in pypdf.PdfReader(str(PDF)).pages)
    pdf_tokens = words(pdf_text)
    pdf_grams = grams(pdf_tokens)
    positions = {}
    for i, tok in enumerate(pdf_tokens):
        positions.setdefault(tok, []).append(i)
    tasks = re.findall(r"^#### ((?:PO|PS|PW|RV)\.\d+\.\d+) · priority \*\*(High|Medium|Low)\*\*", md, re.M)
    missing_ids = [t for t, _ in tasks if not re.search(re.escape(t) + r"\s*:", pdf_text)]
    weak = []
    checked = 0
    for label, text in units(md):
        g = grams(words(text))
        if len(g) < 2:
            continue
        checked += 1
        cov = len(g & pdf_grams) / len(g)
        if cov < THRESHOLD:
            seq = ordered_coverage(words(text), pdf_tokens, positions)
            if seq < ORDERED:
                weak.append((label, round(cov, 2), round(seq, 2), text[:90]))
    return tasks, missing_ids, weak, checked


def main():
    md = TRANSCRIPTION.read_text(encoding="utf-8")
    md = re.sub(r"\A<!--.*?-->\s*", "", md, flags=re.S)
    tasks, missing_ids, weak, checked = verify(md)
    if len(tasks) != 48 or missing_ids or weak:
        print(f"tasks found: {len(tasks)} (expected 48)", file=sys.stderr)
        for t in missing_ids:
            print(f"task id not in PDF: {t}", file=sys.stderr)
        for label, cov, seq, text in weak:
            print(f"low PDF coverage (5-gram {cov}, ordered {seq}): {label}: {text}", file=sys.stderr)
        sys.exit("verification against the PDF failed; fix the transcription")

    practices = re.findall(r"^### ((?:PO|PS|PW|RV)\.\d+) — ", md, re.M)
    prio = {p: sum(1 for _, x in tasks if x == p) for p in ("High", "Medium", "Low")}
    index = {}
    for t, _ in tasks:
        index.setdefault(t.rsplit(".", 1)[0], []).append(t)
    groups = [("PO", "Prepare the Organization"), ("PS", "Protect Software"),
              ("PW", "Produce Well-Secured Software"), ("RV", "Respond to Vulnerabilities")]

    L = []
    w = L.append
    w("# NIST SP 800-218A — secure development practices for generative AI and dual-use foundation models")
    w("")
    w("**Normative source:** NIST SP 800-218A, *Secure Software Development Practices for Generative AI and "
      "Dual-Use Foundation Models: An SSDF Community Profile* (July 2024).")
    w("")
    w(f"**Official source:** {DOI} · PDF: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf")
    w("")
    w(f"**Contents:** complete Table 1 — 4 groups, {len(practices)} practices, {len(tasks)} tasks "
      f"(priority High {prio['High']} · Medium {prio['Medium']} · Low {prio['Low']}).")
    w("")
    w(f"> Generated by `scripts/gen_218a.py` from a hand transcription of Table 1, verified against the official PDF: "
      f"{len(tasks)}/{len(tasks)} task identifiers found and {checked} quoted texts matched (word 5-gram coverage "
      f"≥{int(THRESHOLD * 100)}%, or ≥{int(ORDERED * 100)}% of words in order where table layout splits a cell). "
      "Do not edit by hand: fix the transcription and regenerate.")
    w("")
    w("## Reading rules")
    w("")
    w("- This profile **extends SSDF 1.1** and is not designed to be used on its own. Always read the base task in "
      "`nist-ssdf-800-218.md` together with its extension here.")
    w("- **Scope:** AI model development — data sourcing, design, training, fine-tuning, evaluation, and "
      "incorporating or integrating models into other software. Deployment and operation of AI systems, and most "
      "of the data governance and management life cycle, are **out of scope**.")
    w("- Practices and tasks are those of SSDF 1.1 unless the table labels them **[Modified from SSDF 1.1]** or "
      "**[Not part of SSDF 1.1]**.")
    w("- **Priority** is a suggested relative priority *for this profile*, not a vulnerability severity:")
    w("  - **High** — critically important for the security of AI model development compared with other tasks.")
    w("  - **Medium** — directly supports the security of AI model development.")
    w("  - **Low** — beneficial, but generally no more important than most other tasks.")
    w("- **R** = Recommendation (what NIST recommends doing) · **C** = Consideration (something to consider) · "
      "**N** = Note (additional information). The identifier is appended to the task: `PO.1.2.R1`.")
    w("- `No additions to SSDF 1.1` means the profile adds nothing AI-specific to that task: apply the SSDF 1.1 "
      "guidance.")
    w("- This version has **no Implementation Examples column**. The SSDF 1.1 examples still apply in general. "
      "Never invent examples attributed to 800-218A.")
    w("- Applicability stays **risk- and context-based**: a priority does not make a task mandatory.")
    w("")
    w("**Informative reference legend:** `AI RMF` = NIST AI Risk Management Framework 1.0 · `OWASP` = OWASP Top 10 "
      "for LLM Applications v1.1 (identifiers as they appear in the table) · `Adv ML` = NIST, *Adversarial Machine "
      "Learning: A Taxonomy and Terminology of Attacks and Mitigations*.")
    w("")
    w("## Index")
    w("")
    for gid, gname in groups:
        items = []
        for p in practices:
            if not p.startswith(gid):
                continue
            ts = index.get(p, [])
            nums = [t.split(".", 1)[1] for t in ts]
            consecutive = all(int(b.rsplit(".", 1)[1]) - int(a.rsplit(".", 1)[1]) == 1 for a, b in zip(nums, nums[1:]))
            rng = (f"{ts[0]}-{nums[-1]}" if len(ts) > 1 and consecutive else ", ".join(ts)) if ts else "—"
            items.append(f"{p} ({rng})")
        w(f"- **{gname} ({gid})** — " + " · ".join(items))
    w("")
    w(md.strip())
    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"{OUT.name}: {len(practices)} practices, {len(tasks)} tasks, {checked} texts verified against the PDF",
          file=sys.stderr)


if __name__ == "__main__":
    main()
