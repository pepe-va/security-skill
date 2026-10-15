#!/usr/bin/env python3
"""Generate references/standards/cisa-ztmm-2.0.md from the official CISA Zero Trust Maturity Model v2.0 PDF.

The model is a set of tables (one per pillar, plus cross-cutting capabilities) whose columns are
Function, Traditional, Initial, Advanced and Optimal. pypdf's layout extraction keeps horizontal
positions, so each table is rebuilt by slicing lines at the column starts of its header row. A row
starts when the Function column gets text after a line where it was empty; rows continue across
pages; footnotes at the bottom of a page close the table there and their markers are removed from
the cells. A hyphen at a line break is kept (the source does not say whether it is a compound).
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
PDF = SOURCES / "cisa-ztmm" / "zero_trust_maturity_model_v2_508.pdf"
OUT = SKILL / "references" / "standards" / "cisa-ztmm-2.0.md"
URL = "https://www.cisa.gov/zero-trust-maturity-model"
COLS = ["Function", "Traditional", "Initial", "Advanced", "Optimal"]
PILLARS = ["Identity", "Devices", "Networks", "Applications and Workloads", "Data"]
STOP = re.compile(r"^\s{0,3}(\d{1,3}\s+TLP:CLEAR|\d{1,2} ?[A-Z]|Zero Trust Maturity Model\s+April 2023)")
CONT_WORDS = {"Function)", "Function", "Capability", "Capabilities"}  # wrapped tails of a function name


def join(parts):
    out = ""
    for p in parts:
        p = p.strip()
        if not p:
            continue
        p = p.replace("\u00ad", "-").replace("\u2010", "-").replace("\u2011", "-")
        out = out + p if (not out or out.endswith("-")) else out + " " + p
    out = re.sub(r"(\w)-\s+(\w)", r"\1-\2", out)  # layout mode spaces out compounds: "multi- factor"
    return re.sub(r"\s+", " ", out).strip()


def main():
    reader = pypdf.PdfReader(str(PDF))
    tables, table, row = [], None, None
    for page in reader.pages:
        text = page.extract_text(extraction_mode="layout") or ""
        lines = text.splitlines()
        notes = {int(m.group(1)) for m in re.finditer(r"^\s{0,3}(\d{1,2}) ?[A-Z]", text, re.M)}
        plain = page.extract_text() or ""  # layout mode spaces out titles ("Device  s"); plain text does not
        title = next((m for m in re.finditer(r"^\s*Table \d+: ([A-Za-z ,&-]+?)(?: Pillar)?\s*$", plain, re.M)
                      if "Revision" not in m.group(1) and "...." not in m.group(0)), None)
        hidx = next((i for i, ln in enumerate(lines) if all(c in ln for c in COLS)), None)
        if hidx is None:
            table, row = None, None
            continue
        if title:
            table = {"title": title.group(1).strip(), "rows": []}
            tables.append(table)
        if table is None:
            continue
        head = lines[hidx]
        starts = [head.index(c) for c in COLS]
        prev = ""
        for ln in lines[hidx + 1:]:
            if STOP.match(ln):
                break
            if not ln.strip():
                continue
            cells = {c: [] for c in COLS}
            for m in re.finditer(r"\S+(?: \S+)*", ln):      # chunks: runs separated by 2+ spaces
                if re.fullmatch(r"[a-z]", m.group(0)):
                    continue  # stray one-letter fragments the layout leaves between columns
                ci = min(range(len(starts)), key=lambda i: abs(starts[i] - m.start()))  # nearest column start
                cells[COLS[ci]].append(m.group(0))
            func = " ".join(cells["Function"]).strip()
            # A row starts when the Function column gets text after a line where it was empty, or right
            # after a function name that is already closed with ")" (a name longer than its cells).
            starts_row = func and (not prev or (prev.endswith(")") and func[0].isupper() and func not in CONT_WORDS))
            if row is None or starts_row:
                row = {c: [] for c in COLS}
                table["rows"].append(row)
            for c in COLS:
                for v in cells[c]:
                    for n in sorted(notes, reverse=True):
                        v = re.sub(rf"(?<=[A-Za-z0-9)\].]){n}(?=[\s.,;)]|$)", "", v)
                    row[c].append(v)
            prev = func
    for t in tables:
        t["rows"] = [{c: join(r[c]) for c in COLS} for r in t["rows"] if join(r["Function"])]
    if len(tables) != 6:
        sys.exit(f"expected 6 tables (5 pillars + cross-cutting), rebuilt {len(tables)}")

    flat = re.sub(r"\s+", " ", "\n".join((p.extract_text() or "") for p in reader.pages))
    intros = {}
    for p in PILLARS:
        m = re.search(r"5\.\d+ " + re.escape(p) + r" (.+?) Table \d+ lists", flat)
        if m:
            intros[p] = re.sub(r"(?<=[a-z.])\d{1,2}(?=[\s.,;]|$)", "", m.group(1)).strip()

    n_fun = sum(len(t["rows"]) for t in tables)
    L = []
    w = L.append
    w("# CISA Zero Trust Maturity Model (ZTMM) 2.0")
    w("")
    w(f"**Official source:** {URL} · **Document:** Zero Trust Maturity Model Version 2.0 (April 2023), CISA")
    w("")
    w(f"**Contents:** {len(tables)} tables · {n_fun} functions, each described at four maturity stages "
      "(Traditional, Initial, Advanced, Optimal).")
    w("")
    w("> Generated by `scripts/gen_ztmm.py` from the official PDF; the tables are rebuilt from the page layout and their "
      "cells are verbatim (footnote markers removed). Do not edit by hand: regenerate.")
    w("")
    w("## Purpose in this skill")
    w("")
    w("ZTMM measures **how far an organisation has gone towards zero trust**, pillar by pillar (Identity, Devices, "
      "Networks, Applications and Workloads, Data) plus three cross-cutting capabilities (Visibility and Analytics, "
      "Automation and Orchestration, Governance). It is a maturity model, like SAMM, not a control set for one "
      "system: report the stage the evidence supports (`ZTMM 2.0 Identity / Authentication: Advanced`), and use "
      "`nist-800-207.md` for the architecture principles. CISA itself says the model should not be viewed as a "
      "strict set of requirements.")
    w("")
    w("## Index")
    w("")
    for t in tables:
        w(f"- **{t['title']}**: " + ", ".join(r["Function"] for r in t["rows"]))
    w("")
    for t in tables:
        w(f"## {t['title']}")
        w("")
        if t["title"] in intros:
            w("> " + intros[t["title"]])
            w("")
        for r in t["rows"]:
            w(f"### {t['title']} — {r['Function']}")
            w("")
            for c in COLS[1:]:
                w(f"- **{c}:** {r[c] or '—'}")
            w("")
    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"{OUT.name}: {len(tables)} tables, {n_fun} functions", file=sys.stderr)


if __name__ == "__main__":
    main()
