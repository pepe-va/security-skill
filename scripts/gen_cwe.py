#!/usr/bin/env python3
"""Generate the MITRE CWE references from the official XML catalogue.

Sources (fetch_sources.py, group "cwe"):
  sources/cwe/cwec_latest.xml.zip       the full catalogue
  sources/cwe/2025_cwe_top25.html       the official 2025 Top 25 page (rank, score, KEV count)

Outputs:
  references/standards/cwe/README.md          version, mapping rules, file map, CWE -> OWASP Top 10:2025 index
  references/standards/cwe/top25-2025.md      the 2025 Top 25 with consequences, mitigations and detection
  references/standards/cwe/weaknesses.md      every weakness, compact (description, usage, parents, CAPEC)

Stdlib only.
"""
import html, pathlib, re, sys, zipfile
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = ROOT.parent / "sources"
SKILL = ROOT.parent / "skills" / "security" / "cybersec-skill"
SRC = SOURCES / "cwe" / "cwec_latest.xml.zip"
TOP25 = SOURCES / "cwe" / "2025_cwe_top25.html"
STD = SKILL / "references" / "standards"
OUT = STD / "cwe"
TOP10 = STD / "owasp-top10-2025.md"
NS = {"c": "http://cwe.mitre.org/cwe-7"}
SITE = "https://cwe.mitre.org/data/definitions/{}.html"
TOP25_URL = "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"


def text(el):
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


def first_sentences(s, limit=600):
    if len(s) <= limit:
        return s
    cut = s[:limit]
    return cut[: cut.rfind(". ") + 1] if ". " in cut else cut + "…"


def load():
    z = zipfile.ZipFile(SRC)
    root = ET.fromstring(z.read(z.namelist()[0]))
    meta = root.attrib
    weak = {}
    for w in root.findall(".//c:Weakness", NS):
        wid = w.get("ID")
        parents = [r.get("CWE_ID") for r in w.findall("c:Related_Weaknesses/c:Related_Weakness", NS)
                   if r.get("Nature") == "ChildOf" and r.get("View_ID") == "1000"]
        cons = []
        for c in w.findall("c:Common_Consequences/c:Consequence", NS):
            scopes = [text(s) for s in c.findall("c:Scope", NS)]
            impacts = [text(i) for i in c.findall("c:Impact", NS)]
            cons.append((scopes, impacts, text(c.find("c:Note", NS))))
        mits = [(", ".join(text(p) for p in m.findall("c:Phase", NS)), text(m.find("c:Description", NS)),
                 text(m.find("c:Effectiveness", NS)))
                for m in w.findall("c:Potential_Mitigations/c:Mitigation", NS)]
        dets = [(text(d.find("c:Method", NS)), text(d.find("c:Description", NS)), text(d.find("c:Effectiveness", NS)))
                for d in w.findall("c:Detection_Methods/c:Detection_Method", NS)]
        capec = [r.get("CAPEC_ID") for r in w.findall("c:Related_Attack_Patterns/c:Related_Attack_Pattern", NS)]
        weak[wid] = {
            "id": wid, "name": w.get("Name"), "abstraction": w.get("Abstraction"), "status": w.get("Status"),
            "description": text(w.find("c:Description", NS)),
            "extended": text(w.find("c:Extended_Description", NS)),
            "usage": text(w.find("c:Mapping_Notes/c:Usage", NS)) or "—",
            "parents": parents, "consequences": cons, "mitigations": mits, "detection": dets, "capec": capec,
        }
    return meta, weak


def load_top25():
    t = TOP25.read_text(encoding="utf-8", errors="ignore")
    rows = []
    for tr in re.findall(r"(?s)<tr[^>]*>(.*?)</tr>", t):
        cells = [re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", c))).strip()
                 for c in re.findall(r"(?s)<t[dh][^>]*>(.*?)</t[dh]>", tr)]
        if len(cells) >= 5 and cells[0].isdigit() and cells[1].startswith("CWE-"):
            rows.append({"rank": int(cells[0]), "id": cells[1][4:], "name": cells[2], "score": cells[3],
                         "kev": cells[4], "change": cells[5] if len(cells) > 5 else ""})
    return rows


def top10_index():
    """Map CWE id -> OWASP Top 10:2025 categories whose page lists it."""
    out = {}
    if not TOP10.exists():
        return out
    cat = None
    for line in TOP10.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^## (A\d\d:2025) — (.*)", line)
        if m:
            cat = f"{m.group(1)} {m.group(2)}"
            continue
        if cat:
            for cid in re.findall(r"CWE-(\d+)", line):
                out.setdefault(cid, set()).add(cat)
    return out


def consequences_line(cons):
    parts = []
    for scopes, impacts, _ in cons:
        part = f"{'/'.join(scopes) or '—'}: {'; '.join(impacts) or '—'}"
        if part not in parts:
            parts.append(part)
    return " · ".join(parts)


def main():
    meta, weak = load()
    top25 = load_top25()
    if len(top25) != 25:
        sys.exit(f"expected 25 ranked rows in {TOP25.name}, parsed {len(top25)}")
    t10 = top10_index()
    version, date = meta["Version"], meta["Date"]
    OUT.mkdir(parents=True, exist_ok=True)
    live = [w for w in weak.values() if w["status"] != "Deprecated"]
    deprecated = [w for w in weak.values() if w["status"] == "Deprecated"]
    key = lambda w: int(w["id"])

    # README ----------------------------------------------------------------------------------
    R = []
    w = R.append
    w(f"# MITRE CWE {version} — Common Weakness Enumeration")
    w("")
    w(f"**Official source:** https://cwe.mitre.org/ · **Catalogue:** CWE {version} ({date}), "
      "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip")
    w("")
    w(f"**Contents:** {len(weak)} weaknesses ({len(live)} active, {len(deprecated)} deprecated) · 2025 CWE Top 25.")
    w("")
    w("> Generated by `scripts/gen_cwe.py` from the official XML. Do not edit by hand: regenerate.")
    w("")
    w("## Purpose in this skill")
    w("")
    w("CWE is the **common language of findings**. Every finding carries the CWE of its root cause; from the CWE "
      "the skill reaches the OWASP Top 10:2025 category (index below), the ASVS requirements of the matching "
      "chapter, and the CAPEC attack patterns the weakness enables. CWE classifies a weakness; it is not a "
      "compliance criterion and carries no severity — severity comes from the demonstrated impact and CVSS 4.0.")
    w("")
    w("## Mapping rules (from CWE's own Mapping Notes)")
    w("")
    w("- Prefer the **Base** or **Variant** entry that names the root cause. **Class** and **Pillar** entries are "
      "too abstract for a finding unless nothing lower fits.")
    w("- Respect each entry's **Usage**: `Allowed` — map freely · `Allowed-with-Review` — map only after checking "
      "the description fits · `Discouraged` — find a lower-level entry · `Prohibited` — never map (categories and "
      "views are always prohibited).")
    w("- Read the name **and** the description before mapping. Do not force a Base/Variant entry that does not fit; "
      "a correct Class is better than a wrong Base.")
    w("- Cite as `CWE-<id>` with the catalogue version (`CWE 4.20`). Deprecated entries must not be cited.")
    w("")
    w("## Files")
    w("")
    w("| File | Contents |")
    w("|---|---|")
    w("| `top25-2025.md` | The 2025 Top 25 with rank, score, KEV count, consequences, mitigations and detection |")
    w(f"| `weaknesses.md` | All {len(live)} active weaknesses, compact; search for `### CWE-<id>:` |")
    w("")
    w("## CWE → OWASP Top 10:2025 index")
    w("")
    w("Derived from the CWE lists on each category page of `../owasp-top10-2025.md`. A CWE absent here is not "
      "listed by any Top 10:2025 category.")
    w("")
    w("| CWE | Name | Top 10:2025 category |")
    w("|---|---|---|")
    for cid in sorted(t10, key=int):
        name = weak.get(cid, {}).get("name", "(not in catalogue)")
        w(f"| CWE-{cid} | {name} | {' · '.join(sorted(t10[cid]))} |")
    w("")
    (OUT / "README.md").write_text("\n".join(R) + "\n", encoding="utf-8")

    # Top 25 ----------------------------------------------------------------------------------
    T = []
    w = T.append
    w("# 2025 CWE Top 25 Most Dangerous Software Weaknesses")
    w("")
    w(f"**Official source:** {TOP25_URL} · **Entry details:** CWE {version}")
    w("")
    w("> Generated by `scripts/gen_cwe.py`. Rank, score and KEV count come from the official Top 25 page; the entry "
      "details come from the CWE catalogue. Rank is a prevalence-and-severity ranking of CVE data, not the severity "
      "of a specific finding.")
    w("")
    w("| Rank | CWE | Name | Score | CVEs in KEV | Change vs 2024 | Top 10:2025 |")
    w("|---:|---|---|---:|---:|---|---|")
    for r in top25:
        w(f"| {r['rank']} | CWE-{r['id']} | {r['name']} | {r['score']} | {r['kev']} | {r['change']} | "
          f"{' · '.join(sorted(c.split(' ')[0] for c in t10.get(r['id'], []))) or '—'} |")
    w("")
    for r in top25:
        e = weak.get(r["id"])
        if not e:
            continue
        w(f"## {r['rank']}. CWE-{e['id']}: {e['name']}")
        w("")
        w(f"**Abstraction:** {e['abstraction']} · **Status:** {e['status']} · **Mapping usage:** {e['usage']} · "
          f"{SITE.format(e['id'])}")
        w("")
        w("> " + e["description"])
        if e["extended"]:
            w(">")
            w("> " + first_sentences(e["extended"], 900))
        w("")
        if e["consequences"]:
            w("**Common consequences:** " + consequences_line(e["consequences"]))
            w("")
        if e["mitigations"]:
            w("**Potential mitigations**")
            w("")
            for phase, desc, eff in e["mitigations"]:
                w(f"- *{phase or 'Any phase'}* — {desc}" + (f" (effectiveness: {eff})" if eff else ""))
            w("")
        if e["detection"]:
            w("**Detection methods**")
            w("")
            for method, desc, eff in e["detection"]:
                w(f"- *{method}* — {first_sentences(desc, 400)}" + (f" (effectiveness: {eff})" if eff else ""))
            w("")
        if e["capec"]:
            w("**Related CAPEC:** " + ", ".join(f"CAPEC-{c}" for c in e["capec"]))
            w("")
    (OUT / "top25-2025.md").write_text("\n".join(T) + "\n", encoding="utf-8")

    # Catalogue -------------------------------------------------------------------------------
    C = []
    w = C.append
    w(f"# CWE {version} — weakness catalogue (compact)")
    w("")
    w(f"> Generated by `scripts/gen_cwe.py` from CWE {version} ({date}). Each entry keeps the official name, "
      "description, abstraction, status, mapping usage, parents in the Research Concepts view (CWE-1000), "
      "consequences and related CAPEC. Full text, examples and mitigations: follow the link, or "
      "`top25-2025.md` for the Top 25. Do not edit by hand: regenerate.")
    w("")
    for e in sorted(live, key=key):
        w(f"### CWE-{e['id']}: {e['name']}")
        w("")
        bits = [f"**{e['abstraction']}**", e["status"], f"usage: {e['usage']}"]
        if e["parents"]:
            bits.append("child of " + ", ".join(f"CWE-{p}" for p in e["parents"]))
        if e["id"] in t10:
            bits.append(" · ".join(sorted(c.split(" ")[0] for c in t10[e["id"]])))
        w(" · ".join(bits))
        w("")
        w(first_sentences(e["description"]))
        w("")
        if e["consequences"]:
            w("*Consequences:* " + consequences_line(e["consequences"]))
            w("")
        if e["capec"]:
            w("*CAPEC:* " + ", ".join(e["capec"]))
            w("")
    w("## Deprecated entries (do not cite)")
    w("")
    w(", ".join(f"CWE-{e['id']}" for e in sorted(deprecated, key=key)))
    w("")
    (OUT / "weaknesses.md").write_text("\n".join(C) + "\n", encoding="utf-8")
    print(f"cwe/: CWE {version} — {len(live)} active weaknesses, Top 25 2025, "
          f"{len(t10)} CWE mapped to Top 10:2025", file=sys.stderr)


if __name__ == "__main__":
    main()
