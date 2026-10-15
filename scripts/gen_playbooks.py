#!/usr/bin/env python3
"""Index the Anthropic-Cybersecurity-Skills playbooks, copy the defensive ones, and verify their IDs.

Source: ../../Anthropic-Cybersecurity-Skills/skills/*/ (Apache-2.0). For every playbook the frontmatter
gives the subdomain and the framework mappings (mitre_attack, nist_csf, atlas_techniques,
d3fend_techniques, nist_ai_rmf, mitre_f3).

Outputs under references/playbooks/:
  README.md               what a playbook is, how to search, counts, licence, exclusions
  index-by-domain.md      every playbook by (normalised) subdomain, with a one-line purpose
  index-attack.md         ATT&CK technique -> playbooks
  index-csf.md            CSF 2.0 subcategory -> playbooks
  index-d3fend.md         D3FEND technique -> playbooks
  index-ai-and-fraud.md   ATLAS, AI RMF and F3 identifiers -> playbooks
  id-verification.md      playbook identifiers that do not resolve in the versions this skill incorporates
  <name>/playbook.md      copy of SKILL.md (renamed so no loader mistakes it for a separate skill)
  <name>/references/*.md  copies of the playbook's reference files; scripts/ is never copied
  LICENSE                 Apache-2.0 text of the source repository

Playbooks whose original subdomain is offensive (red-teaming, red-team, offensive-security) are indexed
but not copied: this skill is defensive. Stdlib only.

Without the repository cloned at the repository root, the generator rebuilds the indexes and the identifier check from
sources/playbooks-catalogue.json (written by every run that has the repository) and leaves the copied
playbooks untouched. Refreshing the copies needs a clone of the repository at the recorded revision.
"""
import collections, json, pathlib, re, shutil, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = ROOT.parent / "sources"
SKILL = ROOT.parent / "skills" / "security" / "cybersec-skill"
STD = SKILL / "references" / "standards"
OUT = SKILL / "references" / "playbooks"
REPO = ROOT.parent / "Anthropic-Cybersecurity-Skills"
SRC = REPO / "skills"
CATALOGUE = SOURCES / "playbooks-catalogue.json"
UPSTREAM = "https://github.com/mukul975/Anthropic-Cybersecurity-Skills"
NOT_COPIED = {"red-teaming", "red-team", "offensive-security"}
SUBDOMAIN = {
    "red-team": "red-teaming", "offensive-security": "penetration-testing",
    "identity-and-access-management": "identity-access-management", "identity-security": "identity-access-management",
    "zero-trust": "zero-trust-architecture", "ot-security": "ot-ics-security",
    "firmware-security": "hardware-firmware-security", "firmware-analysis": "hardware-firmware-security",
    "governance-risk-compliance": "compliance-governance", "security-operations": "soc-operations",
    "application-security": "web-application-security",
}


def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---", text, re.S)
    return m.group(1) if m else ""


def listing(fm, key):
    m = re.search(rf"^{key}:\n((?:[ \t-].*\n?)+)", fm + "\n", re.M)
    return [v.strip().strip("'\"") for v in re.findall(r"^\s*-\s*(.+)$", m.group(1), re.M)] if m else []


def scalar(fm, key):
    m = re.search(rf"^{key}:\s*(.*)$", fm, re.M)
    if not m:
        return ""
    v = m.group(1).strip()
    if v in ("", ">", "|", ">-", "|-", "'", '"'):  # folded or quoted multi-line value
        block = re.search(rf"^{key}:.*\n((?:[ \t]+.*\n?)+)", fm + "\n", re.M)
        v = " ".join(x.strip() for x in block.group(1).splitlines()) if block else ""
    return v.strip().strip("'\"").strip()


def one_line(desc, n=180):
    desc = re.sub(r"\s+", " ", desc)
    first = re.split(r"(?<=[.!?])\s", desc, maxsplit=1)[0]
    return first if len(first) <= n else first[: n - 1] + "…"


def valid_sets():
    sys.path.insert(0, str(ROOT))
    import gen_attack  # noqa: E402  (same folder)
    attack_live, attack_revoked = set(), {}
    for dom in ("enterprise", "mobile", "ics"):
        d = gen_attack.load(dom)
        attack_live |= {gen_attack.ext_id(t) for t in d["techs"].values()}
        attack_revoked.update(d["revoked"])
    csf = json.loads((SOURCES / "csf" / "csf-2.0.0.json").read_text())["response"]["elements"]
    els = {e["element_identifier"]: e for e in csf["elements"]}
    csf_withdrawn = {e: els[f"WR-{e}"]["text"] for e in els if f"WR-{e}" in els}
    csf_live = {e for e, x in els.items() if x["element_type"] in ("function", "category", "subcategory")} - set(csf_withdrawn)
    atlas = set(re.findall(r"^#{3,4} (AML\.[TM]\d{4}(?:\.\d{3})?) ", (STD / "mitre-atlas.md").read_text(), re.M))
    d3 = {m.group(2).strip().lower(): m.group(1) for m in
          re.finditer(r"^### (D3-[A-Z0-9]+) — (.+)$", (STD / "mitre-d3fend.md").read_text(), re.M)}
    rmf_text = (STD / "nist-ai-rmf-1.0.md").read_text()
    rmf = set(re.findall(r"^#### ((?:GOVERN|MAP|MEASURE|MANAGE) \d+\.\d+)$", rmf_text, re.M)) | \
        set(re.findall(r"^### ((?:GOVERN|MAP|MEASURE|MANAGE) \d+) — ", rmf_text, re.M))
    f3 = set(re.findall(r"^#{3,4} ([FT]\d{4}(?:\.\d{3})?) — ", (STD / "mitre-f3-1.2.md").read_text(), re.M))
    return attack_live, attack_revoked, csf_live, csf_withdrawn, atlas, d3, rmf, f3


def read_repo():
    """Books from the repository's frontmatter, and its git revision."""
    try:
        rev = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    except OSError:
        rev = ""
    books = []
    for d in sorted(p for p in SRC.iterdir() if (p / "SKILL.md").exists()):
        text = (d / "SKILL.md").read_text(encoding="utf-8", errors="ignore")
        fm = frontmatter(text)
        original = scalar(fm, "subdomain") or "uncategorised"
        b = {
            "name": d.name, "original": original, "subdomain": SUBDOMAIN.get(original, original),
            "description": scalar(fm, "description"),
            "attack": listing(fm, "mitre_attack"), "csf": listing(fm, "nist_csf"),
            "atlas": listing(fm, "atlas_techniques"), "d3fend": listing(fm, "d3fend_techniques"),
            "rmf": [re.sub(r"^(GOVERN|MAP|MEASURE|MANAGE)-", r"\1 ", x) for x in listing(fm, "nist_ai_rmf")],
            "f3": re.findall(r"id:\s*['\"]?([FT]\d{4}(?:\.\d{3})?)", fm),
            "copied": original not in NOT_COPIED,
        }
        books.append(b)
    return books, rev


def main():
    from_repo = SRC.exists()
    if from_repo:
        books, rev = read_repo()
        CATALOGUE.write_text(json.dumps({"source": UPSTREAM, "revision": rev, "books": books}, indent=1,
                                        ensure_ascii=False) + "\n", encoding="utf-8")
    elif CATALOGUE.exists():
        snap = json.loads(CATALOGUE.read_text(encoding="utf-8"))
        books, rev = snap["books"], snap["revision"]
        print(f"{SRC} not found: rebuilding indexes from {CATALOGUE.name} (revision {rev[:12]}); copies left as they are")
    else:
        sys.exit(f"{SRC} not found and no {CATALOGUE.name}: clone {UPSTREAM} into the repository root")
    attack_live, attack_revoked, csf_live, csf_withdrawn, atlas, d3, rmf, f3 = valid_sets()

    problems = collections.defaultdict(list)
    for b in books:
        for t in b["attack"]:
            if t not in attack_live:
                problems["ATT&CK"].append((b["name"], t, attack_revoked.get(t, "not found in ATT&CK v20.0")))
        for c in b["csf"]:
            if c not in csf_live:
                problems["NIST CSF 2.0"].append((b["name"], c, csf_withdrawn.get(c, "not a CSF 2.0 identifier")))
        for a in b["atlas"]:
            if a not in atlas:
                problems["MITRE ATLAS"].append((b["name"], a, "not found in ATLAS 2026.09"))
        for x in b["d3fend"]:
            if x.lower() not in d3:
                problems["MITRE D3FEND"].append((b["name"], x, "no D3FEND technique with this label"))
        for r in b["rmf"]:
            if r not in rmf:
                problems["NIST AI RMF"].append((b["name"], r, "not an AI RMF 1.0 category or subcategory"))
        for f in b["f3"]:
            if f not in f3:
                problems["MITRE F3"].append((b["name"], f, "not in F3 1.2"))

    copied = sum(b["copied"] for b in books)
    for b in books if from_repo else []:
        if b is books[0]:
            if OUT.exists():
                shutil.rmtree(OUT)
            OUT.mkdir(parents=True)
            shutil.copyfile(REPO / "LICENSE", OUT / "LICENSE")
        if not b["copied"]:
            continue
        src, dst = SRC / b["name"], OUT / b["name"]
        (dst / "references").mkdir(parents=True, exist_ok=True)
        note = (f"<!-- Copied from {UPSTREAM} (skills/{b['name']}/SKILL.md, revision {rev[:12] or 'unknown'}), "
                "Apache-2.0. Changes: renamed to playbook.md; scripts/ not included. A playbook is a procedure, "
                "not a standard: see ../README.md. -->\n")
        (dst / "playbook.md").write_text(note + (src / "SKILL.md").read_text(encoding="utf-8", errors="ignore"),
                                         encoding="utf-8")
        for f in sorted((src / "references").glob("*.md")) if (src / "references").exists() else []:
            shutil.copyfile(f, dst / "references" / f.name)

    by_domain = collections.defaultdict(list)
    for b in books:
        by_domain[b["subdomain"]].append(b)
    link = lambda b: f"[`{b['name']}`]({b['name']}/playbook.md)" if b["copied"] else f"`{b['name']}` (not copied)"

    def inverse(field):
        inv = collections.defaultdict(list)
        for b in books:
            for x in b[field]:
                inv[x].append(b)
        return inv

    def key(i):
        return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", i)]

    D = ["# Playbooks by domain", "", "> Generated by `scripts/gen_playbooks.py`. Do not edit by hand.", ""]
    for dom in sorted(by_domain, key=lambda x: (-len(by_domain[x]), x)):
        D += [f"## {dom} ({len(by_domain[dom])})", "", "| Playbook | Purpose |", "|---|---|"]
        for b in sorted(by_domain[dom], key=lambda b: b["name"]):
            D.append(f"| {link(b)} | {one_line(b['description']).replace('|', '/')} |")
        D.append("")
    (OUT / "index-by-domain.md").write_text("\n".join(D) + "\n", encoding="utf-8")

    for fname, field, title, note in (
            ("index-attack.md", "attack", "ATT&CK technique → playbooks", "IDs as written by the playbooks (ATT&CK v19.1); check `id-verification.md` for the ones changed in v20.0."),
            ("index-csf.md", "csf", "NIST CSF 2.0 subcategory → playbooks", "Subcategory text is in `../standards/nist-csf-2.0.md`."),
            ("index-d3fend.md", "d3fend", "MITRE D3FEND technique → playbooks", "Playbooks name D3FEND techniques by label; the D3FEND ID is added where the label resolves.")):
        inv = inverse(field)
        L = [f"# {title}", "", f"> Generated by `scripts/gen_playbooks.py`. {note} Do not edit by hand.", ""]
        for x in sorted(inv, key=key):
            label = f"{d3[x.lower()]} {x}" if field == "d3fend" and x.lower() in d3 else x
            L.append(f"- **{label}** ({len(inv[x])}): " + ", ".join(link(b) for b in sorted(inv[x], key=lambda b: b['name'])))
        (OUT / fname).write_text("\n".join(L) + "\n", encoding="utf-8")

    A = ["# MITRE ATLAS, NIST AI RMF and MITRE F3 → playbooks", "", "> Generated by `scripts/gen_playbooks.py`. Do not edit by hand.", ""]
    for field, title in (("atlas", "MITRE ATLAS"), ("rmf", "NIST AI RMF 1.0"), ("f3", "MITRE F3 (playbooks map v1.1)")):
        inv = inverse(field)
        A += [f"## {title}", ""]
        for x in sorted(inv, key=key):
            A.append(f"- **{x}** ({len(inv[x])}): " + ", ".join(link(b) for b in sorted(inv[x], key=lambda b: b['name'])))
        A.append("")
    (OUT / "index-ai-and-fraud.md").write_text("\n".join(A) + "\n", encoding="utf-8")

    V = ["# Playbook identifiers that do not resolve", "",
         "> Generated by `scripts/gen_playbooks.py`: every framework identifier in the playbooks' frontmatter checked "
         "against the versions this skill incorporates (ATT&CK v20.0, CSF 2.0, ATLAS 2026.09, D3FEND, AI RMF 1.0, "
         "F3 1.2). The playbooks were written against older releases; use the replacement where one is given. Do not "
         "edit by hand.", ""]
    total = sum(len(v) for v in problems.values())
    V.append(f"**{total} unresolved references** across {len(problems)} frameworks." if total else "Every identifier resolves.")
    V.append("")
    for fw in sorted(problems):
        agg = collections.defaultdict(list)
        for name, ident, why in problems[fw]:
            agg[(ident, why)].append(name)
        V += [f"## {fw} ({len(agg)} distinct)", "", "| Identifier | Status | Playbooks |", "|---|---|---|"]
        for (ident, why), names in sorted(agg.items(), key=lambda kv: key(kv[0][0])):
            V.append(f"| `{ident}` | {why} | {len(names)}: {', '.join(sorted(names)[:6])}{' …' if len(names) > 6 else ''} |")
        V.append("")
    (OUT / "id-verification.md").write_text("\n".join(V) + "\n", encoding="utf-8")

    skipped = [b for b in books if not b["copied"]]
    R = ["# Playbooks from Anthropic-Cybersecurity-Skills", "",
         f"**Source:** {UPSTREAM} (revision `{rev[:12] or 'unknown'}`), Apache-2.0 — see `LICENSE`. "
         f"**Indexed:** {len(books)} playbooks in {len(by_domain)} domains. **Copied:** {copied}.", "",
         "> Generated by `scripts/gen_playbooks.py`. Do not edit by hand.", "",
         "## What a playbook is — and is not", "",
         "A playbook is a **practitioner procedure** (when to use, prerequisites, steps, verification) for one task: "
         "hunting a technique, triaging a malware sample, hardening a cloud service, responding to an incident. It "
         "is **not a standard**: it never decides PASS / FAIL and never sets a finding's severity. Use a playbook "
         "to *do* the work; cite the standard to *judge* it. Playbook steps that call tools or scripts describe what "
         "an analyst would run; this skill's execution rules (`../audit/README.md`) still apply — no live probing "
         "of systems you do not own, no installs, sandboxed local evidence only.", "",
         "## How to find one", "",
         "- By domain: `index-by-domain.md`.",
         "- By threat or defence: `index-attack.md` (ATT&CK technique), `index-d3fend.md` (countermeasure), "
         "`index-csf.md` (CSF outcome), `index-ai-and-fraud.md` (ATLAS, AI RMF, F3).",
         "- Then open `<name>/playbook.md` and, if needed, its `references/`.", "",
         "## What was changed or left out", "",
         "- `SKILL.md` is renamed `playbook.md`; a provenance comment is added at the top. Content is otherwise "
         "unchanged.",
         "- `scripts/` is never copied (helper code, partly offensive tooling). Steps that mention a script refer to "
         "the upstream repository.",
         f"- **{len(skipped)} offensive playbooks** (original subdomain red-teaming, red-team or offensive-security) are "
         "indexed but not copied, because this skill is defensive.",
         f"- Framework identifiers were written against older releases. `id-verification.md` lists the "
         f"{sum(len(v) for v in problems.values())} that do not resolve in the versions incorporated here.",
         "- Not imported: the repository's OWASP Top 10 mapping (it labels 2021 categories as 2025) and its "
         "ATT&CK Navigator layer (ATT&CK v14).", "",
         "## Domains", "", "| Domain | Playbooks | Copied |", "|---|---:|---:|"]
    for dom in sorted(by_domain, key=lambda x: (-len(by_domain[x]), x)):
        R.append(f"| {dom} | {len(by_domain[dom])} | {sum(b['copied'] for b in by_domain[dom])} |")
    R.append("")
    (OUT / "README.md").write_text("\n".join(R) + "\n", encoding="utf-8")
    print(f"playbooks/: {len(books)} indexed, {copied} copied, {len(skipped)} offensive not copied, "
          f"{sum(len(v) for v in problems.values())} unresolved IDs", file=sys.stderr)


if __name__ == "__main__":
    main()
