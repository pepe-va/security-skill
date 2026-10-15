#!/usr/bin/env python3
"""Generate the MITRE ATT&CK references from the official STIX 2.1 bundles.

Sources (fetch_sources.py, group "attack"): enterprise-, mobile- and ics-attack-<version>.json from
mitre-attack/attack-stix-data.

Outputs under references/standards/mitre-attack/:
  README.md                    versions, reading rules, tactic index per domain, revoked/deprecated IDs
  enterprise-techniques.md     techniques with sub-techniques, mitigations and detection strategies
  enterprise-mitigations.md    mitigations with the techniques they address
  mobile.md, ics.md            techniques and mitigations of the other two domains

Stdlib only.
"""
import json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = ROOT.parent / "sources"
SKILL = ROOT.parent / "skills" / "security" / "cybersec-skill"
SRC = SOURCES / "attack"
OUT = SKILL / "references" / "standards" / "mitre-attack"
VERSION = "20.0"
DOMAINS = [("enterprise", "Enterprise"), ("mobile", "Mobile"), ("ics", "ICS")]
SITE = "https://attack.mitre.org"


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack") and r.get("external_id"):
            return r["external_id"]
    return None


def clean(text, limit=None):
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"</?code>", "`", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\]\(/", f"]({SITE}/", text)
    text = re.sub(r"[ \t]+", " ", text).strip()
    if limit and len(text) > limit:
        cut = text[:limit]
        text = cut[: cut.rfind(". ") + 1] if ". " in cut else cut + "…"
    return text


def quote(text):
    return "\n".join("> " + ln if ln.strip() else ">" for ln in text.splitlines())


def load(domain):
    path = SRC / f"{domain}-attack-{VERSION}.json"
    objs = json.loads(path.read_text(encoding="utf-8"))["objects"]
    byid = {o["id"]: o for o in objs}
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
    col = next(o for o in objs if o["type"] == "x-mitre-collection")
    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix" and live(o))
    tactics = {o["id"]: o for o in objs if o["type"] == "x-mitre-tactic" and live(o)}
    tactic_order = [t for t in matrix.get("tactic_refs", []) if t in tactics]
    shortname = {t["x_mitre_shortname"]: t for t in tactics.values()}
    techs = {o["id"]: o for o in objs if o["type"] == "attack-pattern" and live(o)}
    mits = {o["id"]: o for o in objs if o["type"] == "course-of-action" and live(o) and ext_id(o)}
    dets = {o["id"]: o for o in objs if o["type"] == "x-mitre-detection-strategy" and live(o)}
    rel = [o for o in objs if o["type"] == "relationship" and live(o)]
    parent_of, subs_of, mit_of, det_of, techs_of_mit = {}, {}, {}, {}, {}
    for r in rel:
        s, t, k = r["source_ref"], r["target_ref"], r["relationship_type"]
        if k == "subtechnique-of" and s in techs and t in techs:
            parent_of[s] = t
            subs_of.setdefault(t, []).append(s)
        elif k == "mitigates" and s in mits and t in techs:
            mit_of.setdefault(t, set()).add(s)
            techs_of_mit.setdefault(s, set()).add(t)
        elif k == "detects" and s in dets and t in techs:
            det_of.setdefault(t, set()).add(s)
    revoked = {}
    live_ids = {ext_id(o) for o in list(techs.values()) + list(mits.values()) + list(tactics.values())}
    for o in objs:
        # Pre-2019 course-of-action objects reuse their technique's T-ID; only M-IDs identify mitigations.
        kind_ok = o["type"] in ("attack-pattern", "x-mitre-tactic") or (
            o["type"] == "course-of-action" and (ext_id(o) or "").startswith("M"))
        if kind_ok and ext_id(o) and not live(o) and ext_id(o) not in live_ids:
            target = next((byid.get(r["target_ref"]) for r in objs if r["type"] == "relationship"
                           and r["relationship_type"] == "revoked-by" and r["source_ref"] == o["id"]), None)
            revoked[ext_id(o)] = ("revoked by " + ext_id(target)) if target and ext_id(target) else "deprecated"
    return dict(col=col, tactics=tactics, order=tactic_order, shortname=shortname, techs=techs, mits=mits,
                dets=dets, parent_of=parent_of, subs_of=subs_of, mit_of=mit_of, det_of=det_of,
                techs_of_mit=techs_of_mit, revoked=revoked)


def tactic_names(d, tech):
    out = []
    for ph in tech.get("kill_chain_phases", []):
        t = d["shortname"].get(ph["phase_name"])
        if t:
            out.append(f"{ext_id(t)} {t['name']}")
    return out


def sort_key(o):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", ext_id(o) or "")]


def technique_block(d, tid, w, full=True):
    t = d["techs"][tid]
    w(f"### {ext_id(t)} — {t['name']}")
    w("")
    meta = ["**Tactics:** " + (", ".join(tactic_names(d, t)) or "—")]
    if t.get("x_mitre_platforms"):
        meta.append("**Platforms:** " + ", ".join(t["x_mitre_platforms"]))
    meta.append(f"**Version:** {t.get('x_mitre_version', '—')} · {SITE}/techniques/{ext_id(t).replace('.', '/')}/")
    w("  \n".join(meta))
    w("")
    w(quote(clean(t.get("description"), 1400 if full else 600)))
    w("")
    for sid in sorted(d["subs_of"].get(tid, []), key=lambda x: sort_key(d["techs"][x])):
        s = d["techs"][sid]
        w(f"#### {ext_id(s)} — {s['name']}")
        w("")
        w(clean(s.get("description"), 450))
        extra = sorted(ext_id(d["mits"][m]) for m in d["mit_of"].get(sid, set()))
        if extra:
            w("")
            w("*Mitigations:* " + ", ".join(extra))
        w("")
    mits = sorted({m for x in [tid] + d["subs_of"].get(tid, []) for m in d["mit_of"].get(x, set())},
                  key=lambda m: sort_key(d["mits"][m]))
    if mits:
        w("**Mitigations:** " + ", ".join(f"`{ext_id(d['mits'][m])}` {d['mits'][m]['name']}" for m in mits))
        w("")
    dets = sorted({x for x in d["det_of"].get(tid, set())}, key=lambda x: sort_key(d["dets"][x]))
    if dets:
        w("**Detection strategies:** " + ", ".join(f"`{ext_id(d['dets'][x])}` {d['dets'][x]['name']}" for x in dets))
        w("")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = {dom: load(dom) for dom, _ in DOMAINS}

    R = []
    w = R.append
    w("# MITRE ATT&CK — adversary tactics and techniques")
    w("")
    w(f"**Official source:** {SITE}/ · **Data:** https://github.com/mitre-attack/attack-stix-data (STIX 2.1)")
    w("")
    for dom, label in DOMAINS:
        d = data[dom]
        n_par = sum(1 for t in d["techs"] if t not in d["parent_of"])
        w(f"- **{label} ATT&CK {d['col'].get('x_mitre_version')}** ({d['col'].get('modified', '')[:10]}): "
          f"{len(d['order'])} tactics · {n_par} techniques · {len(d['parent_of'])} sub-techniques · "
          f"{len(d['mits'])} mitigations · {len(d['dets'])} detection strategies")
    w("")
    w("> Generated by `scripts/gen_attack.py` from the official STIX bundles. Descriptions are trimmed and citation "
      "markers removed; follow the technique link for the full text. Do not edit by hand: regenerate.")
    w("")
    w("## Purpose in this skill")
    w("")
    w("ATT&CK is a **taxonomy of adversary behaviour**, not a control catalogue. This skill uses it to:")
    w("")
    w("1. **Threat-model** a system: which tactics and techniques an adversary could chain against it.")
    w("2. **Tag findings** whose exploitation matches a technique (e.g. a confirmed injection in an internet-facing "
      "service is `T1190 Exploit Public-Facing Application`), so findings speak the same language as detection "
      "and threat intelligence teams.")
    w("3. **Reach defences**: each technique lists its ATT&CK mitigations (`M####`) and detection strategies "
      "(`DET####`); D3FEND (`../mitre-d3fend.md`) gives countermeasures; the verifiable control comes from ASVS, "
      "SSDF, 800-53 or CSF 2.0.")
    w("")
    w("## Reading rules")
    w("")
    w("- A technique can serve **several tactics**; a sub-technique `T####.###` specialises its parent and is read "
      "with it.")
    w("- `Platforms` bounds where the technique applies. No matching platform means **NOT APPLICABLE**.")
    w("- An ATT&CK mitigation is a **direction of defence**, not a compliance criterion. PASS / FAIL rests on the "
      "control of the matching standard.")
    w("- ATT&CK carries **no severity**. A technique tag never sets a finding's severity.")
    w(f"- Cite with the version: `T1190 (ATT&CK v{VERSION})`. Revoked or deprecated IDs (list below) must not be "
      "cited; use the replacement.")
    w("- Enterprise v18+ splits the old Defense Evasion tactic into **Stealth (TA0005)** and **Defense Impairment "
      "(TA0112)**.")
    w("")
    w("## Files")
    w("")
    w("| File | Contents |")
    w("|---|---|")
    w("| `enterprise-techniques.md` | Enterprise techniques with sub-techniques, mitigations and detection strategies; search `### T<id> —` |")
    w("| `enterprise-mitigations.md` | Enterprise mitigations (`M####`) and the techniques each addresses |")
    w("| `mobile.md` | Mobile techniques and mitigations |")
    w("| `ics.md` | ICS techniques and mitigations |")
    w("")
    for dom, label in DOMAINS:
        d = data[dom]
        w(f"## {label} tactic index")
        w("")
        for ta in d["order"]:
            t = d["tactics"][ta]
            members = sorted((x for x in d["techs"].values() if x["id"] not in d["parent_of"] and any(
                ph["phase_name"] == t["x_mitre_shortname"] for ph in x.get("kill_chain_phases", []))), key=sort_key)
            w(f"- **{ext_id(t)} {t['name']}** ({len(members)}): " + ", ".join(f"{ext_id(x)} {x['name']}" for x in members))
        w("")
    w("## Revoked and deprecated identifiers")
    w("")
    w("Do not cite these. A playbook or crosswalk that uses one points to an older release.")
    w("")
    for dom, label in DOMAINS:
        rv = data[dom]["revoked"]
        w(f"**{label}:** " + ("; ".join(f"`{k}` {v}" for k, v in sorted(rv.items(), key=lambda kv: sort_key({"external_references": [{"source_name": "mitre-attack", "external_id": kv[0]}]}))) or "none"))
        w("")
    (OUT / "README.md").write_text("\n".join(R) + "\n", encoding="utf-8")

    d = data["enterprise"]
    E = []
    w = E.append
    w(f"# MITRE ATT&CK Enterprise {d['col'].get('x_mitre_version')} — techniques")
    w("")
    w("> Generated by `scripts/gen_attack.py`. Read `README.md` first for the reading rules. Do not edit by hand.")
    w("")
    for tid in sorted((x for x in d["techs"] if x not in d["parent_of"]), key=lambda x: sort_key(d["techs"][x])):
        technique_block(d, tid, w)
    (OUT / "enterprise-techniques.md").write_text("\n".join(E) + "\n", encoding="utf-8")

    M = []
    w = M.append
    w(f"# MITRE ATT&CK Enterprise {d['col'].get('x_mitre_version')} — mitigations")
    w("")
    w("> Generated by `scripts/gen_attack.py`. A mitigation is a direction of defence, not a compliance criterion.")
    w("")
    for mid in sorted(d["mits"], key=lambda x: sort_key(d["mits"][x])):
        mo = d["mits"][mid]
        w(f"### {ext_id(mo)} — {mo['name']}")
        w("")
        w(quote(clean(mo.get("description"), 1200)))
        w("")
        ts = sorted(d["techs_of_mit"].get(mid, set()), key=lambda x: sort_key(d["techs"][x]))
        w(f"**Addresses ({len(ts)}):** " + (", ".join(ext_id(d["techs"][x]) for x in ts) or "—"))
        w("")
    (OUT / "enterprise-mitigations.md").write_text("\n".join(M) + "\n", encoding="utf-8")

    for dom, label in DOMAINS[1:]:
        d = data[dom]
        F = []
        w = F.append
        w(f"# MITRE ATT&CK {label} {d['col'].get('x_mitre_version')} — techniques and mitigations")
        w("")
        w("> Generated by `scripts/gen_attack.py`. Read `README.md` first. Do not edit by hand.")
        w("")
        w("## Techniques")
        w("")
        for tid in sorted((x for x in d["techs"] if x not in d["parent_of"]), key=lambda x: sort_key(d["techs"][x])):
            technique_block(d, tid, w, full=False)
        w("## Mitigations")
        w("")
        for mid in sorted(d["mits"], key=lambda x: sort_key(d["mits"][x])):
            mo = d["mits"][mid]
            ts = sorted(d["techs_of_mit"].get(mid, set()), key=lambda x: sort_key(d["techs"][x]))
            w(f"### {ext_id(mo)} — {mo['name']}")
            w("")
            w(clean(mo.get("description"), 600))
            w("")
            w(f"**Addresses ({len(ts)}):** " + (", ".join(ext_id(d["techs"][x]) for x in ts) or "—"))
            w("")
        (OUT / f"{dom}.md").write_text("\n".join(F) + "\n", encoding="utf-8")

    for dom, label in DOMAINS:
        d = data[dom]
        print(f"{label}: {len(d['order'])} tactics, {len(d['techs']) - len(d['parent_of'])} techniques, "
              f"{len(d['parent_of'])} sub-techniques, {len(d['mits'])} mitigations, {len(d['revoked'])} revoked/deprecated",
              file=sys.stderr)


if __name__ == "__main__":
    main()
