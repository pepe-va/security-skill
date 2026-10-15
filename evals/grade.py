#!/usr/bin/env python3
"""Grade iteration runs of the cybersec-skill evals. Writes <eval>/<config>/run-1/grading.json.

Assertions are checked programmatically where possible, reusing the skill's own tools: verify_ids for
identifier existence, cvss4 for score consistency, validate_findings for the findings contract.
Usage: python grade.py iteration-1
"""
import hashlib, html, json, pathlib, re, subprocess, sys

WS = pathlib.Path(__file__).resolve().parent
SKILL = WS.parent / "skills" / "security" / "cybersec-skill"
sys.path.insert(0, str(SKILL / "scripts"))
import cvss4, verify_ids  # noqa: E402

IX = verify_ids.build_index()


def read_all(outdir, exts=(".md", ".txt", ".json", ".html")):
    parts = []
    for p in sorted(outdir.rglob("*")):
        if p.is_file() and p.suffix in exts and p.stat().st_size < 3_000_000:
            t = p.read_text(encoding="utf-8", errors="replace")
            if p.suffix == ".html":
                t = html.unescape(re.sub(r"<[^>]+>", " ", t))
            parts.append(t)
    return "\n".join(parts)


def ids_check(text):
    bad, good = [], set()
    for fam, ident, ok, why, _ in verify_ids.check_text("SKILL.md", text, IX):
        if fam == "path":
            continue
        (good.add(ident) if ok else bad.append(f"{ident} ({why})"))
    return good, sorted(set(bad))


def has(text, *alternatives, flags=re.I):
    return any(re.search(a, text, flags) for a in alternatives)


def fixtures_unchanged():
    out = subprocess.run(["sha256sum", "-c", "--quiet", str(WS / "fixtures.sha256")], cwd=WS / "fixtures",
                         capture_output=True, text=True)
    extra = subprocess.run(["find", ".", "-type", "f"], cwd=WS / "fixtures", capture_output=True, text=True).stdout.split()
    return out.returncode == 0 and len(extra) == len((WS / "fixtures.sha256").read_text().splitlines())


# ------------------------------------------------------------------------------------------- per eval

def eval1(out):
    t = read_all(out)
    good, bad = ids_check(t)
    return [
        ("Identifies the lethal trifecta (untrusted ticket content + private code/data + outbound action) and requires removing a leg or human approval",
         has(t, r"trifecta", r"rule of two") and has(t, r"human (approval|review|in the loop)", r"approv"),
         "mentions trifecta/Rule of Two and approval" if has(t, r"trifecta", r"rule of two") else "no trifecta / Rule of Two analysis"),
        ("Treats indirect prompt injection through ticket content as a primary threat",
         has(t, r"(indirect )?prompt injection") and has(t, r"ticket"), "prompt injection + tickets discussed"),
        ("Requires a least-privilege GitHub token enforced by GitHub itself (fine-grained / repo-scoped, no merge, branch protection)",
         has(t, r"least[- ]privilege", r"fine[- ]grained", r"minimal (scope|permission)") and has(t, r"branch protection", r"protected branch", r"cannot merge", r"no merge", r"without merge"),
         "least privilege + branch protection / no merge"),
        ("Treats the MCP server and its tool descriptions as supply chain (pin, verify, review descriptions)",
         has(t, r"MCP") and has(t, r"supply[- ]chain", r"\bpin", r"tool (description|poison)"), "MCP as supply chain"),
        ("Authorisation of the agent's actions is decided outside the model (deterministic policy / target system)",
         has(t, r"outside the (model|LLM)", r"not (by|to) the (model|LLM)", r"deterministic", r"complete mediation", r"policy (engine|enforcement|decision)"),
         "decision outside the model"),
        ("Cites at least 8 distinct standard identifiers that exist in the current version of their standard",
         len(good) >= 8, f"{len(good)} verified identifiers: {', '.join(sorted(good)[:15])}"),
        ("Cites no identifier that is invented, retired or from a superseded edition",
         not bad, "none" if not bad else "; ".join(bad[:10])),
    ]


def eval2(out):
    t = read_all(out)
    fj = next(iter(sorted(out.rglob("findings.json"))), None)
    v = subprocess.run([sys.executable, "-I", str(SKILL / "scripts" / "validate_findings.py"), str(fj)],
                       capture_output=True, text=True) if fj else None
    findings = json.loads(fj.read_text()) if fj else []
    recs = findings if isinstance(findings, list) else findings.get("findings", [])
    conf = [r for r in recs if r.get("verdict") == "confirmed"]
    blob = json.dumps(conf)
    idor_any = has(t, r"invoices/\s*<?\{?id", r"/invoices/") and has(t, r"IDOR", r"BOLA", r"CWE-639", r"CWE-862", r"CWE-285", r"autoriz", r"authori[sz]")
    sqli_any = has(t, r"/search") and has(t, r"CWE-89\b", r"SQL injection", r"inyecci[oó]n SQL", r"SQLi")
    htmls = sorted(out.rglob("*.html"))
    page = htmls[0].read_text(encoding="utf-8", errors="replace") if htmls else ""
    es = bool(re.search(r'<html[^>]*lang="es"', page)) or has(html.unescape(re.sub(r"<[^>]+>", " ", page)), r"hallazgo", r"informe")
    prompt_panel = "checkbox" in page and has(page, r"prompt") and has(page, r"copi|copy")
    fp = [r.get("title", "") for r in conf
          if has(r.get("title", ""), r"pbkdf2", r"password (hash|storage)", r"weak hash", r"hash de contrase")
          or (has(r.get("title", ""), r"inject", r"inyecci") and not has(r.get("title", ""), r"/search", r"search"))]
    return [
        ("findings.json exists and passes the skill's findings validator",
         bool(v) and v.returncode == 0, "no findings.json" if not v else (v.stdout + v.stderr).strip()[-200:]),
        ("Reports the missing ownership check on GET /invoices/<id> (IDOR / BOLA)", idor_any,
         "found in outputs" if idor_any else "not reported"),
        ("Reports the SQL injection in GET /search", sqli_any, "found in outputs" if sqli_any else "not reported"),
        ("Each confirmed finding is justified by a tier-A requirement and a CWE (sources)",
         bool(conf) and all(any(s.get("relation") == "violated-requirement" and s.get("tier") == "A" for s in r.get("sources", []))
                            and any(s.get("relation") == "weakness" for s in r.get("sources", [])) for r in conf),
         f"{len(conf)} confirmed findings" + (f"; sources e.g. {[s.get('id') for s in conf[0].get('sources', [])]}" if conf else "")),
        ("An HTML report in Spanish is produced", bool(htmls) and es, f"{[h.name for h in htmls]} lang es={es}"),
        ("The HTML report has a mitigation prompt panel with per-finding checkboxes and a copy action",
         prompt_panel, "panel present" if prompt_panel else "no prompt panel"),
        ("No false positive on the PBKDF2 password hashing or the parameterised queries",
         not fp, "no confirmed finding on the hashing or the parameterised queries" if not fp else str(fp)),
        ("The target repository was not modified", fixtures_unchanged(), "sha256 of every fixture file unchanged"),
    ]


def eval3(out):
    t = read_all(out)
    good, bad = ids_check(t)
    vectors = re.findall(r"CVSS:4\.0/[A-Z:/]+[A-Z]", t)
    v = vectors[0] if vectors else None
    computed, consistent, base_ok = None, False, False
    if v:
        try:
            computed = cvss4.score(cvss4.parse(v, strict_order=False))
            consistent = bool(re.search(rf"\b{re.escape(str(computed))}\b", t))
            mm = dict(x.split(":") for x in v.split("/")[1:])
            base_ok = all(mm.get(k) == val for k, val in
                          dict(AV="N", AC="L", AT="N", PR="L", UI="N", VI="N", VA="N", SC="N", SI="N", SA="N").items()) and mm.get("VC") in ("H", "L")
        except ValueError as e:
            computed = f"invalid: {e}"
    return [
        ("Names CWE-639 (Authorization Bypass Through User-Controlled Key) as the weakness", has(t, r"CWE-639"),
         "CWE-639 present" if has(t, r"CWE-639") else "CWE-639 absent"),
        ("Gives a CVSS 4.0 base vector matching the facts (AV:N/AC:L/AT:N/PR:L/UI:N, VC:H or L, no integrity, availability or subsequent impact)",
         base_ok, v or "no CVSS 4.0 vector"),
        ("The stated CVSS score is the one FIRST's algorithm gives for the stated vector", consistent,
         f"vector {v} computes to {computed}; {'stated' if consistent else 'not stated'} in the answer"),
        ("Severity is High (consistent with the cross-customer read)", has(t, r"severity[^\n]{0,40}high", r"\bhigh\b[^\n]{0,30}severity", r"\*\*high\*\*"),
         "high severity stated" if has(t, r"\bhigh\b") else "no high severity"),
        ("Cites the ASVS 5.0.0 object-level authorisation requirement (8.2.2)", has(t, r"v5\.0\.0-8\.2\.2", r"(?<![\d.])V?8\.2\.2(?![\d.])"),
         "8.2.2 cited" if has(t, r"8\.2\.2") else "not cited"),
        ("Cites OWASP API Security Top 10 2023 API1 (BOLA)", has(t, r"API1:2023", r"API1\b"), "API1 cited" if has(t, r"API1") else "not cited"),
        ("Cites OWASP Top 10:2025 A01, not only the 2021 edition", has(t, r"A01:2025"), "A01:2025 cited" if has(t, r"A01:2025") else "not cited"),
        ("Cites no identifier that is invented, retired or from a superseded edition", not bad, "none" if not bad else "; ".join(bad[:10])),
    ]


def eval4(out):
    t = read_all(out)
    sbom = [p for p in out.rglob("*.json") if has(p.read_text(errors="replace")[:4000], r'"bomFormat"\s*:\s*"CycloneDX"')]
    reports = [p for p in out.rglob("*") if p.suffix in (".html", ".md") and p.name != "answer.md"]
    return [
        ("A CycloneDX SBOM is produced", bool(sbom), str([p.name for p in sbom]) or "none"),
        ("Reports known vulnerabilities of lodash 4.17.15 with advisory identifiers",
         has(t, r"lodash") and has(t, r"CVE-2020-8203", r"CVE-2021-23337", r"GHSA-p6mc-m468-83gw", r"GHSA-35jh-r3h4-6jhm", r"CVE-2020-28500"),
         "lodash advisories cited" if has(t, r"CVE-2020-8203|CVE-2021-23337|GHSA-") else "no advisory IDs"),
        ("Flags the colour-utilz postinstall hook with encoded eval as suspicious",
         has(t, r"colour-utilz") and has(t, r"postinstall", r"install (hook|script)") and has(t, r"eval", r"base64", r"encoded"),
         "flagged" if has(t, r"colour-utilz") else "not flagged"),
        ("Does not call colour-utilz confirmed malware: it is a lead needing validation (the eval is dead code)",
         has(t, r"needs[_ ]validation", r"not (confirmed|proven) (as )?malicious", r"dead code", r"never (runs|executes|called)", r"if \(false\)", r"inert"),
         "treated as unconfirmed lead"),
        ("Flags expresss as a likely typosquat of express", has(t, r"expresss") and has(t, r"typo", r"look-?alike", r"squat"),
         "typosquat flagged" if has(t, r"typo") else "not flagged"),
        ("Produces a shareable report file", bool(reports), str([p.name for p in reports][:5])),
        ("States that static analysis cannot prove the packages are clean",
         has(t, r"cannot prove", r"can't prove", r"does not prove", r"no (guarantee|proof)", r"not prove"),
         "limitation stated" if has(t, r"cannot prove", r"can't prove", r"does not prove", r"no (guarantee|proof)", r"not prove")
         else "no statement that a clean result is not proof"),
        ("Nothing in the target was installed, built or modified", fixtures_unchanged(), "sha256 of every fixture file unchanged"),
    ]


GRADERS = {1: eval1, 2: eval2, 3: eval3, 4: eval4}


def main():
    it = WS / sys.argv[1]
    for ed in sorted(it.glob("eval-*")):
        meta = json.loads((ed / "eval_metadata.json").read_text())
        for cfg in ("with_skill", "without_skill"):
            run = ed / cfg / "run-1"
            out = run / "outputs"
            if not out.exists():
                print(f"missing {out}")
                continue
            exps = [{"text": a, "passed": bool(p), "evidence": e} for a, p, e in GRADERS[meta["eval_id"]](out)]
            n = sum(e["passed"] for e in exps)
            grading = {"expectations": exps, "summary": {"passed": n, "failed": len(exps) - n, "total": len(exps),
                                                          "pass_rate": round(n / len(exps), 2)}}
            tf = run / "timing.json"
            if tf.exists():
                grading["timing"] = json.loads(tf.read_text())
            (run / "grading.json").write_text(json.dumps(grading, indent=2, ensure_ascii=False) + "\n")
            print(f"{ed.name:40s} {cfg:14s} {n}/{len(exps)}")
        meta["assertions"] = [a for a, _, _ in GRADERS[meta["eval_id"]](ed / "with_skill" / "run-1" / "outputs")] \
            if (ed / "with_skill" / "run-1" / "outputs").exists() else meta["assertions"]
        (ed / "eval_metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
