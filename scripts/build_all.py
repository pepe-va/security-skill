#!/usr/bin/env python3
"""Regenerate everything the skill derives from official sources, in dependency order, then verify it.

Run from anywhere; paths are relative to this repository. Steps (see the skill's references/governance.md):
  1. fetch_sources.py        download missing inputs, adopt existing ones (skipped with --offline)
  2. gen_inventory.py        INVENTORY.md and tier-b-cards.md from the origin repositories, or from the
                             snapshot of their last scan (--refresh-status online; cached status offline)
  3. one generator per standard
  4. gen_asi.py, gen_crosswalk.py  last among the standards: they route to the views and SC controls and
                             verify crosswalk identifiers against the files of step 3
  5. gen_playbooks.py        indexes (and copies, when the origin repository is present); verifies playbook IDs
  6. verify_ids.py           every identifier the skill's own text cites must exist
  7. unit tests              tests/ (QuickJS tests are skipped without the quickjs module)

Usage:
  python scripts/build_all.py              everything
  python scripts/build_all.py --offline    no network: cached sources and status only
  python scripts/build_all.py --list       print the steps
  python scripts/build_all.py --from gen_cwe.py   resume from a step

Run it with the build virtual environment's interpreter (pypdf, pyyaml, beautifulsoup4, lxml, markdownify).
"""
import argparse, importlib.util, json, pathlib, subprocess, sys, time

SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parent
SKILL = REPO / "skills" / "security" / "cybersec-skill"

STANDARDS = [
    "gen_owasp_top10_2025.py", "gen_asvs.py", "gen_api_top10.py", "gen_masvs.py", "gen_800_63b.py",
    "gen_samm.py", "gen_ssdf.py", "gen_218a.py", "gen_slsa.py", "gen_llm_top10.py", "gen_threats.py",
    "gen_atlas.py", "gen_ai_rmf.py", "gen_ai600_1.py", "gen_attack.py", "gen_d3fend.py", "gen_f3.py",
    "gen_cwe.py", "gen_cvss.py", "gen_csf.py", "gen_800_53.py", "gen_nist_guides.py", "gen_ztmm.py",
]
BUILD_MODULES = ("pypdf", "yaml", "bs4", "lxml", "markdownify")


def steps(offline):
    out = [] if offline else [("fetch_sources.py", [])]
    out.append(("gen_inventory.py", [] if offline else ["--refresh-status"]))
    out += [(s, []) for s in STANDARDS]
    out += [("gen_asi.py", []), ("gen_crosswalk.py", []), ("gen_playbooks.py", []), ("verify_ids.py", []),
            ("-m unittest", ["discover", "-s", str(REPO / "tests")])]
    return out


def missing_inputs():
    """Inputs an offline build needs but a fresh clone lacks (download caches are not committed)."""
    src = REPO / "sources"
    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    missing = sorted(k for k in manifest if not (src / k).exists())
    if not any((src / "top10-2025-en").glob("*.html")):
        missing.append("top10-2025-en/ (page cache of gen_owasp_top10_2025.py)")
    return missing


def command(script, extra):
    if script.startswith("-m"):
        return [sys.executable, "-I"] + script.split() + extra
    path = SKILL / "scripts" / script if script == "verify_ids.py" else SCRIPTS / script
    return [sys.executable, "-I", str(path)] + extra


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--from", dest="start")
    args = ap.parse_args()
    plan = steps(args.offline)
    if args.list:
        for i, (s, a) in enumerate(plan, 1):
            print(f"{i:2d}. {s} {' '.join(a)}".rstrip())
        return
    missing = [m for m in BUILD_MODULES if importlib.util.find_spec(m) is None]
    if missing:
        sys.exit(f"missing build modules: {', '.join(missing)} — run with the build venv "
                 f"(pip install pypdf pyyaml beautifulsoup4 lxml markdownify)")
    if args.offline:
        missing = missing_inputs()
        if missing:
            sys.exit("--offline needs inputs that are not on disk (download caches are not committed):\n  "
                     + "\n  ".join(missing) + "\nRun once with network: python scripts/build_all.py")
    if args.start:
        names = [s for s, _ in plan]
        if args.start not in names:
            sys.exit(f"unknown step {args.start}; see --list")
        plan = plan[names.index(args.start):]
    failed = []
    for script, extra in plan:
        t = time.time()
        r = subprocess.run(command(script, extra), cwd=REPO, capture_output=True, text=True)
        tail = (r.stdout + r.stderr).strip().splitlines()[-1:] or [""]
        print(f"{'ok  ' if r.returncode == 0 else 'FAIL'}  {script:24s} {time.time() - t:6.1f}s  {tail[0][:110]}")
        if r.returncode != 0:
            failed.append(script)
            print("\n".join("      " + ln for ln in (r.stdout + r.stderr).strip().splitlines()[-15:]))
            if script in ("fetch_sources.py",) + tuple(STANDARDS):
                break   # later steps read these outputs: stop instead of building on a broken input
    if failed:
        sys.exit(f"failed: {', '.join(failed)}")
    print("build complete")


if __name__ == "__main__":
    main()
