#!/usr/bin/env python3
"""Render the audit output directory into one self-contained HTML report (Phase 6 of modes 2 and 3).

Usage:
  python render_report.py <output-dir> [--lang es|en] [--out FILE] [--allow-invalid]

Reads <output-dir>/findings.json (required), run-metadata.json and coverage-ledger.json (optional) and
writes <output-dir>/security-report.html (or --out). The report has a summary, the context, the
confirmed findings with their justifying sources, the leads that need validation, hardening notes,
coverage, rejected candidates, and a mitigation-prompt panel: one checkbox per finding, criticals
preselected, the prompt rebuilt on every change, and a Copy button.

Safety of the page itself: every string comes from the audited repository and is untrusted. Data is
embedded as JSON with <, >, & and line separators escaped, the page writes it only through textContent,
and a Content-Security-Policy with the hashes of its one style and one script blocks everything else
(no network, no other script, no inline handlers).

The report is refused when findings.json fails scripts/validate_findings.py, unless --allow-invalid is
given; the page then says so in a banner. Stdlib only.
"""
import argparse, base64, datetime, hashlib, html, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent
TEMPLATE = ROOT.parent / "assets" / "report-template.html"
sys.path.insert(0, str(ROOT))
import validate_findings  # noqa: E402
import validate_ledger  # noqa: E402


def embed_json(value):
    text = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def sha256_b64(text):
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()


def load_json(path, required=False):
    if not path.exists():
        if required:
            sys.exit(f"{path} not found")
        return None
    return json.loads(validate_findings.read_file_within_limit(str(path)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("output_dir")
    ap.add_argument("--lang", choices=("es", "en"), default="en",
                    help="report language: use the language of the conversation (default en)")
    ap.add_argument("--out", help="output file (default <output-dir>/security-report.html)")
    ap.add_argument("--allow-invalid", action="store_true", help="render even if the validators fail (the page warns)")
    a = ap.parse_args()
    d = pathlib.Path(a.output_dir)
    findings = load_json(d / "findings.json", required=True)
    meta = load_json(d / "run-metadata.json") or {}
    ledger = load_json(d / "coverage-ledger.json") or []

    problems = list(validate_findings.validate_document(findings, validate_findings.load_schema()))
    if ledger:
        problems += [f"coverage-ledger: {e}" for e in validate_ledger.validate_document(ledger)]
    if problems and not a.allow_invalid:
        for p in problems[:20]:
            print("ERROR:", p, file=sys.stderr)
        sys.exit(f"refusing to render: {len(problems)} validation error(s). Fix them, or pass --allow-invalid.")
    if problems:
        meta = dict(meta)
        meta["run_status"] = "incomplete"
        meta["incomplete_reason"] = (f"the report was rendered with {len(problems)} validation error(s) "
                                     "(--allow-invalid); do not rely on it")

    data = {"lang": a.lang, "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "metadata": meta, "findings": findings, "ledger": ledger}
    page = TEMPLATE.read_text(encoding="utf-8")
    style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    csp = ("default-src 'none'; "
           f"style-src 'sha256-{sha256_b64(style)}'; script-src 'sha256-{sha256_b64(script)}'; "
           "img-src data:; base-uri 'none'; form-action 'none'")
    title = ("Informe de seguridad" if a.lang == "es" else "Security report") + (f" — {meta['repo']}" if meta.get("repo") else "")
    out = (page.replace("__CSP__", html.escape(csp, quote=True))
               .replace("__LANG__", a.lang)
               .replace("__TITLE__", html.escape(title))
               .replace("__DATA__", embed_json(data)))
    target = pathlib.Path(a.out) if a.out else d / "security-report.html"
    target.write_text(out, encoding="utf-8")
    counts = {}
    for f in findings:
        k = f.get("verdict")
        if k == "confirmed":
            k = f"confirmed:{(f.get('severity') or {}).get('overall_severity', '?')}"
        counts[k] = counts.get(k, 0) + 1
    print(f"wrote {target} ({target.stat().st_size:,} bytes) · {', '.join(f'{k}={v}' for k, v in sorted(counts.items())) or 'no findings'}"
          + (f" · WARNING: {len(problems)} validation error(s)" if problems else ""))


if __name__ == "__main__":
    main()
