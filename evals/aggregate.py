#!/usr/bin/env python3
"""Aggregate grading.json files into benchmark.json / benchmark.md (same schema as skill-creator's
aggregate_benchmark.py, which this sandbox cannot execute from ~/.claude). Usage: python aggregate.py iteration-1"""
import json, math, pathlib, sys
from datetime import datetime, timezone

WS = pathlib.Path(__file__).resolve().parent


def stats(v):
    if not v:
        return {"mean": 0.0, "stddev": 0.0, "min": 0.0, "max": 0.0}
    m = sum(v) / len(v)
    sd = math.sqrt(sum((x - m) ** 2 for x in v) / (len(v) - 1)) if len(v) > 1 else 0.0
    return {"mean": round(m, 4), "stddev": round(sd, 4), "min": round(min(v), 4), "max": round(max(v), 4)}


def main():
    it = WS / sys.argv[1]
    runs, by_cfg = [], {}
    for ed in sorted(it.glob("eval-*")):
        meta = json.loads((ed / "eval_metadata.json").read_text())
        for cfg in ("with_skill", "without_skill"):
            for rd in sorted((ed / cfg).glob("run-*")):
                g = json.loads((rd / "grading.json").read_text())
                t = json.loads((rd / "timing.json").read_text()) if (rd / "timing.json").exists() else {}
                res = {**{k: g["summary"][k] for k in ("pass_rate", "passed", "failed", "total")},
                       "time_seconds": t.get("total_duration_seconds", 0.0), "tokens": t.get("total_tokens", 0),
                       "tool_calls": 0, "errors": 0}
                runs.append({"eval_id": meta["eval_id"], "eval_name": meta["eval_name"], "configuration": cfg,
                             "run_number": int(rd.name.split("-")[1]), "result": res,
                             "expectations": g["expectations"], "notes": []})
                by_cfg.setdefault(cfg, []).append(res)
    summary = {c: {"pass_rate": stats([r["pass_rate"] for r in rs]), "time_seconds": stats([r["time_seconds"] for r in rs]),
                   "tokens": stats([r["tokens"] for r in rs])} for c, rs in by_cfg.items()}
    a, b = summary["with_skill"], summary["without_skill"]
    summary["delta"] = {"pass_rate": f"{a['pass_rate']['mean'] - b['pass_rate']['mean']:+.2f}",
                        "time_seconds": f"{a['time_seconds']['mean'] - b['time_seconds']['mean']:+.1f}",
                        "tokens": f"{a['tokens']['mean'] - b['tokens']['mean']:+.0f}"}
    notes = json.loads((it / "analyst-notes.json").read_text()) if (it / "analyst-notes.json").exists() else []
    bench = {"metadata": {"skill_name": "cybersec-skill", "skill_path": str(WS.parent / "skills" / "security" / "cybersec-skill"),
                          "executor_model": "claude-opus-5-5", "analyzer_model": "claude-opus-5-5",
                          "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                          "evals_run": sorted({r["eval_id"] for r in runs}), "runs_per_configuration": 1},
             "runs": runs, "run_summary": summary, "notes": notes}
    (it / "benchmark.json").write_text(json.dumps(bench, indent=2, ensure_ascii=False) + "\n")
    md = ["# Skill Benchmark: cybersec-skill", "", f"**Date**: {bench['metadata']['timestamp']} · 4 evals, 1 run per configuration", "",
          "| Metric | With Skill | Without Skill | Delta |", "|---|---|---|---|",
          f"| Pass rate | {a['pass_rate']['mean']*100:.0f}% | {b['pass_rate']['mean']*100:.0f}% | {summary['delta']['pass_rate']} |",
          f"| Time (s) | {a['time_seconds']['mean']:.0f} ± {a['time_seconds']['stddev']:.0f} | {b['time_seconds']['mean']:.0f} ± {b['time_seconds']['stddev']:.0f} | {summary['delta']['time_seconds']} |",
          f"| Tokens | {a['tokens']['mean']:.0f} ± {a['tokens']['stddev']:.0f} | {b['tokens']['mean']:.0f} ± {b['tokens']['stddev']:.0f} | {summary['delta']['tokens']} |",
          "", "## Per eval", "", "| Eval | With skill | Without skill |", "|---|---|---|"]
    for eid in bench["metadata"]["evals_run"]:
        w = next(r for r in runs if r["eval_id"] == eid and r["configuration"] == "with_skill")
        o = next(r for r in runs if r["eval_id"] == eid and r["configuration"] == "without_skill")
        md.append(f"| {w['eval_name']} | {w['result']['passed']}/{w['result']['total']} · {w['result']['time_seconds']:.0f}s · {w['result']['tokens']} tok "
                  f"| {o['result']['passed']}/{o['result']['total']} · {o['result']['time_seconds']:.0f}s · {o['result']['tokens']} tok |")
    if notes:
        md += ["", "## Notes", ""] + [f"- {n}" for n in notes]
    (it / "benchmark.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
