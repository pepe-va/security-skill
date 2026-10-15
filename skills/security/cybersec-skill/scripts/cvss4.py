#!/usr/bin/env python3
"""CVSS v4.0 scoring: a Python port of FIRST's reference calculator.

The algorithm and data tables come from https://github.com/FIRSTdotorg/cvss-v4-calculator
(Copyright FIRST, Red Hat, and contributors; BSD-2-Clause). The tables are read at run time
from assets/cvss-calculator/*.js, so a calculator update is a re-download, not a code edit.
The port keeps the reference behaviour on purpose, including its quirks:

  - unset Threat/Environmental metrics count as their worst case (E:X -> A, CR/IR/AR:X -> H);
  - if no "max vector" dominates the scored vector, the distances of the last candidate are used;
  - a missing lower MacroVector makes its term drop out of the mean;
  - the final rounding is JavaScript's Math.round (half up), not Python's round (half to even).

Never estimate a CVSS score by hand: compute it here from the vector.

Usage:
  python cvss4.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
  python cvss4.py --test      reproduce every scored example in the summary tables of FIRST's examples page

Stdlib only.
"""
import html, json, math, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent
TABLES = ROOT.parent / "assets" / "cvss-calculator"
# FIRST's examples page is a test input kept in the source repository, not shipped with the skill.
EXAMPLES = ROOT.parents[3] / "sources" / "cvss" / "examples.html"

BASE = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
THREAT = ["E"]
ENVIRONMENTAL = ["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]
SUPPLEMENTAL = ["S", "AU", "R", "V", "RE", "U"]

LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}, "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2}, "AC": {"L": 0.0, "H": 0.1}, "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2}, "VI": {"H": 0.0, "L": 0.1, "N": 0.2}, "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3}, "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2}, "IR": {"H": 0.0, "M": 0.1, "L": 0.2}, "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
DISTANCE_ORDER = ["AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"]


def _js_object(path):
    """Read the object literal assigned in one of the calculator's .js data files."""
    src = path.read_text(encoding="utf-8")
    src = re.sub(r"//[^\n]*", "", src)
    body = src[src.index("{"): src.rindex("}") + 1]
    body = re.sub(r'([{,]\s*)([A-Za-z0-9_]+)\s*:', r'\1"\2":', body)   # quote bare keys
    body = re.sub(r",(\s*[}\]])", r"\1", body)                         # drop trailing commas
    return json.loads(body)


def _load():
    return {
        "lookup": _js_object(TABLES / "cvss_lookup.js"),
        "max_composed": _js_object(TABLES / "max_composed.js"),
        "max_severity": _js_object(TABLES / "max_severity.js"),
        "order": _js_object(TABLES / "metrics.js"),
    }


_T = None


def tables():
    global _T
    if _T is None:
        _T = _load()
    return _T


def parse(vector, strict_order=True):
    """Validate a CVSS v4.0 vector and return {metric: value} with unset metrics as 'X'.

    The specification (Table 23) makes any metric order other than the official one invalid;
    strict_order=False relaxes only that rule, for scoring third-party vectors that break it.
    """
    order = tables()["order"]
    if not vector.startswith("CVSS:4.0/"):
        raise ValueError("vector must start with 'CVSS:4.0/'")
    parts = vector[len("CVSS:4.0/"):].split("/")
    names = list(order)
    sel, last = {}, -1
    for part in parts:
        if ":" not in part:
            raise ValueError(f"malformed metric '{part}'")
        k, v = part.split(":", 1)
        if k not in order:
            raise ValueError(f"unknown metric '{k}'")
        if k in sel:
            raise ValueError(f"metric '{k}' repeated")
        if v not in order[k]:
            raise ValueError(f"invalid value '{v}' for {k}; allowed: {', '.join(order[k])}")
        if strict_order and names.index(k) < last:
            raise ValueError(f"metric '{k}' out of the order the specification requires")
        last = names.index(k)
        sel[k] = v
    missing = [k for k in BASE if k not in sel]
    if missing:
        raise ValueError("missing mandatory Base metric(s): " + ", ".join(missing))
    for k in names:
        sel.setdefault(k, "X")
    return sel


def m(sel, metric):
    """Effective value of a metric, as the reference calculator resolves it."""
    v = sel.get(metric, "X")
    if metric == "E" and v == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and v == "X":
        return "H"
    mod = sel.get("M" + metric)
    if mod is not None and mod != "X":
        return mod
    return v


def macro_vector(sel):
    av, pr, ui = m(sel, "AV"), m(sel, "PR"), m(sel, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if m(sel, "AC") == "L" and m(sel, "AT") == "N" else 1
    vc, vi, va = m(sel, "VC"), m(sel, "VI"), m(sel, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2
    if m(sel, "MSI") == "S" or m(sel, "MSA") == "S":
        eq4 = 0
    elif m(sel, "SC") == "H" or m(sel, "SI") == "H" or m(sel, "SA") == "H":
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[m(sel, "E")]
    eq6 = 0 if ((m(sel, "CR") == "H" and vc == "H") or (m(sel, "IR") == "H" and vi == "H")
                or (m(sel, "AR") == "H" and va == "H")) else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _value_in(metric, max_vector):
    rest = max_vector[max_vector.index(metric) + len(metric) + 1:]
    return rest.split("/")[0]


def _js_round1(x):
    return math.floor(x * 10 + 0.5) / 10


def score(sel):
    t = tables()
    lookup, maxc, maxs = t["lookup"], t["max_composed"], t["max_severity"]
    if all(m(sel, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    mv = macro_vector(sel)
    value = lookup[mv]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in mv)

    def mac(*eqs):
        return "".join(str(e) for e in eqs)

    lower = {
        "eq1": lookup.get(mac(eq1 + 1, eq2, eq3, eq4, eq5, eq6)),
        "eq2": lookup.get(mac(eq1, eq2 + 1, eq3, eq4, eq5, eq6)),
        "eq4": lookup.get(mac(eq1, eq2, eq3, eq4 + 1, eq5, eq6)),
        "eq5": lookup.get(mac(eq1, eq2, eq3, eq4, eq5 + 1, eq6)),
    }
    if eq3 == 0 and eq6 == 0:
        left = lookup.get(mac(eq1, eq2, eq3, eq4, eq5, eq6 + 1))
        right = lookup.get(mac(eq1, eq2, eq3 + 1, eq4, eq5, eq6))
        # JavaScript: comparisons involving undefined are false, so the right branch wins.
        lower["eq3eq6"] = left if (left is not None and right is not None and left > right) else right
    elif eq3 == 1 and eq6 == 1 or eq3 == 0 and eq6 == 1:
        lower["eq3eq6"] = lookup.get(mac(eq1, eq2, eq3 + 1, eq4, eq5, eq6))
    elif eq3 == 1 and eq6 == 0:
        lower["eq3eq6"] = lookup.get(mac(eq1, eq2, eq3, eq4, eq5, eq6 + 1))
    else:
        lower["eq3eq6"] = lookup.get(mac(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1))

    max_vectors = [a + b + c + d + e
                   for a in maxc["eq1"][str(eq1)]
                   for b in maxc["eq2"][str(eq2)]
                   for c in maxc["eq3"][str(eq3)][str(eq6)]
                   for d in maxc["eq4"][str(eq4)]
                   for e in maxc["eq5"][str(eq5)]]
    dist = {}
    for mx in max_vectors:
        dist = {k: LEVELS[k][m(sel, k)] - LEVELS[k][_value_in(k, mx)] for k in DISTANCE_ORDER}
        if all(d >= 0 for d in dist.values()):
            break  # otherwise keep the last candidate's distances, as the reference does

    current = {
        "eq1": dist["AV"] + dist["PR"] + dist["UI"],
        "eq2": dist["AC"] + dist["AT"],
        "eq3eq6": dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"],
        "eq4": dist["SC"] + dist["SI"] + dist["SA"],
        "eq5": 0,
    }
    step = 0.1
    max_sev = {
        "eq1": maxs["eq1"][str(eq1)] * step,
        "eq2": maxs["eq2"][str(eq2)] * step,
        "eq3eq6": maxs["eq3eq6"][str(eq3)][str(eq6)] * step,
        "eq4": maxs["eq4"][str(eq4)] * step,
    }
    n, total = 0, 0.0
    for eq in ("eq1", "eq2", "eq3eq6", "eq4", "eq5"):
        if lower[eq] is None:
            continue
        n += 1
        if eq == "eq5":
            continue  # the eq5 proportion is always 0
        total += (value - lower[eq]) * (current[eq] / max_sev[eq])
    value -= (total / n) if n else 0
    value = min(max(value, 0.0), 10.0)
    return _js_round1(value)


def severity(s):
    if s == 0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"


def nomenclature(sel):
    threat = sel.get("E", "X") != "X"
    env = any(sel.get(k, "X") != "X" for k in ENVIRONMENTAL)
    return "CVSS-B" + ("T" if threat else "") + ("E" if env else "")


def evaluate(vector):
    sel = parse(vector)
    s = score(sel)
    return {"vector": vector, "score": s, "severity": severity(s), "nomenclature": nomenclature(sel),
            "macro_vector": macro_vector(sel)}


def official_examples():
    """(vector, score) pairs from the summary tables of FIRST's examples page.

    Each example has a small table whose columns hold a score in one row and the vector in
    another (or both in one cell). The "CVSS v4 Score" boxes further down the same page are not
    used: several of them disagree with the summary tables and look stale.
    """
    if not EXAMPLES.exists():
        return []
    t = EXAMPLES.read_text(encoding="utf-8", errors="ignore")

    def clean(c):
        return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", c))).strip()

    out, seen = [], set()
    for table in re.findall(r"(?s)<table[^>]*>(.*?)</table>", t):
        grid = [[clean(c) for c in re.findall(r"(?s)<t[dh][^>]*>(.*?)</t[dh]>", tr)]
                for tr in re.findall(r"(?s)<tr[^>]*>(.*?)</tr>", table)]
        width = max((len(r) for r in grid), default=0)
        for j in range(width):
            col = [r[j] for r in grid if j < len(r)]
            vecs = [v for c in col for v in re.findall(r"CVSS:4\.0/[A-Za-z:/]+", c)]
            nums = [float(n) for c in col for n in re.findall(r"(?<![\w.:/])(\d{1,2}\.\d)(?![\w.])", c)]
            if len(vecs) == 1 and len(nums) == 1 and vecs[0] not in seen:
                seen.add(vecs[0])
                out.append((vecs[0], nums[0]))
    return out


# Page values that disagree with the reference algorithm this module ports line by line.
# Kept visible rather than silently excluded; re-check when FIRST updates the page or the calculator.
KNOWN_DISCREPANCIES = {
    "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": (
        8.2, "the page says 8.2; the reference algorithm gives 9.2 because EQ2 has no lower MacroVector, "
             "so AT:P adds no reduction once AC:H places the vector in EQ2=1 (AC:L/AT:P and AC:H/AT:N "
             "also score 9.2). FIRST's own JS calculator, run in QuickJS, also gives 9.2 "
             "(tests/test_cvss4.py in the source repository): the error is on the examples page."),
}


def self_test():
    cases = official_examples()
    if not cases:
        sys.exit("no scored examples found in " + str(EXAMPLES))
    bad, misordered = [], []
    for v, expected in cases:
        try:
            parse(v)
        except ValueError:
            misordered.append(v)
        got = score(parse(v, strict_order=False))
        if got != expected and KNOWN_DISCREPANCIES.get(v, (None,))[0] != expected:
            bad.append((v, expected, got))
    for v, e, g in bad:
        print(f"MISMATCH {v}: FIRST {e}, port {g}")
    known = [v for v, _ in cases if v in KNOWN_DISCREPANCIES]
    print(f"{len(cases) - len(bad) - len(known)}/{len(cases)} official examples reproduced exactly; "
          f"{len(known)} known discrepancy, {len(bad)} unexplained")
    for v in known:
        print(f"known discrepancy: {v}: {KNOWN_DISCREPANCIES[v][1]}")
    for v in misordered:
        print(f"note: example breaks the metric order of spec Table 23 (scored with strict_order=False): {v}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--test":
        self_test()
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    try:
        print(json.dumps(evaluate(sys.argv[1]), indent=2))
    except ValueError as e:
        sys.exit(f"invalid vector: {e}")
