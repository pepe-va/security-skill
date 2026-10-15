"""Tests for scripts/cvss4.py.

1. The official examples of FIRST's examples page are reproduced (one documented page error).
2. FIRST's reference calculator (BSD-2-Clause JavaScript in the skill's assets/cvss-calculator) is run in QuickJS
   and must give the same score as the Python port for those examples and for random vectors, including
   threat and environmental metrics. Skipped when the `quickjs` module is not installed (pip install quickjs).
Run: python -m unittest discover tests
"""
import json, pathlib, random, sys, unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOOLS = REPO / "skills" / "security" / "cybersec-skill" / "scripts"
sys.path.insert(0, str(TOOLS))
import cvss4  # noqa: E402

try:
    import quickjs
except ImportError:  # pragma: no cover
    quickjs = None

CALC = TOOLS.parent / "assets" / "cvss-calculator"
BASE = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
DRIVER = """
function jsScore(vector) {
  var sel = {};
  for (var k in expectedMetricOrder) sel[k] = "X";
  var parts = vector.split("/").slice(1);
  for (var i = 0; i < parts.length; i++) { var kv = parts[i].split(":"); sel[kv[0]] = kv[1]; }
  return cvss_score(sel, cvssLookup_global, maxSeverity, macroVector(sel));
}
"""


class OfficialExamples(unittest.TestCase):
    def test_examples_reproduced(self):
        cases = cvss4.official_examples()
        self.assertGreater(len(cases), 40)
        for vector, expected in cases:
            got = cvss4.score(cvss4.parse(vector, strict_order=False))
            if vector in cvss4.KNOWN_DISCREPANCIES:
                self.assertEqual(cvss4.KNOWN_DISCREPANCIES[vector][0], expected)
                continue
            self.assertEqual(got, expected, vector)

    def test_severity_and_nomenclature(self):
        r = cvss4.evaluate("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")
        self.assertEqual((r["score"], r["severity"], r["nomenclature"]), (9.3, "Critical", "CVSS-B"))
        r = cvss4.evaluate("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U")
        self.assertEqual(r["nomenclature"], "CVSS-BT")

    def test_bad_vectors_rejected(self):
        for v in ("CVSS:3.1/AV:N", "CVSS:4.0/AV:N/AC:L", "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                  "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"):
            with self.assertRaises(ValueError, msg=v):
                cvss4.parse(v)


@unittest.skipIf(quickjs is None, "quickjs not installed")
class AgainstFirstCalculator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = quickjs.Context()
        for name in ("cvss_lookup.js", "max_severity.js", "max_composed.js", "metrics.js", "cvss_score.js"):
            cls.ctx.eval((CALC / name).read_text())
        cls.ctx.eval(DRIVER)
        cls.order = json.loads(cls.ctx.eval("JSON.stringify(expectedMetricOrder)"))

    def js(self, vector):
        return float(self.ctx.eval(f"String(jsScore({json.dumps(vector)}))"))

    def assertSame(self, vector):
        self.assertEqual(cvss4.score(cvss4.parse(vector, strict_order=False)), self.js(vector), vector)

    def test_known_discrepancy_is_a_page_error(self):
        for vector in cvss4.KNOWN_DISCREPANCIES:
            self.assertEqual(self.js(vector), 9.2)
            self.assertSame(vector)

    def test_official_examples(self):
        for vector, _ in cvss4.official_examples():
            self.assertSame(vector)

    def test_random_vectors(self):
        rng = random.Random(4)
        for _ in range(1500):
            parts = [f"{m}:{rng.choice([x for x in self.order[m] if x != 'X'])}" for m in BASE]
            parts += [f"{m}:{rng.choice(self.order[m])}" for m in self.order if m not in BASE and rng.random() < 0.3]
            self.assertSame("CVSS:4.0/" + "/".join(parts))


if __name__ == "__main__":
    unittest.main()
