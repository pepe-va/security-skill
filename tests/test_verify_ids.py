"""Tests for scripts/verify_ids.py: real identifiers resolve, invented or retired ones do not.

Run: python -m unittest discover tests
"""
import pathlib, sys, unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOOLS = REPO / "skills" / "security" / "cybersec-skill" / "scripts"
sys.path.insert(0, str(TOOLS))
import verify_ids  # noqa: E402

GOOD = """ASVS `v5.0.0-8.2.2`, V8.4.1 and chapter V13 · SSDF `PW.4.4`, practice PS.3 · `800-218A PW.7.2.R1`
A01:2025 · API1:2023 · LLM01:2026 · ASI02 · AML.T0070 and AML.TA0006 · T1195.002, TA0006, M1051
D3-MFA · F1005.003 · CWE-639 · PR.AA-01 · GOVERN 1.7 · GV-1.1-001 · AC-6(1), SC-7 · MASVS-AUTH-1
SC-AUTH-01 · SLSA Build L3 · 800-63B-4 §3.1.1.2 · 800-190 §4.1 R28 · OWASP SAMM V2.0
`references/standards/owasp-asvs-5.0.0.md`"""

BAD = {
    "v5.0.0-99.1.1": "ASVS", "PW.9.9": "SSDF", "A11:2025": "Top 10", "A01:2021": "Top 10", "API11:2023": "API Top 10",
    "LLM01:2025": "LLM Top 10", "ASI11": "ASI", "AML.T0045": "ATLAS", "T9999": "ATT&CK", "D3-NOPE": "D3FEND",
    "F9999": "F3", "CWE-730": "CWE", "PR.ZZ-01": "CSF 2.0", "GOVERN 9.9": "AI RMF", "GV-9.9-001": "AI 600-1",
    "AC-99": "800-53", "MASVS-AUTH-9": "MASVS", "SC-AUTH-99": "SC", "Build L7": "SLSA",
    "800-190 §4.1 R12": "NIST guide", "800-63B-4 §9.9": "NIST guide", "`references/standards/nope.md`": "path",
}


class VerifyIds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ix = verify_ids.build_index()

    def results(self, text):
        return list(verify_ids.check_text("SKILL.md", text, self.ix))

    def test_real_identifiers_resolve(self):
        res = self.results(GOOD)
        self.assertTrue(res)
        unknown = [(fam, ident, why) for fam, ident, ok, why, _ in res if not ok]
        self.assertEqual(unknown, [])

    def test_invented_or_retired_identifiers_fail(self):
        for text, family in BAD.items():
            with self.subTest(text=text):
                res = [(fam, ok) for fam, _, ok, _, _ in self.results(text)]
                self.assertIn((family, False), res)

    def test_218a_items_need_their_context(self):
        # PO.5.3 exists only in SP 800-218A: bare it is an unknown SSDF task, prefixed it resolves.
        self.assertIn(("SSDF", False), [(f, ok) for f, _, ok, _, _ in self.results("SSDF `PO.5.3`")])
        self.assertIn(("800-218A", True), [(f, ok) for f, _, ok, _, _ in self.results("`800-218A PO.5.3`")])

    def test_skill_text_is_clean(self):
        bad = []
        for rel in verify_ids.SCANNED:
            text = (verify_ids.SKILL / rel).read_text(encoding="utf-8")
            for fam, ident, ok, why, no in verify_ids.check_text(rel, text, self.ix):
                if not ok and not (ident in verify_ids.EXCEPTIONS and rel in verify_ids.EXCEPTIONS[ident][0]):
                    bad.append(f"{rel}:{no} {ident} ({why})")
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
