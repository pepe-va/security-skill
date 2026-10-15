"""Tests for scripts/validate_findings.py.

Ported from security-audit-skill's validate-findings.test.cjs (MIT, Cloudflare), plus tests for the
checks this skill adds (sources, CVSS, dependency records). Run: python -m unittest discover tests
"""
import copy, json, os, pathlib, subprocess, sys, tempfile, unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOOLS = REPO / "skills" / "security" / "cybersec-skill" / "scripts"
sys.path.insert(0, str(TOOLS))
import validate_findings as vf  # noqa: E402

SCHEMA = vf.load_schema()
TERMINAL_CONTROL_PAYLOAD = "\u001b\u0007\u0085\u202e\u034f\ufe0f"
TERMINAL_CONTROL_BYTES = [b"\x1b", b"\x07", "\u0085".encode(), "\u202e".encode(), "\u034f".encode(), "\ufe0f".encode()]

ASVS = {"standard": "OWASP ASVS", "version": "5.0.0", "id": "v5.0.0-8.2.2",
        "file": "references/standards/owasp-asvs-5.0.0.md", "relation": "violated-requirement", "tier": "A"}
CWE = {"standard": "MITRE CWE", "version": "4.20", "id": "CWE-639", "file": "references/standards/cwe/weaknesses.md",
       "relation": "weakness", "tier": "A"}


def src(kind="entrypoint", file="src/handler.c", line=10):
    return {"kind": kind, "file": file, "line": line, "scope": "handle", "description": "Attacker data reaches the operation."}


def evidence(file="src/handler.c", line=10):
    return {"file": file, "line": line, "description": "The source performs the operation without the required check."}


def confirmed():
    return {
        "verdict": "confirmed", "fingerprint": "src-handler-missing-check", "title": "Missing ownership check",
        "description": "An attacker can reach an operation without the intended ownership check.",
        "root_cause": "handle omits the ownership check before changing the object.",
        "intended_behavior": "Only the object's owner can change it.",
        "trace": [src("entrypoint"), src("propagation", "src/model.c", 20), src("sink", "src/store.c", 30)],
        "evidence": [evidence()], "conditions": [],
        "execution": {"attacker_perspective": "An unprivileged remote user with their own account.",
                      "payloads": ["An object identifier owned by another user."],
                      "instructions": ["Submit the identifier through the public operation."],
                      "observed_result": "The other user's object changes."},
        "remediation": {"strategy": "Check ownership before the state change."},
        "severity": {"likelihood": {"score": "medium", "reason": "The operation is directly reachable."},
                     "impact": {"score": "medium", "reason": "The attacker changes one protected object."},
                     "overall_severity": "medium"},
        "confidence": {"score": "high", "reason": "The source path and result were reproduced."},
        "sources": [copy.deepcopy(ASVS), copy.deepcopy(CWE)],
    }


def needs_validation():
    return {
        "verdict": "needs_validation", "fingerprint": "src-parser-size-hypothesis", "title": "Unchecked parsed size",
        "description": "A parsed size may reach an allocation without a limit.",
        "claimed_root_cause": "parse_size may pass an unbounded value to allocate.",
        "trace": [src()], "evidence": [evidence()],
        "blockers": ["The generated parser source is absent from this checkout."],
        "validation_plan": {"local": "Generate the parser and submit the smallest input that exceeds the documented limit.",
                            "deployment": "In an approved test deployment, confirm the request reaches the generated parser and record the bounded observable result."},
        "sources": [{"standard": "MITRE CWE", "version": "4.20", "id": "CWE-770",
                     "file": "references/standards/cwe/weaknesses.md", "relation": "weakness", "tier": "A"}],
    }


def rejected():
    return {
        "verdict": "rejected", "fingerprint": "src-router-auth-bypass", "title": "Authorization bypass in router",
        "description": "The candidate claimed a route bypassed authorization.",
        "claimed_root_cause": "dispatch was claimed to skip the authorization wrapper.",
        "trace": [src("sink")], "evidence": [evidence()],
        "reason": "All routes pass through the authorization wrapper before dispatch.",
    }


def errors_for(value):
    return vf.validate_document(value, SCHEMA)


def run_cli(contents, timeout=15):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "findings.json")
        with open(path, "wb") as fh:
            fh.write(contents if isinstance(contents, bytes) else contents.encode("utf-8", "surrogatepass"))
        return subprocess.run([sys.executable, str(TOOLS / "validate_findings.py"), path], capture_output=True, timeout=timeout)


def out(result):
    return (result.stdout + result.stderr).decode("utf-8", "replace")


def producer_shaped():
    demo = confirmed()
    demo["conditions"] = [{"kind": "authentication_level", "description": "The attacker needs a normal account."}]
    demo["execution"]["payloads"] = ["", " \t\r\n", "\u0000\u001f\u007f", "\u034f", "\ufe0f", "\ud800", "\udc00", "[{,}]\\\""]
    demo["remediation"]["code_changes"] = [{"file_name": "src/handler.c", "fixed_code": ""}]
    blocked = needs_validation()
    del blocked["validation_plan"]["deployment"]
    return [demo, blocked, rejected()]


def dumps(value):
    return json.dumps(value, ensure_ascii=True)


class Upstream(unittest.TestCase):
    def reject(self, factory, mutate):
        v = factory()
        mutate(v)
        self.assertNotEqual(errors_for([v]), [], f"mutation accepted: {v}")

    def test_schema_shape(self):
        self.assertEqual(SCHEMA["type"], "array")
        self.assertEqual([b["properties"]["verdict"]["const"] for b in SCHEMA["items"]["oneOf"]],
                         ["confirmed", "needs_validation", "rejected"])
        c = SCHEMA["items"]["oneOf"][0]["properties"]
        self.assertTrue(c["title"]["visibleContent"])
        self.assertNotIn("minLength", c["execution"]["properties"]["payloads"]["items"])

    def test_cli_accepts_producer_shaped(self):
        r = run_cli(dumps(producer_shaped()))
        self.assertEqual(r.returncode, 0, out(r))
        self.assertIn("PASS: 3 findings valid", out(r))

    def test_accepts_branches(self):
        self.assertEqual(errors_for([]), [])
        self.assertEqual(errors_for([confirmed(), needs_validation(), rejected()]), [])
        for drop in ("deployment", "local"):
            v = needs_validation()
            del v["validation_plan"][drop]
            self.assertEqual(errors_for([v]), [])

    def test_one_line_trace(self):
        v = confirmed()
        v["trace"] = [src("entrypoint")]
        self.assertEqual(errors_for([v]), [])

    def test_rejects_empty_required_content(self):
        cases = [
            (confirmed, lambda f: f.update(title="")), (confirmed, lambda f: f.update(title="   ")),
            (confirmed, lambda f: f.update(evidence=[])), (confirmed, lambda f: f["execution"].update(payloads=[])),
            (confirmed, lambda f: f["execution"].update(instructions=[])),
            (confirmed, lambda f: f["execution"].update(observed_result="")),
            (confirmed, lambda f: f["remediation"].update(strategy="")),
            (needs_validation, lambda f: f.update(blockers=[])), (needs_validation, lambda f: f.update(validation_plan={})),
            (needs_validation, lambda f: f.update(validation_plan={"local": " "})),
            (rejected, lambda f: f.update(claimed_root_cause="")),
        ]
        for factory, mutate in cases:
            self.reject(factory, mutate)

    def test_preserves_payload_strings(self):
        v = confirmed()
        payloads = ["", " \t\r\n", "\u0000\u001f\u007f", "\u034f", "\ufe0f", "\ud800", "\udc00"]
        v["execution"]["payloads"] = list(payloads)
        v["remediation"]["code_changes"] = [{"file_name": "src/handler.c", "fixed_code": "\u0000 \t\r\n\u001f\u007f\u034f\ufe0f\ud800x\udc00"}]
        self.assertEqual(errors_for([v]), [])
        self.assertEqual(v["execution"]["payloads"], payloads)

    def test_rejects_invisible_prose(self):
        for invisible in ["\u0000\t\r\n\u001f\u007f\u200b", "\u034f", "\ufe0f", "\ud800", "\udc00", "visible\ud800"]:
            cases = [
                (confirmed, lambda f: f.update(title=invisible)),
                (confirmed, lambda f: f["trace"][0].update(scope=invisible)),
                (confirmed, lambda f: f["evidence"][0].update(description=invisible)),
                (confirmed, lambda f: f["execution"].update(instructions=[invisible])),
                (confirmed, lambda f: f["remediation"].update(strategy=invisible)),
                (confirmed, lambda f: f["severity"]["impact"].update(reason=invisible)),
                (confirmed, lambda f: f["confidence"].update(reason=invisible)),
                (needs_validation, lambda f: f.update(blockers=[invisible])),
                (needs_validation, lambda f: f.update(validation_plan={"local": invisible})),
                (rejected, lambda f: f.update(reason=invisible)),
            ]
            for factory, mutate in cases:
                self.reject(factory, mutate)

    def test_quotes_controls_in_diagnostics(self):
        v = confirmed()
        v["trace"][0]["kind"] = f"invalid-{TERMINAL_CONTROL_PAYLOAD}"
        v["execution"][f"extra-{TERMINAL_CONTROL_PAYLOAD}"] = "value"
        text = "\n".join(errors_for([v]))
        for esc in ["\\u001b", "\\u0007", "\\u0085", "\\u202e", "\\u034f", "\\ufe0f"]:
            self.assertIn(esc, text)
        for marker in TERMINAL_CONTROL_BYTES:
            self.assertNotIn(marker, text.encode("utf-8", "surrogatepass"))

    def test_rejects_line_zero(self):
        self.reject(confirmed, lambda f: f["trace"][0].update(line=0))
        self.reject(rejected, lambda f: f["evidence"][0].update(line=0))

    def test_unexpected_field(self):
        self.reject(confirmed, lambda f: f.update(constructor="not allowed"))

    def test_one_of_exactly_one(self):
        self.assertTrue(any("matched 2" in e for e in vf.collect_unchecked("value", {"oneOf": [{"type": "string"}, {"minLength": 1}]}, "$test")))
        self.assertTrue(any("matched 0" in e for e in vf.collect_unchecked(7, {"oneOf": [{"type": "string"}, {"minimum": 10}]}, "$test")))

    def test_duplicates(self):
        a, b = confirmed(), rejected()
        b["fingerprint"] = a["fingerprint"]
        self.assertTrue(any("duplicate of" in e for e in errors_for([a, b])))
        self.reject(needs_validation, lambda f: f.update(blockers=[f["blockers"][0], f["blockers"][0]]))

    def test_canonical_uniqueness_at_limit(self):
        n = vf.LIMITS["arrayItems"]
        entries = [{"id": i, "label": str(i)} for i in range(n)]
        self.assertEqual(vf.collect_unchecked(entries, {"type": "array", "uniqueItems": True}, "$data"), [])
        dup = entries[:-1] + [{"label": "0", "id": 0}]
        self.assertTrue(any(f"duplicate at index {n - 1}" in e for e in vf.collect_unchecked(dup, {"type": "array", "uniqueItems": True}, "$data")))

    def test_bounds_canonical_keys(self):
        big = "x" * (vf.LIMITS["canonicalKeyBytes"] + 1)
        self.assertTrue(any("canonical key exceeds" in e for e in vf.collect_unchecked([big], {"type": "array", "uniqueItems": True}, "$d")))
        size = vf.LIMITS["uniqueSetBytes"] // 6
        items = [f"{i}{'x' * size}" for i in range(6)]
        self.assertTrue(any("canonical uniqueness set exceeds" in e for e in vf.collect_unchecked(items, {"type": "array", "uniqueItems": True}, "$d")))

    def test_sorted(self):
        self.assertTrue(any("sorted lexicographically" in e for e in errors_for([rejected(), confirmed()])))

    def test_severity_above_impact(self):
        def m(f):
            f["severity"]["overall_severity"] = "high"
            f["severity"]["impact"]["score"] = "medium"
        self.reject(confirmed, m)

    def test_unsafe_paths(self):
        bad = ["/etc/passwd", "../src/file.c", "src/../file.c", "src//file.c", "C:\\src\\file.c", "src/file:name.c",
               "src/file\nname.c", "src/file\u0001name.c", "src/file\u0085name.c", "src/file\u2028name.c",
               "src/file\u202ename.c", "src/file\u2066name.c", "src/file\u200dname.c", "src/file\u034fname.c",
               "src/file\ufe0fname.c", "src/file\ud800name.c", "src/file\udc00name.c", "CON", "src/con.txt", "src/PRN",
               "src/AUX.c", "src/NUL", "src/COM1.log", "src/lpt9", "src/CONIN$", "src/CONOUT$.txt", "src/CLOCK$.txt",
               "src/COM\u00b9.log", "src/LPT\u00b2.log", "src /file.c", "src./file.c", "src/file.c ", "src/file.c.",
               "src/cloc\u212a$.txt"]
        for p in bad:
            self.reject(confirmed, lambda f, p=p: f["trace"][0].update(file=p))
        self.reject(rejected, lambda f: f["evidence"][0].update(file="NUL.txt"))
        self.reject(confirmed, lambda f: f["remediation"].update(code_changes=[{"file_name": "src/file:name.c", "fixed_code": "x"}]))

    def test_unicode_paths_ok(self):
        v = confirmed()
        v["title"] = "Finding \U0001F600 cafe\u0301"
        v["trace"][0]["file"] = "src/日本語/cafe\u0301-\U0001F600.ts"
        v["evidence"][0]["file"] = "src/mañana/файл.ts"
        v["remediation"]["code_changes"] = [{"file_name": "src/修正/éxito.ts", "fixed_code": "replacement"}]
        self.assertEqual(errors_for([v]), [])

    def test_cli_byte_limit(self):
        r = run_cli(b" " * (vf.LIMITS["inputBytes"] + 1))
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"input exceeds {vf.LIMITS['inputBytes']} byte limit", out(r))
        self.assertNotIn("Traceback", out(r))

    def test_cli_invalid_utf8(self):
        enc = dumps(producer_shaped()).encode()
        r = run_cli(enc.replace(b"src/handler.c", b"src/handler\x80c", 1))
        self.assertEqual(r.returncode, 1)
        self.assertIn("input is not valid UTF-8", out(r))
        self.assertNotIn("Traceback", out(r))

    def test_cli_quotes_controls(self):
        v = confirmed()
        v["trace"][0]["kind"] = f"invalid-{TERMINAL_CONTROL_PAYLOAD}"
        v["execution"][f"extra-{TERMINAL_CONTROL_PAYLOAD}"] = "value"
        r = run_cli(json.dumps([v], ensure_ascii=False))
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"$[0].trace[0].kind", r.stderr)
        for marker in TERMINAL_CONTROL_BYTES:
            self.assertNotIn(marker, r.stderr)

    def test_cli_generic_syntax_error(self):
        r = run_cli(b"[" + TERMINAL_CONTROL_PAYLOAD.encode() + b"]")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stderr, b"Failed to parse findings JSON: invalid JSON syntax\n")

    def test_cli_missing_path_not_reflected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, f"missing-{TERMINAL_CONTROL_PAYLOAD}.json")
            r = subprocess.run([sys.executable, str(TOOLS / "validate_findings.py"), p], capture_output=True, timeout=15)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"Failed to read findings JSON:", r.stderr)
        for marker in TERMINAL_CONTROL_BYTES:
            self.assertNotIn(marker, r.stderr)

    def test_cli_lone_surrogate_prose(self):
        f = producer_shaped()
        f[0]["title"] = "\ud800"
        r = run_cli(dumps(f))
        self.assertEqual(r.returncode, 1)
        self.assertIn("must contain only valid Unicode scalar values", out(r))

    @unittest.skipIf(os.name == "nt", "POSIX only")
    def test_cli_fifo(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings.json")
            os.mkfifo(p)
            r = subprocess.run([sys.executable, str(TOOLS / "validate_findings.py"), p], capture_output=True, timeout=15)
        self.assertEqual(r.returncode, 1)
        self.assertIn("input must be a regular file", out(r))

    @unittest.skipIf(os.name == "nt", "POSIX only")
    def test_cli_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            t, s = os.path.join(d, "target.json"), os.path.join(d, "findings.json")
            pathlib.Path(t).write_text(dumps(producer_shaped()))
            os.symlink(t, s)
            r = subprocess.run([sys.executable, str(TOOLS / "validate_findings.py"), s], capture_output=True, timeout=15)
        self.assertEqual(r.returncode, 1)
        self.assertIn("input must not be a symlink", out(r))

    def test_cli_nesting_limit(self):
        n = vf.LIMITS["nestingDepth"] + 1
        r = run_cli("[" * n + "0" + "]" * n)
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"{vf.LIMITS['nestingDepth']} level nesting depth limit", out(r))
        self.assertNotIn("RecursionError", out(r))

    def test_cli_array_limit(self):
        r = run_cli(json.dumps([None] * (vf.LIMITS["arrayItems"] + 1)))
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"{vf.LIMITS['arrayItems']} item array limit", out(r))

    def test_pattern_and_branch_invariants(self):
        self.reject(rejected, lambda f: f.update(fingerprint="not stable"))
        self.reject(needs_validation, lambda f: f.update(severity={"impact": {"score": "low"}, "overall_severity": "low"}))

    def test_schema_keyword_checks(self):
        self.assertTrue(any("format" in e for e in vf.schema_errors({"type": "string", "format": "uuid"})))
        self.assertTrue(any("regular expression" in e for e in vf.schema_errors({"type": "string", "pattern": "["})))
        self.assertTrue(any("expected boolean" in e for e in vf.schema_errors({"type": "string", "visibleContent": "yes"})))
        self.assertTrue(any("requires type" in e for e in vf.schema_errors({"type": "array", "visibleContent": True})))
        self.assertNotEqual(vf.validate_document([], {"type": "array", "maxItems": 1}), [])

    def test_caps_output(self):
        self.assertEqual(len(errors_for([None] * vf.LIMITS["arrayItems"])), vf.LIMITS["validationErrors"])
        r = run_cli(json.dumps([None] * vf.LIMITS["arrayItems"]))
        self.assertEqual(r.returncode, 1)
        self.assertIn("output capped at 100", out(r))
        self.assertLess(len(out(r)), 20000)

    def test_prose_corpus(self):
        expect = {"Valid prose.": True, "caf\u00e9": True, "": False, " \t\r\n": False, "\u200b": False,
                  "\u034f": False, "\ufe0f": False, "\ud800": False, "\udc00": False, "visible\ud800": False}
        for value, ok in expect.items():
            self.assertEqual(vf.has_visible_prose(value), ok, repr(value))


class Sources(unittest.TestCase):
    def test_sources_required(self):
        for factory in (confirmed, needs_validation):
            v = factory()
            del v["sources"]
            self.assertTrue(any('missing required field "sources"' in e for e in errors_for([v])))

    def test_confirmed_needs_requirement_and_weakness(self):
        v = confirmed()
        v["sources"] = [CWE]
        self.assertTrue(any("violated-requirement" in e for e in errors_for([v])))
        v = confirmed()
        v["sources"] = [ASVS]
        self.assertTrue(any("weakness" in e for e in errors_for([v])))

    def test_identifier_must_exist(self):
        v = confirmed()
        v["sources"][0]["id"] = "v5.0.0-99.9.9"
        self.assertTrue(any("not found in" in e for e in errors_for([v])))
        v = confirmed()
        v["sources"][0]["file"] = "references/standards/does-not-exist.md"
        self.assertTrue(any("does not exist" in e for e in errors_for([v])))

    def test_tier_b_only_candidate(self):
        v = needs_validation()
        v["sources"].append({"standard": "PCI DSS", "version": "4.0.1", "id": "Req 6.2.4",
                             "file": "references/standards/tier-b-cards.md", "relation": "violated-requirement", "tier": "B"})
        self.assertTrue(any("candidate-control" in e for e in errors_for([v])))
        v["sources"][-1]["relation"] = "candidate-control"
        self.assertEqual(errors_for([v]), [])

    def test_compound_identifiers(self):
        self.assertTrue(vf.id_in_text("PW.7.2.R1", "#### PW.7.2 · priority\n- **R1:** Scan"))
        self.assertTrue(vf.id_in_text("§3.1.1.2", "##### 3.1.1.2. Password Verifiers"))
        self.assertFalse(vf.id_in_text("AC-2", "AC-20 Use of External Systems"))

    def test_cvss_must_be_computed(self):
        v = confirmed()
        v["cvss"] = {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                     "score": 9.9, "severity": "Critical", "nomenclature": "CVSS-B"}
        self.assertTrue(any("does not match scripts/cvss4.py" in e for e in errors_for([v])))
        sys.path.insert(0, str(TOOLS))
        import cvss4
        ref = cvss4.evaluate(v["cvss"]["vector"])
        v["cvss"].update(score=ref["score"], severity=ref["severity"], nomenclature=ref["nomenclature"])
        self.assertEqual(errors_for([v]), [])

    def test_dependency_needs_package(self):
        v = needs_validation()
        v["category"] = "dependency"
        self.assertTrue(any('requires "package"' in e for e in errors_for([v])))
        v["package"] = {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0"}
        self.assertEqual(errors_for([v]), [])


if __name__ == "__main__":
    unittest.main()
