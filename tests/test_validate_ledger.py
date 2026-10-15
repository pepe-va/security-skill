"""Tests for scripts/validate_ledger.py, ported from security-audit-skill's validate-coverage-ledger.test.cjs (MIT).

Run: python -m unittest discover tests
"""
import json, os, pathlib, subprocess, sys, tempfile, unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOOLS = REPO / "skills" / "security" / "cybersec-skill" / "scripts"
sys.path.insert(0, str(TOOLS))
import validate_ledger as vl  # noqa: E402
import validate_findings as vf  # noqa: E402

REFS = {"surface": "src/router.ts#POST /users/:id", "boundary": "src/authz.ts#requireOwner",
        "subsystem": "packages/api", "attack_class": "ATTACK-CLASSES.md#Access control"}


def unit(**over):
    refs = over.pop("canonical_refs", dict(REFS))
    v = {"coverage_id": vl.canonical_coverage_id(refs), "canonical_refs": refs, "surface": "Update-user route",
         "boundary": "Object ownership", "subsystem": "API", "attack_class": "Access control",
         "starting_paths": ["src/router.ts", "src/authz.ts"],
         "ordinary_attack_class_block": "ATTACK-CLASSES.md#Access control", "selected_companion_blocks": [],
         "excluded_blocks": [{"block": "WEB-PROTOCOL-AND-AUTH.md#Cache behavior", "reason": "The route is not cached."}],
         "prior_status": "new", "attempts": [], "wave": 1, "status": "planned", "agent_id": None,
         "reviewed_paths": [], "local_checks": [], "result_fingerprints": [], "unresolved": []}
    v.update(over)
    return v


def source_check(agent="hunter-1", **over):
    v = {"agent_id": agent, "reviewed_paths": ["src/router.ts"], "invariant": "The route checks object ownership.",
         "method": "source", "result": "The owner check applies before the update.", "artifact": None}
    v.update(over)
    return v


def local_check(agent="hunter-1", **over):
    v = source_check(agent, method="local", result="The bounded fixture accepted the other owner's object.",
                     artifact=f"agents/{agent}/artifacts/result.txt")
    v.update(over)
    return v


def archived(**over):
    v = {"wave": 1, "status": "blocked", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
         "local_checks": [source_check()], "result_fingerprints": [], "unresolved": ["The deployed policy is unavailable."],
         "reassignment_reason": "The critic found an unchecked parallel path."}
    v.update(over)
    return v


def errs(value):
    return vl.validate_document(value)


def has(errors, text):
    return any(text in e for e in errors)


def run_cli(contents):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "coverage-ledger.json")
        with open(p, "wb") as fh:
            fh.write(contents if isinstance(contents, bytes) else contents.encode("utf-8", "surrogatepass"))
        return subprocess.run([sys.executable, str(TOOLS / "validate_ledger.py"), p], capture_output=True, timeout=30)


class Ledger(unittest.TestCase):
    def test_accepts(self):
        self.assertEqual(errs([]), [])
        self.assertEqual(errs([unit()]), [])
        u = unit()
        del u["attempts"]
        self.assertTrue(has(errs([u]), 'missing required field "attempts"'))
        self.assertEqual(errs([unit(status="covered", agent_id="hunter-1", reviewed_paths=["src/router.ts"],
                                    local_checks=[source_check()])]), [])

    def test_cli(self):
        r = run_cli(json.dumps([unit()]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"PASS: 1 coverage units valid", r.stdout)

    def test_preflight_strings(self):
        v = unit(surface='Route \\ slash [list] {object}, colon: quoted "value"',
                 excluded_blocks=[{"block": "COMPANION.md#Literal [brackets] {braces}",
                                   "reason": 'The text contains a backslash \\ before an escaped "quote".'}])
        vl.preflight_json_text(json.dumps([v]))
        self.assertEqual(run_cli(json.dumps([v])).returncode, 0)

    def test_preflight_limits(self):
        d = vl.LIMITS["nestingDepth"]
        vl.preflight_json_text("[" * d + "0" + "]" * d)
        with self.assertRaisesRegex(vl.JsonStructureError, "exceeds nesting depth limit 64"):
            vl.preflight_json_text("[" * (d + 1) + "0" + "]" * (d + 1))
        with self.assertRaisesRegex(vl.JsonStructureError, "exceeds 10000 top-level unit limit"):
            vl.preflight_json_text("[" + "null," * vl.LIMITS["units"] + "null]")
        with self.assertRaisesRegex(vl.JsonStructureError, "exceeds 1000 item array limit"):
            vl.preflight_json_text("[[" + "null," * vl.LIMITS["collectionItems"] + "null]]")
        fields = ",".join(f'"field{i}":null' for i in range(vl.LIMITS["objectFields"] + 1))
        with self.assertRaisesRegex(vl.JsonStructureError, "exceeds 1000 field object limit"):
            vl.preflight_json_text("[{" + fields + "}]")
        full = "[" + "null," * (vl.LIMITS["collectionItems"] - 1) + "null]"
        need = vl.LIMITS["preflightValues"] // (vl.LIMITS["collectionItems"] + 1) + 1
        with self.assertRaisesRegex(vl.JsonStructureError, "exceeds 500000 total value limit"):
            vl.preflight_json_text("[" + ",".join([full] * need) + "]")

    def test_preflight_truncation(self):
        for text, msg in (("[", "truncated JSON structure"), ('["unterminated', "unterminated JSON string"),
                          ('[{"field":1]', "mismatched JSON containers")):
            with self.assertRaisesRegex(vl.JsonStructureError, msg):
                vl.preflight_json_text(text)

    def test_canonical_ids(self):
        self.assertEqual(vl.encode_canonical_ref("route:POST /users"), "route%3APOST%20%2Fusers")
        self.assertNotEqual(vl.encode_canonical_ref("route name"), vl.encode_canonical_ref("route-name"))
        self.assertEqual(vl.canonical_coverage_id({"surface": "a", "boundary": "b", "subsystem": "c", "attack_class": "d",
                                                   "lifecycle": "retry"}), "a::b::c::d::retry")
        for bad in ("e\u0301", "bad\u0000ref", "hidden\u200bref"):
            with self.assertRaises(TypeError):
                vl.encode_canonical_ref(bad)

    def test_noncanonical_duplicate_colliding(self):
        self.assertTrue(has(errs([unit(coverage_id="display-label-slug")]), "expected canonical ID"))
        self.assertTrue(has(errs([unit(), unit()]), "duplicate coverage ID"))
        self.assertTrue(has(errs([unit(), unit(surface="Delete-user route")]), "canonical identity collision"))

    def test_alias(self):
        first = unit()
        alias = unit(canonical_refs=dict(REFS, surface="src/alias.ts#updateUser"))
        ledger = sorted([first, alias], key=lambda u: u["coverage_id"])
        self.assertTrue(has(errs(ledger), "semantic tuple already uses coverage ID"))

    def test_order(self):
        second = dict(REFS, surface="zzz")
        self.assertTrue(has(errs([unit(canonical_refs=second), unit()]), "sorted lexicographically"))

    def test_block_maps(self):
        self.assertTrue(has(errs([unit(selected_companion_blocks=["AI-AND-LLM.md#Tool calls"],
                                       excluded_blocks=[{"block": "AI-AND-LLM.md#Tool calls", "reason": "Claimed irrelevant."}])]),
                            "also selected"))
        self.assertTrue(has(errs([unit(excluded_blocks=[{"block": "AI-AND-LLM.md#Tool calls", "reason": ""}])]), "reason"))

    def test_artifacts(self):
        self.assertEqual(errs([unit(status="covered", agent_id="hunter-1", reviewed_paths=["src/router.ts"],
                                    local_checks=[local_check()])]), [])
        self.assertEqual(errs([unit(status="covered", agent_id="hunter-1", reviewed_paths=["src/router.ts", "src/authz.ts"],
                                    local_checks=[source_check(), local_check("verifier-1", reviewed_paths=["src/authz.ts"])])]), [])
        self.assertTrue(has(errs([unit(status="covered", agent_id="hunter-1", reviewed_paths=["src/router.ts", "src/authz.ts"],
                                       local_checks=[source_check()])]), "has no check owner"))
        for agent, artifact in ((None, "agents/hunter-1/artifacts/result.txt"), ("hunter-1", None), ("hunter-1", "result.txt"),
                                ("hunter-1", "agents/hunter-2/artifacts/result.txt"),
                                ("../hunter", "agents/../hunter/artifacts/result.txt")):
            v = unit(status="covered", agent_id="hunter-1", reviewed_paths=["src/router.ts"],
                     local_checks=[local_check(agent, artifact=artifact)])
            self.assertNotEqual(errs([v]), [], f"{agent}: {artifact}")
        self.assertTrue(has(errs([unit(status="blocked", reviewed_paths=["src/router.ts"], local_checks=[source_check()],
                                       unresolved=["The boundary behavior is not source-visible."])]),
                            'unit with status "blocked" requires a canonical lowercase agent ID'))
        self.assertTrue(has(errs([unit(status="covered", agent_id="hunter-1", reviewed_paths=["src/router.ts"],
                                       local_checks=[source_check(artifact="agents/hunter-1/artifacts/source.txt")])]),
                            "source-only check must use null"))

    def test_agent_ids(self):
        for ok in ("hunter-1", "verifier_2", "a0"):
            self.assertTrue(vl.is_safe_agent_id(ok), ok)
        for bad in ("Hunter-1", "hunter.1", "hunter-1.", "hunter ", "con", "prn", "aux", "nul", "com1", "lpt9", "../hunter"):
            self.assertFalse(vl.is_safe_agent_id(bad), bad)
        self.assertTrue(has(errs([unit(status="in_progress", agent_id="Hunter-1")]), "canonical lowercase agent ID"))

    def test_state_evidence(self):
        self.assertTrue(has(errs([unit(status="in_progress")]), 'unit with status "in_progress" requires'))
        self.assertTrue(has(errs([unit(status="blocked")]), "unresolved"))
        self.assertTrue(has(errs([unit(status="candidate")]), "reviewed_paths"))
        self.assertEqual(errs([unit(status="in_progress", agent_id="hunter-1")]), [])
        self.assertTrue(has(errs([unit(status="in_progress", agent_id="hunter-1", reviewed_paths=["src/router.ts"],
                                       local_checks=[source_check()])]), "must keep this array empty"))
        self.assertTrue(has(errs([unit(agent_id="hunter-1", reviewed_paths=["src/router.ts"], local_checks=[source_check()])]),
                            "planned unit must be unassigned"))
        cand = unit(status="candidate", agent_id="hunter-1", reviewed_paths=["src/router.ts"],
                    local_checks=[source_check(invariant="Ownership is required.", result="No check exists.")],
                    result_fingerprints=["src-router-missing-owner-check"], unresolved=["validation_budget_exhausted"])
        self.assertEqual(errs([cand]), [])
        blocked = unit(status="blocked", agent_id="hunter-1", reviewed_paths=["src/router.ts"], local_checks=[source_check()],
                       unresolved=["The deployed policy is unavailable."])
        self.assertEqual(errs([blocked]), [])
        self.assertTrue(has(errs([dict(blocked, result_fingerprints=["forbidden-fingerprint"])]), "result_fingerprints"))
        for status in ("not_applicable", "out_of_scope", "deferred"):
            self.assertEqual(errs([unit(status=status, unresolved=["Reason recorded."])]), [])
            e = errs([unit(status=status, agent_id="hunter-1", reviewed_paths=["src/router.ts"], local_checks=[source_check()],
                           result_fingerprints=["forbidden-fingerprint"], unresolved=["Reason recorded."])])
            self.assertTrue(has(e, "must be unassigned") and has(e, "reviewed_paths") and has(e, "result_fingerprints"), status)
        self.assertTrue(has(errs([unit(status="covered", agent_id="hunter-1", reviewed_paths=["src/router.ts"],
                                       local_checks=[source_check()], result_fingerprints=["forbidden-fingerprint"])]),
                            "result_fingerprints"))
        self.assertTrue(has(errs([unit(status="covered", agent_id="hunter-1", reviewed_paths=["src/router.ts"],
                                       local_checks=[source_check()], unresolved=["Unexpected unresolved claim."])]), "unresolved"))

    def test_reassignment(self):
        self.assertEqual(errs([unit(attempts=[archived()], wave=2, status="in_progress", agent_id="hunter-2")]), [])
        self.assertEqual(errs([unit(attempts=[archived()], wave=2, status="covered", agent_id="hunter-2",
                                    reviewed_paths=["src/authz.ts"],
                                    local_checks=[source_check("hunter-2", reviewed_paths=["src/authz.ts"])])]), [])
        cand = archived(status="candidate", result_fingerprints=["src-router-missing-owner-check"],
                        unresolved=["validation_budget_exhausted"])
        self.assertEqual(errs([unit(attempts=[cand], wave=2, status="deferred", unresolved=["quick_profile_final_critic"])]), [])

    def test_owner_reuse_and_mixing(self):
        self.assertTrue(has(errs([unit(attempts=[archived()], wave=2, status="in_progress", agent_id="hunter-1")]),
                            "current assignment owner must be fresh"))
        e = errs([unit(attempts=[archived(local_checks=[local_check()])], wave=2, status="covered", agent_id="hunter-2",
                       reviewed_paths=["src/router.ts"], local_checks=[local_check()])])
        self.assertTrue(has(e, "prior assignment owner evidence must remain"))
        self.assertTrue(has(e, "artifact from an archived attempt cannot be reused"))
        e = errs([unit(attempts=[archived(local_checks=[local_check()]),
                                 archived(wave=2, agent_id="hunter-2", local_checks=[local_check()])],
                       wave=3, status="in_progress", agent_id="hunter-3")])
        self.assertTrue(has(e, "prior assignment owner evidence must remain in its earlier attempt"))
        self.assertTrue(has(e, "artifact from an earlier attempt cannot be reused"))
        self.assertTrue(has(errs([unit(attempts=[archived(), archived(wave=1, agent_id="hunter-2",
                                                                      local_checks=[source_check("hunter-2")])],
                                       wave=3, status="in_progress", agent_id="hunter-3")]), "strictly increasing"))

    def test_paths_and_fingerprints(self):
        for bad in ("/etc/passwd", "../src/file.js", "src/../file.js", "src/con.txt", "src/PRN", "src/AUX.c", "src/NUL",
                    "src/CLOCK$.txt", "src/conin$.txt", "src/conout$", "src/COM1.log", "src/lpt9", "src/COM\u00b9.log",
                    "src/lpt\u00b3", "src/file.js.", "C:/src/file.js", "src/file\n.js", "src/file\u0085.js",
                    "src/file\u2028.js", "src/file\u200b.js", "src/file\u034f.js", "src/file\ufe0f.js"):
            self.assertFalse(vl.is_safe_relative_path(bad), repr(bad))
        self.assertTrue(vl.is_safe_relative_path("src/handler.js"))
        self.assertTrue(vl.is_safe_relative_path("src/caf\u00e9/handler.js"))
        self.assertTrue(has(errs([unit(starting_paths=["../src/router.ts"])]), "repository-relative path"))
        self.assertTrue(has(errs([unit(status="candidate", agent_id="hunter-1", reviewed_paths=["src/router.ts"],
                                       local_checks=[source_check(invariant="Ownership is required.", result="No check exists.")],
                                       result_fingerprints=["not stable"])]), "invalid fingerprint"))

    def test_invisible_prose(self):
        for invisible in ("\u200b", "\u034f", "\ufe0f", "\ud800"):
            self.assertTrue(has(errs([unit(surface=invisible)]), "surface"), repr(invisible))

    def test_cli_safety(self):
        r = run_cli(b"[" + "\u001b\u0007\u0085\u202e".encode() + b"]")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(b"\x1b", r.stderr)
        enc = json.dumps([unit()]).encode().replace(b"Update-user", b"Update\x80user", 1)
        r = run_cli(enc)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"input is not valid UTF-8", r.stderr)
        r = run_cli(json.dumps([None] * 200))
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"output capped at 100", r.stderr)

    def test_shared_helpers_agree(self):
        corpus = ["src/handler.js", "src/caf\u00e9/handler.js", "src/cloc\u212a$.txt", "CON", "/etc/passwd", "src\\file.c",
                  "src/file:name.c", "~home/file.c", "src/file.c ", "src/file\u202ename.c", "src/file\ud800name.c"]
        for v in corpus:
            self.assertEqual(vf.is_safe_relative_source_path(v), vl.is_safe_relative_path(v), repr(v))
        self.assertFalse(vl.is_safe_relative_path("src/cloc\u212a$.txt"))


if __name__ == "__main__":
    unittest.main()
