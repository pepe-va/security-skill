"""Tests for scripts/render_report.py.

The page script is executed with QuickJS against a minimal DOM written in JavaScript, so the tests check
real behaviour without a browser: criticals preselected, prompt rebuilt on change, language, hostile
strings kept as text. Skipped when the `quickjs` module is not installed (pip install quickjs).
Run: python -m unittest discover tests
"""
import json, pathlib, re, subprocess, sys, tempfile, unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOOLS = REPO / "skills" / "security" / "cybersec-skill" / "scripts"
sys.path.insert(0, str(TOOLS))
import cvss4  # noqa: E402

try:
    import quickjs
except ImportError:  # pragma: no cover
    quickjs = None

HOSTILE = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
MOCK_DOM = r"""
var created = [];
function Node(tag) { this.tagName = tag; this.children = []; this.attrs = {}; this.listeners = {}; this._text = "";
  this.hidden = false; this.checked = false; this.value = ""; this.className = ""; created.push(this); }
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Object.defineProperty(Node.prototype, "textContent", {
  get: function () { return this._text + this.children.map(function (c) { return c.textContent; }).join(""); },
  set: function (v) { this._text = String(v); this.children = []; } });
Object.defineProperty(Node.prototype, "innerHTML", { set: function () { throw new Error("innerHTML used"); } });
Node.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); };
Node.prototype.getAttribute = function (k) { return this.attrs.hasOwnProperty(k) ? this.attrs[k] : null; };
Node.prototype.addEventListener = function (ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); };
Node.prototype.fire = function (ev) { (this.listeners[ev] || []).forEach(function (fn) { fn({}); }); };
Node.prototype.focus = function () {}; Node.prototype.select = function () {};
var app = new Node("main");
var document = { title: "", documentElement: new Node("html"),
  createElement: function (t) { return new Node(t); },
  createTextNode: function (s) { return { textContent: String(s) }; },
  getElementById: function (id) { return id === "report-data" ? { textContent: DATA } : app; },
  execCommand: function () { return true; } };
var window = { matchMedia: function () { return { matches: false }; }, isSecureContext: false };
var navigator = {};
"""


def src(std, ver, ident, f, rel):
    return {"standard": std, "version": ver, "id": ident, "file": f, "relation": rel, "tier": "A"}


def finding(fp, title, sev):
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    r = cvss4.evaluate(v)
    return {
        "verdict": "confirmed", "fingerprint": fp, "title": title, "description": "Reads other users' orders.",
        "root_cause": "No ownership check.", "intended_behavior": "Only owners read their orders.",
        "trace": [{"kind": "sink", "file": "app/db.py", "line": 40, "scope": "get_order", "description": "Query by id."}],
        "evidence": [{"file": "app/db.py", "line": 40, "description": "No owner filter."}], "conditions": [],
        "execution": {"attacker_perspective": "Customer.", "payloads": [HOSTILE], "instructions": ["Request order 2."],
                      "observed_result": "Order 2 is returned."},
        "remediation": {"strategy": "Filter by owner."},
        "severity": {"likelihood": {"score": "high", "reason": "Easy."}, "impact": {"score": sev, "reason": "Data."},
                     "overall_severity": sev},
        "confidence": {"score": "high", "reason": "Reproduced."},
        "cvss": {"vector": v, "score": r["score"], "severity": r["severity"], "nomenclature": r["nomenclature"]},
        "sources": [src("OWASP ASVS", "5.0.0", "v5.0.0-8.2.2", "references/standards/owasp-asvs-5.0.0.md", "violated-requirement"),
                    src("MITRE CWE", "4.20", "CWE-639", "references/standards/cwe/weaknesses.md", "weakness")],
    }


def pending():
    return {"verdict": "needs_validation", "fingerprint": "dep-npm-lodash", "title": "lodash 4.17.15 has a known vulnerability",
            "description": "Known CVE.", "claimed_root_cause": "Vulnerable version resolved.",
            "trace": [{"kind": "sink", "file": "package-lock.json", "line": 3, "scope": "lodash", "description": "Resolved."}],
            "evidence": [{"file": "package-lock.json", "line": 3, "description": "4.17.15"}],
            "blockers": ["Reachability not established."], "validation_plan": {"local": "Search for _.template calls."},
            "category": "dependency", "package": {"ecosystem": "npm", "name": "lodash", "version": "4.17.15"},
            "sources": [src("MITRE CWE", "4.20", "CWE-1395", "references/standards/cwe/weaknesses.md", "weakness")]}


def render(lang, findings, meta=None):
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "findings.json").write_text(json.dumps(sorted(findings, key=lambda f: f["fingerprint"])))
    (d / "run-metadata.json").write_text(json.dumps(meta or {"repo": "shop-api", "source_ref": "abc123"}))
    r = subprocess.run([sys.executable, str(TOOLS / "render_report.py"), str(d), "--lang", lang], capture_output=True, text=True)
    return r, d / "security-report.html"


@unittest.skipIf(quickjs is None, "quickjs not installed")
class RenderedPage(unittest.TestCase):
    def run_page(self, html):
        data = re.search(r'<script type="application/json" id="report-data">(.*?)</script>', html, re.S).group(1)
        script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
        ctx = quickjs.Context()
        ctx.eval("var DATA = " + json.dumps(data) + ";")
        ctx.eval(MOCK_DOM)
        ctx.eval(script)
        return ctx

    def setUp(self):
        self.findings = [finding("a-critical", HOSTILE + " IDOR", "critical"), finding("b-high", "SQL injection", "high"), pending()]

    def test_embedded_data_cannot_break_out(self):
        r, path = render("en", self.findings)
        self.assertEqual(r.returncode, 0, r.stderr)
        html = path.read_text()
        self.assertNotIn("<script>alert", html)
        data = re.search(r'id="report-data">(.*?)</script>', html, re.S).group(1)
        self.assertNotIn("<", data)
        self.assertIn("script-src 'sha256-", html.replace("&#x27;", "'"))

    def test_criticals_preselected_and_prompt_rebuilds(self):
        _, path = render("en", self.findings)
        ctx = self.run_page(path.read_text())
        state = json.loads(ctx.eval("""JSON.stringify({
            boxes: created.filter(function (n) { return n.tagName === 'input' && n.attrs.type === 'checkbox'; }).map(function (n) { return n.checked; }),
            prompt: created.filter(function (n) { return n.tagName === 'textarea'; })[0].value })"""))
        self.assertEqual(state["boxes"], [True, False, False])          # critical, high, pending
        self.assertIn("IDOR", state["prompt"])
        self.assertIn("[CRITICAL]", state["prompt"])
        self.assertNotIn("SQL injection", state["prompt"])
        self.assertIn("v5.0.0-8.2.2", state["prompt"])                   # sources travel with the finding
        prompt = ctx.eval("""(function () { var b = created.filter(function (n) { return n.tagName === 'input' && n.attrs.type === 'checkbox'; });
            b[1].checked = true; b[1].fire('change'); b[2].checked = true; b[2].fire('change');
            return created.filter(function (n) { return n.tagName === 'textarea'; })[0].value; })()""")
        self.assertIn("SQL injection", prompt)
        self.assertIn("[VERIFY FIRST]", prompt)
        self.assertIn("Reachability not established.", prompt)

    def test_most_severe_preselected_without_criticals(self):
        _, path = render("en", [finding("b-high", "SQL injection", "high"), finding("c-med", "Verbose errors", "medium"), pending()])
        ctx = self.run_page(path.read_text())
        state = json.loads(ctx.eval("""JSON.stringify({
            boxes: created.filter(function (n) { return n.tagName === 'input' && n.attrs.type === 'checkbox'; }).map(function (n) { return n.checked; }),
            prompt: created.filter(function (n) { return n.tagName === 'textarea'; })[0].value })"""))
        self.assertEqual(state["boxes"], [True, False, False])          # high, medium, pending
        self.assertIn("SQL injection", state["prompt"])
        self.assertNotIn("Verbose errors", state["prompt"])

    def test_hostile_text_stays_text(self):
        _, path = render("en", self.findings)
        ctx = self.run_page(path.read_text())
        tags = json.loads(ctx.eval("JSON.stringify(created.map(function (n) { return n.tagName; }))"))
        self.assertNotIn("script", tags)
        self.assertNotIn("img", tags)
        self.assertIn(HOSTILE, ctx.eval("app.textContent"))

    def test_spanish(self):
        _, path = render("es", self.findings)
        html = path.read_text()
        self.assertIn('<html lang="es">', html)
        ctx = self.run_page(html)
        text = ctx.eval("app.textContent")
        self.assertIn("Prompt de mitigación", text)
        self.assertIn("Hallazgos confirmados", text)
        prompt = ctx.eval("created.filter(function (n) { return n.tagName === 'textarea'; })[0].value")
        self.assertIn("[CRÍTICA]", prompt)
        self.assertIn("Reglas:", prompt)

    def test_copy_button_fallback(self):
        _, path = render("en", self.findings)
        ctx = self.run_page(path.read_text())
        status = ctx.eval("""(function () { var btn = created.filter(function (n) { return n.tagName === 'button' && n.className === 'btn-primary'; })[0];
            btn.fire('click'); return created.filter(function (n) { return n.attrs.role === 'status'; })[0].textContent; })()""")
        self.assertEqual(status, "Copied to the clipboard.")


class Refusal(unittest.TestCase):
    def test_refuses_invalid_findings(self):
        bad = finding("a", "No sources", "high")
        del bad["sources"]
        r, _ = render("en", [bad])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refusing to render", r.stderr)


if __name__ == "__main__":
    unittest.main()
